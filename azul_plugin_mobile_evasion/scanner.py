"""Static mobile evasion indicator scanner."""

from __future__ import annotations

import plistlib
import re
import zipfile
from dataclasses import dataclass
from io import BytesIO
from typing import IO, Iterable

MIB = 1024 * 1024
DEFAULT_MAX_ENTRY_SIZE = 200 * MIB
DEFAULT_MAX_TOTAL_SCAN_SIZE = 512 * MIB
DEFAULT_MAX_ARCHIVE_ENTRIES = 10_000
SCAN_CHUNK_SIZE = MIB
PLATFORM_SAMPLE_SIZE = 4096
MAX_METADATA_ENTRY_SIZE = 8 * MIB
CONTEXT_BYTES = 48
ANDROID_BINARY_XML_MAGIC = b"\x03\x00\x08\x00"
DEX_MAGIC = b"dex\n"
MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)

# Android binary XML (AXML) chunk types and value encodings used by the manifest parser.
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
STRING_POOL_UTF8_FLAG = 1 << 8
AXML_NO_ENTRY = 0xFFFFFFFF
AXML_TYPE_STRING = 0x03
AXML_TYPE_INT_DEC = 0x10
AXML_TYPE_INT_HEX = 0x11
AXML_TYPE_INT_BOOLEAN = 0x12


@dataclass(frozen=True)
class EvasionRule:
    """Static evidence pattern for a mobile evasion indicator."""

    rule_id: str
    platform: str
    category: str
    indicator: str
    confidence: str
    patterns: tuple[bytes, ...]


@dataclass(frozen=True)
class EvasionFinding:
    """Matched mobile evasion indicator with supporting evidence."""

    rule_id: str
    platform: str
    category: str
    indicator: str
    confidence: str
    evidence: str
    location: str
    file_kind: str
    file_size: int
    context: str
    confidence_reason: str
    package_identity: tuple[str, ...]
    permissions: tuple[str, ...]
    entitlements: tuple[str, ...]
    network_indicators: tuple[str, ...]


@dataclass(frozen=True)
class ArchiveEntrySample:
    """Small archive member sample used for platform detection."""

    filename: str
    file_size: int
    sample: bytes


@dataclass(frozen=True)
class ScanChunk:
    """A bounded content chunk with metadata for enrichment."""

    location: str
    data: bytes
    file_kind: str
    file_size: int


@dataclass(frozen=True)
class PackageContext:
    """Package-level context shared across findings."""

    identity: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    entitlements: tuple[str, ...] = ()


RULES: tuple[EvasionRule, ...] = (
    EvasionRule(
        rule_id="android-emulator-qemu",
        platform="android",
        category="emulator",
        indicator="Android emulator property or device probe",
        confidence="high",
        patterns=(
            b"ro.kernel.qemu",
            b"ro.boot.qemu",
            b"ro.kernel.android.qemud",
            b"/dev/qemu_pipe",
            b"/dev/socket/qemud",
            b"/dev/qemu_trace",
        ),
    ),
    EvasionRule(
        rule_id="android-emulator-system-properties",
        platform="android",
        category="emulator",
        indicator="Android emulator system property probe",
        confidence="high",
        patterns=(
            b"ro.hardware",
            b"ro.product.model",
            b"ro.product.manufacturer",
            b"ro.product.device",
            b"ro.product.board",
            b"ro.bootloader",
            b"ro.serialno",
            b"ro.build.fingerprint",
            b"getprop",
        ),
    ),
    EvasionRule(
        rule_id="android-emulator-hardware",
        platform="android",
        category="emulator",
        indicator="Android emulator hardware fingerprint probe",
        confidence="medium",
        patterns=(
            b"goldfish",
            b"ranchu",
            b"generic_x86",
            b"generic_x86_64",
            b"google_sdk",
            b"sdk_gphone",
            b"vbox86",
            b"ttVM_Hdragon",
            b"Android SDK built for x86",
        ),
    ),
    EvasionRule(
        rule_id="android-emulator-vendor",
        platform="android",
        category="emulator",
        indicator="Third-party Android emulator vendor probe",
        confidence="medium",
        patterns=(
            b"Genymotion",
            b"BlueStacks",
            b"NoxPlayer",
            b"bignox",
            b"AndyOS",
            b"andyroid",
            b"LDPlayer",
            b"microvirt",
            b"MuMu",
        ),
    ),
    EvasionRule(
        rule_id="android-emulator-telephony",
        platform="android",
        category="emulator",
        indicator="Android emulator telephony identity probe",
        confidence="medium",
        patterns=(
            b"TelephonyManager",
            b"getDeviceId",
            b"getSubscriberId",
            b"getSimSerialNumber",
            b"getNetworkOperatorName",
            b"android_id",
            b"15555215554",
            b"15555215556",
            b"310260000000000",
        ),
    ),
    EvasionRule(
        rule_id="android-emulator-sensor",
        platform="android",
        category="emulator",
        indicator="Android emulator sensor or camera capability probe",
        confidence="low",
        patterns=(
            b"SensorManager",
            b"getSensorList",
            b"TYPE_ACCELEROMETER",
            b"TYPE_GYROSCOPE",
            b"CameraManager",
            b"hasSystemFeature",
        ),
    ),
    EvasionRule(
        rule_id="android-root",
        platform="android",
        category="root",
        indicator="Android root environment probe",
        confidence="medium",
        patterns=(
            b"/system/xbin/su",
            b"/system/bin/su",
            b"/sbin/su",
            b"/su/bin/su",
            b"/system/app/Superuser.apk",
            b"Superuser.apk",
            b"RootBeer",
            b"Magisk",
            b"su -c",
            b"which su",
            b"busybox",
        ),
    ),
    EvasionRule(
        rule_id="android-root-packages",
        platform="android",
        category="root",
        indicator="Android root management package probe",
        confidence="medium",
        patterns=(
            b"com.noshufou.android.su",
            b"eu.chainfire.supersu",
            b"com.koushikdutta.superuser",
            b"com.topjohnwu.magisk",
            b"com.kingroot.kinguser",
            b"com.kingo.root",
        ),
    ),
    EvasionRule(
        rule_id="android-root-build-tags",
        platform="android",
        category="root",
        indicator="Android rooted build tag probe",
        confidence="medium",
        patterns=(b"test-keys", b"ro.build.tags", b"ro.debuggable", b"ro.secure"),
    ),
    EvasionRule(
        rule_id="android-integrity-attestation",
        platform="android",
        category="integrity",
        indicator="Android integrity or attestation environment check",
        confidence="low",
        patterns=(
            b"SafetyNet",
            b"SafetyNetClient",
            b"attest",
            b"PlayIntegrity",
            b"IntegrityManager",
            b"MEETS_DEVICE_INTEGRITY",
            b"MEETS_STRONG_INTEGRITY",
        ),
    ),
    EvasionRule(
        rule_id="android-hooking-framework",
        platform="android",
        category="instrumentation",
        indicator="Android hooking framework probe",
        confidence="high",
        patterns=(
            b"XposedBridge",
            b"de.robv.android.xposed",
            b"LSPosed",
            b"EdXposed",
            b"riru",
            b"zygisk",
            b"Substrate",
            b"com.saurik.substrate",
        ),
    ),
    EvasionRule(
        rule_id="ios-simulator",
        platform="ios",
        category="simulator",
        indicator="iOS simulator environment probe",
        confidence="high",
        patterns=(
            b"TARGET_IPHONE_SIMULATOR",
            b"SIMULATOR_DEVICE_NAME",
            b"SIMULATOR_MODEL_IDENTIFIER",
            b"SIMULATOR_UDID",
            b"iphonesimulator",
            b"i386-apple-ios",
            b"x86_64-apple-ios-simulator",
        ),
    ),
    EvasionRule(
        rule_id="ios-jailbreak",
        platform="ios",
        category="jailbreak",
        indicator="iOS jailbreak environment probe",
        confidence="medium",
        patterns=(
            b"/Applications/Cydia.app",
            b"cydia://",
            b"MobileSubstrate",
            b"/Library/MobileSubstrate",
            b"/bin/bash",
            b"/usr/sbin/sshd",
            b"/etc/apt",
            b"/private/var/lib/apt",
            b"/private/var/stash",
            b"/Applications/Sileo.app",
            b"/Applications/Zebra.app",
            b"/Applications/blackra1n.app",
            b"SubstrateLoader.dylib",
        ),
    ),
    EvasionRule(
        rule_id="ios-jailbreak-schemes",
        platform="ios",
        category="jailbreak",
        indicator="iOS jailbreak URL scheme probe",
        confidence="medium",
        patterns=(b"cydia://package/", b"sileo://", b"zbra://", b"undecimus://", b"filza://"),
    ),
    EvasionRule(
        rule_id="ios-filesystem-write",
        platform="ios",
        category="jailbreak",
        indicator="iOS sandbox escape filesystem write probe",
        confidence="low",
        patterns=(b"/private/jailbreak.txt",),
    ),
    EvasionRule(
        rule_id="anti-debug",
        platform="mobile",
        category="debugger",
        indicator="Debugger detection or denial probe",
        confidence="medium",
        patterns=(
            b"ptrace",
            b"PT_DENY_ATTACH",
            b"TracerPid",
            b"sysctl",
            b"isDebuggerConnected",
            b"Debug.isDebuggerConnected",
            b"Debug.waitingForDebugger",
            b"android.os.Debug",
            b"task_get_exception_ports",
            b"mach_port",
            b"csops",
            b"amIBeingDebugged",
        ),
    ),
    EvasionRule(
        rule_id="anti-tamper-signature",
        platform="mobile",
        category="tamper",
        indicator="Application signature or bundle tamper check",
        confidence="low",
        patterns=(
            b"getPackageInfo",
            b"GET_SIGNATURES",
            b"GET_SIGNING_CERTIFICATES",
            b"signingInfo",
            b"SecCodeCopySelf",
            b"SecStaticCodeCheckValidity",
            b"embedded.mobileprovision",
        ),
    ),
    EvasionRule(
        rule_id="instrumentation-frida",
        platform="mobile",
        category="instrumentation",
        indicator="Frida instrumentation probe",
        confidence="high",
        patterns=(
            b"frida",
            b"gum-js-loop",
            b"frida-agent",
            b"LIBFRIDA",
            b"frida-server",
            b"re.frida.server",
        ),
    ),
    EvasionRule(
        rule_id="instrumentation-tools",
        platform="mobile",
        category="instrumentation",
        indicator="Mobile instrumentation or runtime manipulation tool probe",
        confidence="medium",
        patterns=(
            b"objection",
            b"Cycript",
            b"SSLKillSwitch",
            b"Substrate",
            b"MSHookFunction",
            b"MSHookMessageEx",
            b"fishhook",
        ),
    ),
    EvasionRule(
        rule_id="network-proxy",
        platform="mobile",
        category="proxy",
        indicator="Proxy or interception environment probe",
        confidence="low",
        patterns=(
            b"HTTP_PROXY",
            b"HTTPS_PROXY",
            b"http.proxyHost",
            b"http.proxyPort",
            b"ProxySelector",
            b"CFNetworkCopySystemProxySettings",
        ),
    ),
)

# Patterns are matched case-insensitively; pre-lower them once so each chunk scan
# does not recompute `pattern.lower()` for every rule pattern.
_LOWERED_RULES: tuple[tuple[EvasionRule, tuple[tuple[bytes, bytes], ...]], ...] = tuple(
    (rule, tuple((pattern, pattern.lower()) for pattern in rule.patterns)) for rule in RULES
)
MAX_PATTERN_SIZE = max(len(pattern) for rule in RULES for pattern in rule.patterns)


def scan_mobile_evasion(
    data: bytes,
    *,
    file_format: str | None = None,
    mime: str | None = None,
    magic: str | None = None,
    max_entry_size: int = DEFAULT_MAX_ENTRY_SIZE,
    max_total_scan_size: int = DEFAULT_MAX_TOTAL_SCAN_SIZE,
    max_archive_entries: int = DEFAULT_MAX_ARCHIVE_ENTRIES,
) -> list[EvasionFinding]:
    """Scan an APK, IPA, or raw mobile binary for static evasion evidence."""
    platform_hint, package_context = _detect_platform_and_context(
        data,
        file_format=file_format,
        mime=mime,
        magic=magic,
        max_archive_entries=max_archive_entries,
    )
    findings = []
    for chunk in _iter_scan_chunks(
        data,
        max_entry_size=max_entry_size,
        max_total_scan_size=max_total_scan_size,
        max_archive_entries=max_archive_entries,
    ):
        findings.extend(_scan_chunk(chunk, platform_hint, package_context))

    return sorted(
        _deduplicate(findings),
        key=lambda finding: (finding.platform, finding.category, finding.rule_id, finding.evidence, finding.location),
    )


def detect_mobile_platform(
    data: bytes,
    *,
    file_format: str | None = None,
    mime: str | None = None,
    magic: str | None = None,
    max_archive_entries: int = DEFAULT_MAX_ARCHIVE_ENTRIES,
) -> str:
    """Identify Android/iOS package content without relying on filename extension."""
    metadata_platform = _platform_from_azul_metadata(file_format=file_format, mime=mime, magic=magic)
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            entries = _sample_archive_entries(archive, max_archive_entries=max_archive_entries)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        raw_platform = _detect_raw_mobile_platform(data)
        return raw_platform if raw_platform != "mobile" else metadata_platform

    return _platform_from_scores(entries, metadata_platform)


def _scan_chunk(chunk: ScanChunk, platform_hint: str, package_context: PackageContext) -> list[EvasionFinding]:
    findings = []
    lowered = chunk.data.lower()
    for rule, patterns in _LOWERED_RULES:
        if rule.platform not in ("mobile", platform_hint):
            continue
        matched_patterns = [original for original, lowered_pattern in patterns if lowered_pattern in lowered]
        if not matched_patterns:
            continue
        for pattern in _most_specific_patterns(matched_patterns):
            index = lowered.find(pattern.lower())
            if index < 0:
                continue
            findings.append(
                EvasionFinding(
                    rule_id=rule.rule_id,
                    platform=platform_hint if rule.platform == "mobile" else rule.platform,
                    category=rule.category,
                    indicator=rule.indicator,
                    confidence=rule.confidence,
                    evidence=pattern.decode("utf-8", errors="replace"),
                    location=chunk.location,
                    file_kind=chunk.file_kind,
                    file_size=chunk.file_size,
                    context=_context_for_pattern(chunk.data, pattern, index),
                    confidence_reason=_confidence_reason(rule, chunk.file_kind),
                    package_identity=package_context.identity,
                    permissions=package_context.permissions,
                    entitlements=package_context.entitlements,
                    network_indicators=_network_indicators_near(chunk.data, pattern, index),
                )
            )
    return findings


def _iter_scan_chunks(
    data: bytes,
    *,
    max_entry_size: int,
    max_total_scan_size: int,
    max_archive_entries: int,
    location_prefix: str = "",
) -> Iterable[ScanChunk]:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            scanned_bytes = 0
            scanned_entries = 0
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if scanned_entries >= max_archive_entries:
                    break
                scanned_entries += 1
                if info.file_size > max_entry_size:
                    continue
                if scanned_bytes + info.file_size > max_total_scan_size:
                    continue
                try:
                    with archive.open(info) as member:
                        first = member.read(SCAN_CHUNK_SIZE)
                        file_kind = _file_kind(info.filename, first[:PLATFORM_SAMPLE_SIZE])
                        if _is_nested_archive(info.filename, file_kind):
                            nested_data = first + member.read()
                            yield from _iter_scan_chunks(
                                nested_data,
                                max_entry_size=max_entry_size,
                                max_total_scan_size=max_total_scan_size - scanned_bytes,
                                max_archive_entries=max_archive_entries - scanned_entries,
                                location_prefix=f"{location_prefix}{info.filename}!",
                            )
                        else:
                            yield from _iter_member_chunks(member, first, info, file_kind, location_prefix)
                    scanned_bytes += info.file_size
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue
    except zipfile.BadZipFile:
        if len(data) <= max_entry_size and len(data) <= max_total_scan_size:
            yield ScanChunk(
                f"{location_prefix}input", data, _file_kind("input", data[:PLATFORM_SAMPLE_SIZE]), len(data)
            )


def _iter_member_chunks(
    member: IO[bytes],
    first: bytes,
    info: zipfile.ZipInfo,
    file_kind: str,
    location_prefix: str,
) -> Iterable[ScanChunk]:
    location = f"{location_prefix}{info.filename}"
    overlap = b""
    chunk = first
    while chunk:
        scan_chunk = overlap + chunk
        yield ScanChunk(location, scan_chunk, file_kind, info.file_size)
        overlap = scan_chunk[-(MAX_PATTERN_SIZE - 1) :]
        chunk = member.read(SCAN_CHUNK_SIZE)


def _file_kind(location: str, sample: bytes) -> str:
    lowered = location.lower()
    if sample.startswith(DEX_MAGIC) or re.fullmatch(r".*/?classes\d*\.dex", lowered):
        return "dex"
    if sample.startswith(MACHO_MAGICS):
        return "mach-o"
    if sample.startswith(b"PK\x03\x04") or lowered.endswith((".apk", ".ipa", ".zip")):
        return "archive"
    if lowered.endswith(".so"):
        return "elf"
    if lowered.endswith(".plist"):
        return "plist"
    if "androidmanifest.xml" in lowered:
        return "android-manifest"
    if lowered.endswith((".rsa", ".dsa", ".ec", ".sf")) or "codesignature/" in lowered:
        return "signature"
    if lowered.endswith((".txt", ".properties", ".json", ".xml")):
        return "text"
    return "binary"


def _is_nested_archive(location: str, file_kind: str) -> bool:
    return file_kind == "archive" and location.lower().endswith((".apk", ".ipa", ".zip"))


def _context_for_pattern(data: bytes, pattern: bytes, index: int) -> str:
    if index < 0:
        return ""
    start = max(0, index - CONTEXT_BYTES)
    end = min(len(data), index + len(pattern) + CONTEXT_BYTES)
    return _clean_text(data[start:end])


def _network_indicators_near(data: bytes, pattern: bytes, index: int) -> tuple[str, ...]:
    if index < 0:
        return ()
    start = max(0, index - 256)
    end = min(len(data), index + len(pattern) + 256)
    text = _clean_text(data[start:end])
    indicators = re.findall(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", text)
    return tuple(sorted(set(indicator.rstrip(".,);]}'\"") for indicator in indicators)))


def _confidence_reason(rule: EvasionRule, file_kind: str) -> str:
    return f"Matched {rule.confidence}-confidence {rule.category} evidence in {file_kind} content"


def _clean_text(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    text = text.replace("\N{REPLACEMENT CHARACTER}", " ")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _most_specific_patterns(patterns: Iterable[bytes]) -> list[bytes]:
    """Return matches without shorter patterns contained in longer matches."""
    ordered = sorted(set(patterns), key=lambda pattern: (-len(pattern), pattern.lower(), pattern))
    selected = []
    for pattern in ordered:
        lowered = pattern.lower()
        if any(lowered in chosen.lower() for chosen in selected):
            continue
        selected.append(pattern)
    return sorted(selected, key=lambda pattern: (pattern.lower(), pattern))


def _detect_platform_and_context(
    data: bytes,
    *,
    file_format: str | None,
    mime: str | None,
    magic: str | None,
    max_archive_entries: int,
) -> tuple[str, PackageContext]:
    """Determine the platform and extract package context from a single archive open."""
    metadata_platform = _platform_from_azul_metadata(file_format=file_format, mime=mime, magic=magic)
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            entries = _sample_archive_entries(archive, max_archive_entries=max_archive_entries)
            platform = _platform_from_scores(entries, metadata_platform)
            context = _package_context(archive, platform, max_archive_entries=max_archive_entries)
            return platform, context
    except (OSError, RuntimeError, zipfile.BadZipFile):
        raw_platform = _detect_raw_mobile_platform(data)
        return (raw_platform if raw_platform != "mobile" else metadata_platform), PackageContext()


def _platform_from_scores(entries: dict[str, ArchiveEntrySample], metadata_platform: str) -> str:
    android_score = _android_package_score(entries)
    ios_score = _ios_package_score(entries)

    if android_score >= 3 and android_score > ios_score:
        return "android"
    if ios_score >= 3 and ios_score > android_score:
        return "ios"
    return metadata_platform


def _platform_from_azul_metadata(
    *,
    file_format: str | None = None,
    mime: str | None = None,
    magic: str | None = None,
) -> str:
    """Map Azul file typing metadata to the scanner's platform names."""
    normalized_format = (file_format or "").split(";", 1)[0].strip().lower()
    normalized_mime = (mime or "").lower()
    normalized_magic = (magic or "").lower()

    if normalized_format.startswith("android/"):
        return "android"
    if normalized_format.startswith("ios/") or normalized_format == "executable/mach-o":
        return "ios"
    if "android package (apk)" in normalized_magic or normalized_magic.startswith("dalvik dex"):
        return "android"
    if "mach-o" in normalized_magic:
        return "ios"
    if normalized_mime in {"application/vnd.android.package-archive", "application/x-dex"}:
        return "android"
    return "mobile"


def _package_context(
    archive: zipfile.ZipFile,
    platform_hint: str,
    *,
    max_archive_entries: int,
) -> PackageContext:
    if platform_hint == "android":
        manifest = _read_named_entry(archive, "AndroidManifest.xml", max_bytes=MAX_METADATA_ENTRY_SIZE)
        if manifest is None:
            return PackageContext()
        return _android_package_context(manifest)
    if platform_hint == "ios":
        plist = _read_ios_info_plist(
            archive, max_bytes=MAX_METADATA_ENTRY_SIZE, max_archive_entries=max_archive_entries
        )
        if plist is None:
            return PackageContext()
        return _ios_package_context(plist)
    return PackageContext()


def _read_named_entry(archive: zipfile.ZipFile, name: str, *, max_bytes: int) -> bytes | None:
    try:
        info = archive.getinfo(name)
    except KeyError:
        return None
    if info.is_dir() or info.file_size > max_bytes:
        return None
    try:
        with archive.open(info) as member:
            return member.read(max_bytes + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return None


def _read_ios_info_plist(archive: zipfile.ZipFile, *, max_bytes: int, max_archive_entries: int) -> bytes | None:
    scanned_entries = 0
    for info in archive.infolist():
        if info.is_dir():
            continue
        if scanned_entries >= max_archive_entries:
            break
        scanned_entries += 1
        name = info.filename
        if not (name.startswith("Payload/") and name.endswith(".app/Info.plist")):
            continue
        if info.file_size > max_bytes:
            return None
        try:
            with archive.open(info) as member:
                return member.read(max_bytes + 1)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return None
    return None


def _android_package_context(manifest: bytes) -> PackageContext:
    """Extract identity and permissions from a binary (AXML) or plain-text manifest."""
    if manifest.startswith(ANDROID_BINARY_XML_MAGIC):
        elements = _parse_axml_elements(manifest)
        if elements is None:
            return PackageContext()
        return _android_context_from_elements(elements)
    return _android_context_from_text(_clean_text(manifest))


def _android_context_from_elements(elements: list[tuple[str, dict[str, str]]]) -> PackageContext:
    manifest_attrs: dict[str, str] = {}
    sdk_attrs: dict[str, str] = {}
    permissions: list[str] = []
    for name, attrs in elements:
        if name == "manifest" and not manifest_attrs:
            manifest_attrs = attrs
        elif name == "uses-sdk" and not sdk_attrs:
            sdk_attrs = attrs
        elif name == "uses-permission":
            permission = attrs.get("name")
            if permission:
                permissions.append(permission)

    identity = []
    for key, label, source in (
        ("package", "android_package", manifest_attrs),
        ("versionName", "android_version_name", manifest_attrs),
        ("minSdkVersion", "android_min_sdk", sdk_attrs),
        ("targetSdkVersion", "android_target_sdk", sdk_attrs),
    ):
        value = source.get(key)
        if value:
            identity.append(f"{label}={value}")
    return PackageContext(identity=tuple(identity), permissions=tuple(sorted(set(permissions))))


def _android_context_from_text(text: str) -> PackageContext:
    identity = []
    for key, label in (
        ("package", "android_package"),
        ("versionName", "android_version_name"),
        ("minSdkVersion", "android_min_sdk"),
        ("targetSdkVersion", "android_target_sdk"),
    ):
        value = _xml_attr(text, key)
        if value:
            identity.append(f"{label}={value}")

    permissions = tuple(sorted(set(re.findall(r'uses-permission[^>]+name="([^"]+)"', text))))
    return PackageContext(identity=tuple(identity), permissions=permissions)


def _ios_package_context(plist_bytes: bytes) -> PackageContext:
    try:
        plist = plistlib.loads(plist_bytes)
    except (plistlib.InvalidFileException, ValueError, TypeError):
        return PackageContext()
    if not isinstance(plist, dict):
        return PackageContext()

    identity = []
    for key, label in (
        ("CFBundleIdentifier", "ios_bundle_id"),
        ("CFBundleName", "ios_bundle_name"),
        ("CFBundleShortVersionString", "ios_version"),
        ("CFBundleExecutable", "ios_executable"),
    ):
        value = plist.get(key)
        if isinstance(value, str) and value:
            identity.append(f"{label}={value}")

    entitlements = []
    for url_type in plist.get("CFBundleURLTypes", []) or []:
        if not isinstance(url_type, dict):
            continue
        for scheme in url_type.get("CFBundleURLSchemes", []) or []:
            if isinstance(scheme, str) and scheme:
                entitlements.append(f"url_scheme={scheme}")

    return PackageContext(identity=tuple(identity), entitlements=tuple(sorted(set(entitlements))))


def _xml_attr(text: str, attr_name: str) -> str | None:
    match = re.search(rf'(?:android:)?{re.escape(attr_name)}="([^"]+)"', text)
    return match.group(1) if match else None


def _parse_axml_elements(data: bytes) -> list[tuple[str, dict[str, str]]] | None:
    """Parse start elements (name + attributes) from Android binary XML.

    Returns a list of (element_name, {attr_name: value}) tuples, or None when the
    content cannot be parsed as binary XML.
    """
    try:
        strings: list[str] | None = None
        elements: list[tuple[str, dict[str, str]]] = []
        offset = 8  # skip the ResXMLTree_header (a bare ResChunk_header).
        total = len(data)
        while offset + 8 <= total:
            chunk_type = int.from_bytes(data[offset : offset + 2], "little")
            chunk_size = int.from_bytes(data[offset + 4 : offset + 8], "little")
            if chunk_size < 8 or offset + chunk_size > total:
                break
            if chunk_type == RES_STRING_POOL_TYPE:
                strings = _parse_axml_string_pool(data, offset, chunk_size)
            elif chunk_type == RES_XML_START_ELEMENT_TYPE and strings is not None:
                element = _parse_axml_start_element(data, offset, chunk_size, strings)
                if element is not None:
                    elements.append(element)
            offset += chunk_size
        if strings is None:
            return None
        return elements
    except (IndexError, ValueError):
        return None


def _parse_axml_string_pool(data: bytes, pool_offset: int, pool_size: int) -> list[str]:
    string_count = int.from_bytes(data[pool_offset + 8 : pool_offset + 12], "little")
    flags = int.from_bytes(data[pool_offset + 16 : pool_offset + 20], "little")
    strings_start = int.from_bytes(data[pool_offset + 20 : pool_offset + 24], "little")
    is_utf8 = bool(flags & STRING_POOL_UTF8_FLAG)

    pool_end = pool_offset + pool_size
    offsets_base = pool_offset + 28
    string_count = max(0, min(string_count, (pool_end - offsets_base) // 4))
    strings = []
    for i in range(string_count):
        offset_pos = offsets_base + i * 4
        string_offset = int.from_bytes(data[offset_pos : offset_pos + 4], "little")
        position = pool_offset + strings_start + string_offset
        if position >= pool_end:
            strings.append("")
            continue
        if is_utf8:
            strings.append(_decode_axml_utf8_string(data, position, pool_end))
        else:
            strings.append(_decode_axml_utf16_string(data, position, pool_end))
    return strings


def _decode_axml_length_u8(data: bytes, position: int, end: int) -> tuple[int, int]:
    length = data[position]
    position += 1
    if length & 0x80:
        if position >= end:
            return length & 0x7F, position
        length = ((length & 0x7F) << 8) | data[position]
        position += 1
    return length, position


def _decode_axml_utf8_string(data: bytes, position: int, end: int) -> str:
    _, position = _decode_axml_length_u8(data, position, end)  # UTF-16 character count, unused.
    byte_length, position = _decode_axml_length_u8(data, position, end)
    byte_length = min(byte_length, max(0, end - position))
    return data[position : position + byte_length].decode("utf-8", errors="replace")


def _decode_axml_utf16_string(data: bytes, position: int, end: int) -> str:
    if position + 2 > end:
        return ""
    length = int.from_bytes(data[position : position + 2], "little")
    position += 2
    if length & 0x8000:
        if position + 2 > end:
            return ""
        length = ((length & 0x7FFF) << 16) | int.from_bytes(data[position : position + 2], "little")
        position += 2
    byte_length = min(length * 2, max(0, ((end - position) // 2) * 2))
    return data[position : position + byte_length].decode("utf-16-le", errors="replace")


def _parse_axml_start_element(
    data: bytes,
    offset: int,
    chunk_size: int,
    strings: list[str],
) -> tuple[str, dict[str, str]] | None:
    chunk_end = offset + chunk_size
    ext = offset + 16  # skip the node header (ResChunk_header + lineNumber + comment).
    if ext + 20 > chunk_end:
        return None
    name_index = int.from_bytes(data[ext + 4 : ext + 8], "little")
    attribute_start = int.from_bytes(data[ext + 8 : ext + 10], "little")
    attribute_size = int.from_bytes(data[ext + 10 : ext + 12], "little")
    attribute_count = int.from_bytes(data[ext + 12 : ext + 14], "little")
    name = _axml_string(strings, name_index)
    if name is None:
        return None
    if attribute_size < 20:
        attribute_size = 20

    attributes: dict[str, str] = {}
    attribute_base = ext + attribute_start
    for i in range(attribute_count):
        attribute_offset = attribute_base + i * attribute_size
        if attribute_offset + 20 > chunk_end:
            break
        attr_name_index = int.from_bytes(data[attribute_offset + 4 : attribute_offset + 8], "little")
        raw_value_index = int.from_bytes(data[attribute_offset + 8 : attribute_offset + 12], "little")
        value_type = data[attribute_offset + 15]
        value_data = int.from_bytes(data[attribute_offset + 16 : attribute_offset + 20], "little")
        attr_name = _axml_string(strings, attr_name_index)
        if attr_name is None:
            continue
        value = _axml_attribute_value(strings, raw_value_index, value_type, value_data)
        if value is not None:
            attributes[attr_name] = value
    return name, attributes


def _axml_string(strings: list[str], index: int) -> str | None:
    if index == AXML_NO_ENTRY or index < 0 or index >= len(strings):
        return None
    return strings[index]


def _axml_attribute_value(strings: list[str], raw_value_index: int, value_type: int, value_data: int) -> str | None:
    if raw_value_index != AXML_NO_ENTRY:
        return _axml_string(strings, raw_value_index)
    if value_type == AXML_TYPE_STRING:
        return _axml_string(strings, value_data)
    if value_type in (AXML_TYPE_INT_DEC, AXML_TYPE_INT_HEX):
        return str(value_data)
    if value_type == AXML_TYPE_INT_BOOLEAN:
        return "true" if value_data else "false"
    return None


def _sample_archive_entries(
    archive: zipfile.ZipFile,
    *,
    max_archive_entries: int,
) -> dict[str, ArchiveEntrySample]:
    entries = {}
    sampled_entries = 0
    for info in archive.infolist():
        if info.is_dir():
            continue
        if sampled_entries >= max_archive_entries:
            break
        sampled_entries += 1
        try:
            with archive.open(info) as member:
                sample = member.read(PLATFORM_SAMPLE_SIZE)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            sample = b""
        entries[info.filename] = ArchiveEntrySample(info.filename, info.file_size, sample)
    return entries


def _android_package_score(entries: dict[str, ArchiveEntrySample]) -> int:
    score = 0
    names = set(entries)

    manifest = entries.get("AndroidManifest.xml")
    if manifest:
        score += 2
        if manifest.sample.startswith(ANDROID_BINARY_XML_MAGIC) or b"<manifest" in manifest.sample[:512].lower():
            score += 1

    dex_names = [name for name in names if re.fullmatch(r"classes\d*\.dex", name)]
    valid_dex_count = sum(1 for name in dex_names if entries[name].sample.startswith(DEX_MAGIC))
    if valid_dex_count:
        score += 2
    elif dex_names:
        score += 1

    if "resources.arsc" in names:
        score += 1
    if any(name.startswith("res/") for name in names):
        score += 1
    if any(name.startswith("lib/") and name.endswith(".so") for name in names):
        score += 1
    if any(name.startswith("META-INF/") and name.endswith((".RSA", ".DSA", ".EC", ".SF")) for name in names):
        score += 1

    return score


def _ios_package_score(entries: dict[str, ArchiveEntrySample]) -> int:
    score = 0
    names = set(entries)
    payload_app_prefixes = {
        name.split(".app/", 1)[0] + ".app/" for name in names if name.startswith("Payload/") and ".app/" in name
    }

    if payload_app_prefixes:
        score += 2

    for prefix in payload_app_prefixes:
        if any(
            name.startswith(prefix)
            and "/" not in name[len(prefix) :]
            and entries[name].sample.startswith(MACHO_MAGICS)
            for name in names
        ):
            score += 2
        if f"{prefix}Info.plist" in names:
            score += 1
        if f"{prefix}_CodeSignature/CodeResources" in names:
            score += 1
        if any(name.startswith(prefix) and name.endswith(".mobileprovision") for name in names):
            score += 1
        if any(
            name.startswith(prefix + "Frameworks/") and (".framework/" in name or name.endswith(".dylib"))
            for name in names
        ):
            score += 1

    return score


def _detect_raw_mobile_platform(data: bytes) -> str:
    if data.startswith(DEX_MAGIC):
        return "android"
    if data.startswith(MACHO_MAGICS):
        return "ios"
    return "mobile"


def _deduplicate(findings: Iterable[EvasionFinding]) -> list[EvasionFinding]:
    seen = set()
    unique = []
    for finding in findings:
        key = (
            finding.rule_id,
            finding.platform,
            finding.category,
            finding.indicator,
            finding.confidence,
            finding.evidence.lower(),
            finding.location,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
