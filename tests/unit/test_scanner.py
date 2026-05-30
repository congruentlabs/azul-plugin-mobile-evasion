import plistlib
import pytest
from zipfile import ZIP_DEFLATED

from azul_plugin_mobile_evasion.scanner import RULES, scan_mobile_evasion

from .common import DEX_MAGIC, encode_axml, make_apk, make_ipa, make_zip


def _rule_ids(findings):
    return {finding.rule_id for finding in findings}


def _finding_tuples(findings):
    return [(finding.platform, finding.category, finding.evidence, finding.location) for finding in findings]


def test_detects_android_emulator_property_probe():
    findings = scan_mobile_evasion(make_apk(b"SystemProperties.get('ro.kernel.qemu')", b"/dev/qemu_pipe"))

    assert [(finding.platform, finding.category, finding.evidence) for finding in findings] == [
        ("android", "emulator", "/dev/qemu_pipe"),
        ("android", "emulator", "ro.kernel.qemu"),
    ]


def test_detects_ios_simulator_and_debugger_probe():
    findings = scan_mobile_evasion(make_ipa(b"TARGET_IPHONE_SIMULATOR", b"ptrace", b"PT_DENY_ATTACH"))

    assert ("ios", "simulator", "TARGET_IPHONE_SIMULATOR") in [
        (finding.platform, finding.category, finding.evidence) for finding in findings
    ]
    assert ("ios", "debugger", "ptrace") in [
        (finding.platform, finding.category, finding.evidence) for finding in findings
    ]
    assert ("ios", "debugger", "PT_DENY_ATTACH") in [
        (finding.platform, finding.category, finding.evidence) for finding in findings
    ]


def test_returns_no_findings_for_plain_package():
    assert scan_mobile_evasion(make_apk(b"normal application content")) == []


@pytest.mark.parametrize(
    ("rule_id", "sample"),
    [
        ("android-emulator-qemu", b"ro.boot.qemu"),
        ("android-emulator-system-properties", b"ro.build.fingerprint"),
        ("android-emulator-hardware", b"generic_x86_64"),
        ("android-emulator-vendor", b"BlueStacks"),
        ("android-emulator-telephony", b"getSimSerialNumber"),
        ("android-emulator-sensor", b"SensorManager"),
        ("android-root", b"/system/xbin/su"),
        ("android-root-packages", b"com.kingroot.kinguser"),
        ("android-root-build-tags", b"test-keys"),
        ("android-integrity-attestation", b"SafetyNetClient"),
        ("android-hooking-framework", b"de.robv.android.xposed"),
    ],
)
def test_android_rule_families_are_covered(rule_id, sample):
    assert rule_id in _rule_ids(scan_mobile_evasion(make_apk(sample)))


@pytest.mark.parametrize(
    ("rule_id", "sample"),
    [
        ("ios-simulator", b"x86_64-apple-ios-simulator"),
        ("ios-jailbreak", b"/private/var/lib/apt"),
        ("ios-jailbreak-schemes", b"sileo://"),
        ("ios-filesystem-write", b"/private/jailbreak.txt"),
        ("anti-debug", b"PT_DENY_ATTACH"),
        ("anti-tamper-signature", b"SecCodeCopySelf"),
        ("instrumentation-frida", b"frida-server"),
        ("instrumentation-tools", b"MSHookMessageEx"),
        ("network-proxy", b"CFNetworkCopySystemProxySettings"),
    ],
)
def test_ios_and_mobile_rule_families_are_covered(rule_id, sample):
    assert rule_id in _rule_ids(scan_mobile_evasion(make_ipa(sample)))


def test_detects_android_root_hooking_attestation_and_proxy_checks():
    findings = scan_mobile_evasion(
        make_apk(
            b"com.topjohnwu.magisk",
            b"XposedBridge",
            b"IntegrityManager MEETS_STRONG_INTEGRITY",
            b"ProxySelector http.proxyHost",
        )
    )

    rules = _rule_ids(findings)

    assert "android-root-packages" in rules
    assert "android-hooking-framework" in rules
    assert "android-integrity-attestation" in rules
    assert "network-proxy" in rules


def test_detects_ios_jailbreak_instrumentation_tamper_and_debug_checks():
    findings = scan_mobile_evasion(
        make_ipa(
            b"SubstrateLoader.dylib",
            b"MSHookFunction",
            b"SecStaticCodeCheckValidity",
            b"task_get_exception_ports",
            b"CFNetworkCopySystemProxySettings",
        )
    )

    rules = _rule_ids(findings)

    assert "ios-jailbreak" in rules
    assert "instrumentation-tools" in rules
    assert "anti-tamper-signature" in rules
    assert "anti-debug" in rules
    assert "network-proxy" in rules


def test_android_rules_do_not_fire_for_ios_packages():
    findings = scan_mobile_evasion(make_ipa(b"ro.kernel.qemu", b"com.topjohnwu.magisk"))

    assert "android-emulator-qemu" not in _rule_ids(findings)
    assert "android-root-packages" not in _rule_ids(findings)


def test_ios_rules_do_not_fire_for_android_packages():
    findings = scan_mobile_evasion(make_apk(b"TARGET_IPHONE_SIMULATOR", b"/Applications/Cydia.app"))

    assert "ios-simulator" not in _rule_ids(findings)
    assert "ios-jailbreak" not in _rule_ids(findings)


def test_mobile_rules_fire_for_raw_binary_with_mobile_platform():
    findings = scan_mobile_evasion(b"plain native blob with frida-server and ptrace")

    assert ("mobile", "debugger", "ptrace", "input") in _finding_tuples(findings)
    assert ("mobile", "instrumentation", "frida-server", "input") in _finding_tuples(findings)


def test_raw_binary_does_not_fire_platform_specific_rules():
    findings = scan_mobile_evasion(b"ro.kernel.qemu TARGET_IPHONE_SIMULATOR")

    assert "android-emulator-qemu" not in _rule_ids(findings)
    assert "ios-simulator" not in _rule_ids(findings)


def test_zip_without_mobile_markers_uses_mobile_rules_only():
    findings = scan_mobile_evasion(make_zip({"payload.bin": b"frida-server ro.kernel.qemu"}))

    assert "instrumentation-frida" in _rule_ids(findings)
    assert "android-emulator-qemu" not in _rule_ids(findings)


def test_duplicate_evidence_in_same_location_is_suppressed():
    findings = scan_mobile_evasion(make_apk(b"frida-server frida-server"))

    frida_findings = [finding for finding in findings if finding.rule_id == "instrumentation-frida"]

    assert len(frida_findings) == 1
    assert frida_findings[0].evidence == "frida-server"


def test_specific_evidence_wins_over_substring_evidence():
    findings = scan_mobile_evasion(make_apk(b"frida-agent"))

    evidence = [finding.evidence for finding in findings if finding.rule_id == "instrumentation-frida"]

    assert evidence == ["frida-agent"]


def test_same_evidence_in_different_locations_is_preserved():
    findings = scan_mobile_evasion(
        make_zip(
            {
                "AndroidManifest.xml": b"<manifest />",
                "classes.dex": b"frida-server",
                "lib/arm64-v8a/libcheck.so": b"frida-server",
            }
        )
    )

    locations = sorted(finding.location for finding in findings if finding.rule_id == "instrumentation-frida")

    assert locations == ["classes.dex", "lib/arm64-v8a/libcheck.so"]


def test_large_archive_entries_are_scanned_by_default():
    findings = scan_mobile_evasion(
        make_zip(
            {
                "AndroidManifest.xml": b"<manifest />",
                "classes.dex": b"normal",
                "assets/large.bin": b"frida-server" + (b"x" * (21 * 1024 * 1024)),
            },
            compression=ZIP_DEFLATED,
        )
    )

    assert "instrumentation-frida" in _rule_ids(findings)


def test_archive_entries_over_configured_limit_are_skipped():
    findings = scan_mobile_evasion(
        make_zip(
            {
                "AndroidManifest.xml": b"<manifest />",
                "classes.dex": b"normal",
                "assets/large.bin": b"frida-server",
            }
        ),
        max_entry_size=8,
    )

    assert "instrumentation-frida" not in _rule_ids(findings)


def test_archive_scan_stops_at_total_scan_budget():
    findings = scan_mobile_evasion(
        make_zip(
            {
                "AndroidManifest.xml": b"<manifest />",
                "classes.dex": b"frida-server",
                "assets/over-budget.bin": b"ptrace",
            }
        ),
        max_total_scan_size=24,
    )

    assert "instrumentation-frida" in _rule_ids(findings)
    assert "anti-debug" not in _rule_ids(findings)


def test_archive_scan_stops_at_entry_budget():
    findings = scan_mobile_evasion(
        make_zip(
            {
                "AndroidManifest.xml": b"<manifest />",
                "classes.dex": b"normal",
                "assets/over-budget.bin": b"frida-server",
            }
        ),
        max_archive_entries=2,
    )

    assert "instrumentation-frida" not in _rule_ids(findings)


def test_finding_includes_file_context_and_confidence_reason():
    findings = scan_mobile_evasion(make_apk(b"before http://evil.test/a frida-server after"))

    finding = next(finding for finding in findings if finding.rule_id == "instrumentation-frida")

    assert finding.file_kind == "dex"
    assert finding.file_size > 0
    assert "frida-server" in finding.context
    assert "http://evil.test/a" in finding.network_indicators
    assert finding.confidence_reason == "Matched high-confidence instrumentation evidence in dex content"


def test_extracts_plain_android_manifest_identity_and_permissions():
    data = make_zip(
        {
            "AndroidManifest.xml": (
                b'<manifest package="com.example.evasive" android:versionName="1.2.3">'
                b'<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>'
                b'<uses-permission android:name="android.permission.READ_PHONE_STATE"/>'
                b"</manifest>"
            ),
            "classes.dex": DEX_MAGIC + b"getDeviceId",
        }
    )

    finding = scan_mobile_evasion(data)[0]

    assert "android_package=com.example.evasive" in finding.package_identity
    assert "android_version_name=1.2.3" in finding.package_identity
    assert "android_min_sdk=23" in finding.package_identity
    assert "android_target_sdk=35" in finding.package_identity
    assert finding.permissions == ("android.permission.READ_PHONE_STATE",)


def test_extracts_ios_info_plist_identity_and_url_schemes():
    data = make_ipa(
        b"ptrace",
        info_plist={
            "CFBundleIdentifier": "com.example.sideload",
            "CFBundleName": "SideLoad",
            "CFBundleShortVersionString": "9.9",
            "CFBundleExecutable": "SideLoad",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["sileo"]}],
        },
    )

    finding = scan_mobile_evasion(data)[0]

    assert "ios_bundle_id=com.example.sideload" in finding.package_identity
    assert "ios_bundle_name=SideLoad" in finding.package_identity
    assert "ios_version=9.9" in finding.package_identity
    assert "ios_executable=SideLoad" in finding.package_identity
    assert finding.entitlements == ("url_scheme=sileo",)


def test_scans_nested_mobile_archives_with_nested_location():
    nested = make_ipa(b"frida-server")
    data = make_zip(
        {
            "AndroidManifest.xml": b"<manifest />",
            "classes.dex": DEX_MAGIC + b"normal",
            "assets/backup.ipa": nested,
        }
    )

    findings = scan_mobile_evasion(data)

    assert ("assets/backup.ipa!Payload/Test.app/Test") in {
        finding.location for finding in findings if finding.rule_id == "instrumentation-frida"
    }


def test_rule_ids_are_unique():
    rule_ids = [rule.rule_id for rule in RULES]

    assert len(rule_ids) == len(set(rule_ids))


def test_rule_patterns_are_non_empty_and_unique_within_rule():
    for rule in RULES:
        assert rule.patterns
        assert len(rule.patterns) == len(set(rule.patterns))
        assert all(pattern for pattern in rule.patterns)


def test_extracts_identity_and_permissions_from_binary_android_manifest():
    data = make_zip(
        {
            "AndroidManifest.xml": encode_axml(
                package="com.example.binary",
                version_name="4.5.6",
                min_sdk=24,
                target_sdk=34,
                permissions=["android.permission.READ_PHONE_STATE", "android.permission.INTERNET"],
            ),
            "classes.dex": DEX_MAGIC + b"getDeviceId",
            "resources.arsc": b"resources",
        }
    )

    finding = next(finding for finding in scan_mobile_evasion(data) if finding.rule_id == "android-emulator-telephony")

    assert "android_package=com.example.binary" in finding.package_identity
    assert "android_version_name=4.5.6" in finding.package_identity
    assert "android_min_sdk=24" in finding.package_identity
    assert "android_target_sdk=34" in finding.package_identity
    assert finding.permissions == ("android.permission.INTERNET", "android.permission.READ_PHONE_STATE")


def test_extracts_binary_android_manifest_with_utf16_string_pool():
    data = make_zip(
        {
            "AndroidManifest.xml": encode_axml(
                package="com.example.utf16",
                version_name="1.0",
                min_sdk=21,
                target_sdk=33,
                permissions=["android.permission.CAMERA"],
                utf8=False,
            ),
            "classes.dex": DEX_MAGIC + b"getDeviceId",
            "resources.arsc": b"resources",
        }
    )

    finding = next(finding for finding in scan_mobile_evasion(data) if finding.rule_id == "android-emulator-telephony")

    assert "android_package=com.example.utf16" in finding.package_identity
    assert finding.permissions == ("android.permission.CAMERA",)


def test_extracts_ios_identity_from_binary_info_plist():
    data = make_ipa(
        b"ptrace",
        info_plist={
            "CFBundleIdentifier": "com.example.binplist",
            "CFBundleExecutable": "Test",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["sileo"]}],
        },
        plist_fmt=plistlib.FMT_BINARY,
    )

    finding = next(finding for finding in scan_mobile_evasion(data) if finding.rule_id == "anti-debug")

    assert "ios_bundle_id=com.example.binplist" in finding.package_identity
    assert finding.entitlements == ("url_scheme=sileo",)


def test_extracts_ios_identity_from_info_plist_larger_than_sample_size():
    data = make_ipa(
        b"ptrace",
        info_plist={
            "CFBundleIdentifier": "com.example.large",
            "CFBundleExecutable": "Test",
            "Padding": "A" * 9000,
        },
    )

    finding = next(finding for finding in scan_mobile_evasion(data) if finding.rule_id == "anti-debug")

    assert "ios_bundle_id=com.example.large" in finding.package_identity


def test_samsung_knox_string_does_not_trigger_emulator_vendor():
    findings = scan_mobile_evasion(make_apk(b"com.samsung.android.knox.KnoxEnterpriseLicenseManager"))

    assert "android-emulator-vendor" not in _rule_ids(findings)


def test_frida_default_ports_alone_do_not_trigger():
    findings = scan_mobile_evasion(make_apk(b"open socket on 127.0.0.1:27042 and 27043"))

    assert "instrumentation-frida" not in _rule_ids(findings)


def test_normal_private_path_does_not_trigger_filesystem_write():
    findings = scan_mobile_evasion(make_ipa(b"/private/var/mobile/Containers writeToFile FileManager.default"))

    assert "ios-filesystem-write" not in _rule_ids(findings)
