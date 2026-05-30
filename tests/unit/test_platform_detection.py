from azul_plugin_mobile_evasion.scanner import detect_mobile_platform, scan_mobile_evasion

from .common import DEX_MAGIC, MACHO_64_MAGIC, make_apk, make_ipa, make_zip


def test_detects_android_from_zip_structure_without_filename_extension():
    package = make_apk(b"ro.kernel.qemu")

    assert detect_mobile_platform(package) == "android"
    assert {finding.rule_id for finding in scan_mobile_evasion(package)} == {"android-emulator-qemu"}


def test_detects_ios_from_payload_app_structure_without_filename_extension():
    package = make_ipa(b"TARGET_IPHONE_SIMULATOR")

    assert detect_mobile_platform(package) == "ios"
    assert {finding.rule_id for finding in scan_mobile_evasion(package)} == {"ios-simulator"}


def test_lone_classes_dex_inside_zip_is_not_enough_for_android():
    package = make_zip({"classes.dex": DEX_MAGIC + b"ro.kernel.qemu"})

    assert detect_mobile_platform(package) == "mobile"
    assert {finding.rule_id for finding in scan_mobile_evasion(package)} == set()


def test_lone_payload_app_file_is_not_enough_for_ios():
    package = make_zip({"Payload/Test.app/readme.txt": b"TARGET_IPHONE_SIMULATOR"})

    assert detect_mobile_platform(package) == "mobile"
    assert {finding.rule_id for finding in scan_mobile_evasion(package)} == set()


def test_apk_like_plain_xml_manifest_and_dex_are_enough_for_android():
    package = make_zip({"AndroidManifest.xml": b"<manifest />", "classes.dex": DEX_MAGIC + b"goldfish"})

    assert detect_mobile_platform(package) == "android"
    assert "android-emulator-hardware" in {finding.rule_id for finding in scan_mobile_evasion(package)}


def test_ipa_like_payload_app_info_plist_and_macho_are_enough_for_ios():
    package = make_zip({"Payload/Runner.app/Runner": MACHO_64_MAGIC + b"ptrace", "Payload/Runner.app/Info.plist": b""})

    assert detect_mobile_platform(package) == "ios"
    assert "anti-debug" in {finding.rule_id for finding in scan_mobile_evasion(package)}


def test_raw_dex_magic_is_android_without_filename_extension():
    data = DEX_MAGIC + b"ro.kernel.qemu"

    assert detect_mobile_platform(data) == "android"
    assert "android-emulator-qemu" in {finding.rule_id for finding in scan_mobile_evasion(data)}


def test_raw_macho_magic_is_ios_without_filename_extension():
    data = MACHO_64_MAGIC + b"TARGET_IPHONE_SIMULATOR"

    assert detect_mobile_platform(data) == "ios"
    assert "ios-simulator" in {finding.rule_id for finding in scan_mobile_evasion(data)}


def test_generic_zip_with_android_and_ios_strings_stays_mobile():
    package = make_zip({"notes.txt": b"ro.kernel.qemu TARGET_IPHONE_SIMULATOR frida-server"})

    assert detect_mobile_platform(package) == "mobile"
    assert {finding.rule_id for finding in scan_mobile_evasion(package)} == {"instrumentation-frida"}


def test_azul_file_format_metadata_is_used_as_android_hint():
    data = b"ro.kernel.qemu"

    assert detect_mobile_platform(data, file_format="android/apk") == "android"
    assert "android-emulator-qemu" in {
        finding.rule_id for finding in scan_mobile_evasion(data, file_format="android/apk")
    }


def test_azul_magic_metadata_is_used_as_ios_hint():
    data = b"TARGET_IPHONE_SIMULATOR"

    assert detect_mobile_platform(data, magic="Mach-O 64-bit executable arm64") == "ios"
    assert "ios-simulator" in {
        finding.rule_id for finding in scan_mobile_evasion(data, magic="Mach-O 64-bit executable arm64")
    }


def test_content_detection_wins_over_generic_azul_archive_type():
    package = make_apk(b"ro.kernel.qemu")

    assert detect_mobile_platform(package, file_format="archive/zip") == "android"
