from typing import Any, cast

from azul_runner import DATA_HASH, FV, Event, JobResult, State

from .common import BaseMobileEvasionTest, make_apk, make_ipa, make_zip


class TestMobileEvasionPlugin(BaseMobileEvasionTest):
    def test_android_evasion_features(self):
        data = make_apk(b"Build.HARDWARE == 'goldfish'", b"RootBeer", b"frida-agent")

        result = self.do_execution(data_in=[("content", data)], no_multiprocessing=True)

        expected_features = {
            "mobile_evasion_category": [FV("emulator"), FV("instrumentation"), FV("root")],
            "mobile_evasion_confidence": [FV("high"), FV("medium")],
            "mobile_evasion_confidence_reason": [
                FV("Matched high-confidence instrumentation evidence in dex content"),
                FV("Matched medium-confidence emulator evidence in dex content"),
                FV("Matched medium-confidence root evidence in dex content"),
            ],
            "mobile_evasion_context": [FV("dex 035 Build.HARDWARE == 'goldfish' RootBeer frida-agent")],
            "mobile_evasion_evidence": [FV("frida-agent"), FV("goldfish"), FV("RootBeer")],
            "mobile_evasion_file_kind": [FV("dex")],
            "mobile_evasion_file_size": [FV("57")],
            "mobile_evasion_indicator": [
                FV("Frida instrumentation probe"),
                FV("Android emulator hardware fingerprint probe"),
                FV("Android root environment probe"),
            ],
            "mobile_evasion_location": [FV("classes.dex")],
            "mobile_evasion_platform": [FV("android")],
            "mobile_evasion_rule_id": [
                FV("android-emulator-hardware"),
                FV("android-root"),
                FV("instrumentation-frida"),
            ],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_ios_evasion_features(self):
        data = make_ipa(b"SIMULATOR_DEVICE_NAME", b"/Applications/Cydia.app")

        result = self.do_execution(data_in=[("content", data)], no_multiprocessing=True)

        expected_features = {
            "mobile_evasion_category": [FV("jailbreak"), FV("simulator")],
            "mobile_evasion_confidence": [FV("medium"), FV("high")],
            "mobile_evasion_confidence_reason": [
                FV("Matched high-confidence simulator evidence in mach-o content"),
                FV("Matched medium-confidence jailbreak evidence in mach-o content"),
            ],
            "mobile_evasion_context": [FV("SIMULATOR_DEVICE_NAME /Applications/Cydia.app")],
            "mobile_evasion_evidence": [FV("/Applications/Cydia.app"), FV("SIMULATOR_DEVICE_NAME")],
            "mobile_evasion_file_kind": [FV("mach-o")],
            "mobile_evasion_file_size": [FV("49")],
            "mobile_evasion_indicator": [
                FV("iOS jailbreak environment probe"),
                FV("iOS simulator environment probe"),
            ],
            "mobile_evasion_location": [FV("Payload/Test.app/Test")],
            "mobile_evasion_platform": [FV("ios")],
            "mobile_evasion_rule_id": [FV("ios-jailbreak"), FV("ios-simulator")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_no_findings_returns_completed_empty(self):
        result = self.do_execution(data_in=[("content", make_apk(b"plain app"))], no_multiprocessing=True)

        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.COMPLETED_EMPTY, "No mobile evasion indicators detected")),
        )

    def test_multiple_locations_are_exposed_as_features(self):
        data = make_zip(
            {
                "AndroidManifest.xml": b"<manifest />",
                "classes.dex": b"ro.kernel.qemu",
                "lib/arm64-v8a/libcheck.so": b"frida-server",
            }
        )

        result = self.do_execution(data_in=[("content", data)], no_multiprocessing=True)

        expected_features = {
            "mobile_evasion_category": [FV("emulator"), FV("instrumentation")],
            "mobile_evasion_confidence": [FV("high")],
            "mobile_evasion_confidence_reason": [
                FV("Matched high-confidence emulator evidence in dex content"),
                FV("Matched high-confidence instrumentation evidence in elf content"),
            ],
            "mobile_evasion_context": [FV("frida-server"), FV("ro.kernel.qemu")],
            "mobile_evasion_evidence": [FV("frida-server"), FV("ro.kernel.qemu")],
            "mobile_evasion_file_kind": [FV("dex"), FV("elf")],
            "mobile_evasion_file_size": [FV("12"), FV("14")],
            "mobile_evasion_indicator": [
                FV("Frida instrumentation probe"),
                FV("Android emulator property or device probe"),
            ],
            "mobile_evasion_location": [FV("classes.dex"), FV("lib/arm64-v8a/libcheck.so")],
            "mobile_evasion_platform": [FV("android")],
            "mobile_evasion_rule_id": [FV("android-emulator-qemu"), FV("instrumentation-frida")],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=DATA_HASH(data).hexdigest(), features=expected_features)],
            ),
        )

    def test_configured_entry_size_limit_is_applied(self):
        data = make_zip(
            {
                "AndroidManifest.xml": b"<manifest />",
                "classes.dex": b"normal",
                "assets/large.bin": b"frida-server",
            }
        )

        result = self.do_execution(
            config=cast(Any, {"mobile_evasion_max_entry_size": 8}),
            data_in=[("content", data)],
            no_multiprocessing=True,
        )

        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.COMPLETED_EMPTY, "No mobile evasion indicators detected")),
        )

    def test_enriched_context_features_are_exposed(self):
        data = make_zip(
            {
                "AndroidManifest.xml": (
                    b'<manifest package="com.example.evasive">'
                    b'<uses-permission android:name="android.permission.READ_PHONE_STATE"/>'
                    b"</manifest>"
                ),
                "classes.dex": b"dex\n035\x00http://evil.test/a getDeviceId",
            }
        )

        result = self.do_execution(data_in=[("content", data)], no_multiprocessing=True)

        features = result.events[0].features
        assert FV("android_package=com.example.evasive") in features["mobile_evasion_package_identity"]
        assert FV("android.permission.READ_PHONE_STATE") in features["mobile_evasion_permission"]
        assert FV("http://evil.test/a") in features["mobile_evasion_network_indicator"]
