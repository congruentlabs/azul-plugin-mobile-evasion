"""Detect mobile anti-analysis and environment evasion indicators."""

from azul_runner import BinaryPlugin, Feature, FeatureType, Job, State, add_settings, cmdline_run

from .scanner import (
    DEFAULT_MAX_ARCHIVE_ENTRIES,
    DEFAULT_MAX_ENTRY_SIZE,
    DEFAULT_MAX_TOTAL_SCAN_SIZE,
    scan_mobile_evasion,
)


class AzulPluginMobileEvasion(BinaryPlugin):
    """Detect mobile anti-analysis and environment evasion indicators."""

    VERSION = "2026.05.22"
    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "android/apk",
                "ios/ipa",
                "archive/zip",
                "executable/mach-o",
            ]
        },
        filter_max_content_size="512MiB",
        mobile_evasion_max_entry_size=(int, DEFAULT_MAX_ENTRY_SIZE),
        mobile_evasion_max_total_scan_size=(int, DEFAULT_MAX_TOTAL_SCAN_SIZE),
        mobile_evasion_max_archive_entries=(int, DEFAULT_MAX_ARCHIVE_ENTRIES),
    )
    FEATURES = [
        Feature("mobile_evasion_rule_id", desc="Rule identifier for the detected indicator", type=FeatureType.String),
        Feature("mobile_evasion_indicator", desc="Detected mobile evasion indicator", type=FeatureType.String),
        Feature(
            "mobile_evasion_category", desc="Category of detected mobile evasion behavior", type=FeatureType.String
        ),
        Feature(
            "mobile_evasion_platform", desc="Mobile platform associated with the indicator", type=FeatureType.String
        ),
        Feature(
            "mobile_evasion_evidence", desc="Static evidence that triggered the indicator", type=FeatureType.String
        ),
        Feature("mobile_evasion_confidence", desc="Confidence assigned to the indicator", type=FeatureType.String),
        Feature(
            "mobile_evasion_location", desc="Location in the package where evidence was found", type=FeatureType.String
        ),
        Feature("mobile_evasion_file_kind", desc="Type of file containing the evidence", type=FeatureType.String),
        Feature(
            "mobile_evasion_file_size",
            desc="Uncompressed size of the file containing the evidence",
            type=FeatureType.Integer,
        ),
        Feature(
            "mobile_evasion_context",
            desc="Short surrounding context for the matched evidence",
            type=FeatureType.String,
        ),
        Feature(
            "mobile_evasion_confidence_reason",
            desc="Reason for the assigned confidence",
            type=FeatureType.String,
        ),
        Feature("mobile_evasion_package_identity", desc="Mobile package identity metadata", type=FeatureType.String),
        Feature("mobile_evasion_permission", desc="Relevant Android package permission", type=FeatureType.String),
        Feature(
            "mobile_evasion_entitlement",
            desc="Relevant iOS package entitlement or URL scheme",
            type=FeatureType.String,
        ),
        Feature(
            "mobile_evasion_network_indicator",
            desc="Network indicator found near evasion evidence",
            type=FeatureType.String,
        ),
    ]

    def execute(self, job: Job):
        """Run static mobile evasion scanning."""
        data = job.get_data().read()
        entity = job.event.entity
        config = self.cfg.model_dump()
        findings = scan_mobile_evasion(
            data,
            file_format=entity.file_format,
            mime=entity.mime,
            magic=entity.magic,
            max_entry_size=config["mobile_evasion_max_entry_size"],
            max_total_scan_size=config["mobile_evasion_max_total_scan_size"],
            max_archive_entries=config["mobile_evasion_max_archive_entries"],
        )
        if not findings:
            return State(State.Label.COMPLETED_EMPTY, "No mobile evasion indicators detected")

        self.add_feature_values("mobile_evasion_indicator", [finding.indicator for finding in findings])
        self.add_feature_values("mobile_evasion_rule_id", [finding.rule_id for finding in findings])
        self.add_feature_values("mobile_evasion_category", [finding.category for finding in findings])
        self.add_feature_values("mobile_evasion_platform", [finding.platform for finding in findings])
        self.add_feature_values("mobile_evasion_evidence", [finding.evidence for finding in findings])
        self.add_feature_values("mobile_evasion_confidence", [finding.confidence for finding in findings])
        self.add_feature_values("mobile_evasion_location", [finding.location for finding in findings])
        self.add_feature_values("mobile_evasion_file_kind", [finding.file_kind for finding in findings])
        self.add_feature_values("mobile_evasion_file_size", [finding.file_size for finding in findings])
        self.add_feature_values("mobile_evasion_context", [finding.context for finding in findings])
        self.add_feature_values(
            "mobile_evasion_confidence_reason", [finding.confidence_reason for finding in findings]
        )
        self.add_feature_values(
            "mobile_evasion_package_identity",
            [value for finding in findings for value in finding.package_identity],
        )
        self.add_feature_values(
            "mobile_evasion_permission",
            [value for finding in findings for value in finding.permissions],
        )
        self.add_feature_values(
            "mobile_evasion_entitlement",
            [value for finding in findings for value in finding.entitlements],
        )
        self.add_feature_values(
            "mobile_evasion_network_indicator",
            [value for finding in findings for value in finding.network_indicators],
        )


def main():
    """Run the plugin from the command line."""
    cmdline_run(AzulPluginMobileEvasion)


if __name__ == "__main__":
    main()
