from __future__ import annotations

from plcsec.compliance import crosswalk_report


def test_crosswalk_maps_evidence_tags_without_claiming_compliance() -> None:
    report = {"schema_version": "plcsec.report.v2", "tool_version": "0.4.0", "findings": [
        {"finding_id": "F1", "title": "Unexpected device", "severity": "medium", "tags": ["asset-inventory"]},
        {"finding_id": "F2", "title": "Write request", "severity": "info", "tags": ["write-capable-traffic"]},
    ]}
    result = crosswalk_report(report)
    assert result["mapped_finding_count"] == 2
    assert result["is_certification"] is False
    assert any("FR 1" in theme for item in result["mappings"] for mapping in item["mappings"] for theme in mapping["iec_62443_themes"])
    assert any("FR 2" in theme for item in result["mappings"] for mapping in item["mappings"] for theme in mapping["iec_62443_themes"])
    assert result["limitations"]
