import json

from plcsec.stix_export import export_stix_report, report_to_stix_bundle, validate_stix_bundle


def _report() -> dict:
    return {
        "tool": "PLCSEC", "tool_version": "0.6.0", "assessment_type": "passive-pcap-analysis",
        "started_at": "2026-11-23T08:00:00Z", "completed_at": "2026-11-23T08:01:00Z",
        "scope": {"capture": "synthetic.pcap"},
        "assets": [{"ip": "192.0.2.10", "packets_seen": 12, "first_seen": "2026-11-23T08:00:00Z", "last_seen": "2026-11-23T08:01:00Z"}],
        "flows": [{"src_ip": "192.0.2.20", "dst_ip": "192.0.2.10", "src_port": 40000, "dst_port": 502, "transport": "tcp", "packets": 5}],
        "findings": [{"finding_id": "TEST-1", "title": "Unexpected observed service", "severity": "medium", "confidence": "medium", "description": "Review this observation.", "evidence": {"ip": "192.0.2.10"}, "recommendation": "Validate with owner."}],
    }


def test_stix_bundle_contains_asset_flow_and_finding_note() -> None:
    bundle = report_to_stix_bundle(_report())
    validate_stix_bundle(bundle)
    kinds = [obj["type"] for obj in bundle["objects"]]
    assert "identity" in kinds
    assert "ipv4-addr" in kinds
    assert "network-traffic" in kinds
    assert "observed-data" in kinds
    assert "note" in kinds


def test_stix_note_is_not_misrepresented_as_vulnerability() -> None:
    bundle = report_to_stix_bundle(_report())
    assert not any(obj["type"] == "vulnerability" for obj in bundle["objects"])
    note = next(obj for obj in bundle["objects"] if obj["type"] == "note")
    content = json.loads(note["content"])
    assert content["finding_id"] == "TEST-1"
    assert "not a confirmed vulnerability" in content["interpretation"]


def test_stix_rejects_missing_reference() -> None:
    bundle = report_to_stix_bundle(_report())
    note = next(obj for obj in bundle["objects"] if obj["type"] == "note")
    note["object_refs"] = ["observed-data--00000000-0000-4000-8000-000000000000"]
    try:
        validate_stix_bundle(bundle)
    except ValueError as exc:
        assert "missing object" in str(exc)
    else:
        raise AssertionError("missing reference was accepted")


def test_export_stix_report(tmp_path) -> None:
    source = tmp_path / "assessment.json"
    target = tmp_path / "out" / "assessment.stix.json"
    source.write_text(json.dumps(_report()), encoding="utf-8")
    result = export_stix_report(source, target)
    assert result["stix_version"] == "2.1"
    assert target.is_file()
    validate_stix_bundle(json.loads(target.read_text(encoding="utf-8")))
