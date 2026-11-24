import json

from plcsec.cef_export import export_cef_report, finding_to_cef


def test_cef_escapes_header_and_extension_fields() -> None:
    line = finding_to_cef({
        "finding_id": "F|1", "title": "Unexpected = service", "severity": "high",
        "priority_score": 88, "description": "line one\nline two = x",
        "evidence": {"ip": "192.0.2.10", "dst_port": 502},
    })
    assert line.startswith("CEF:0|PLCSEC|Industrial Security Framework|")
    assert "F\\|1" in line
    assert "Unexpected = service" in line
    assert "msg=line one line two \\= x" in line
    assert "dhost=192.0.2.10" in line
    assert "dpt=502" in line


def test_export_cef_report(tmp_path) -> None:
    source = tmp_path / "report.json"
    target = tmp_path / "out.cef"
    source.write_text(json.dumps({"tool_version": "0.6.0", "findings": [
        {"finding_id": "F1", "title": "Finding", "severity": "medium", "description": "Test", "evidence": {}}
    ]}), encoding="utf-8")
    result = export_cef_report(source, target)
    assert result["event_count"] == 1
    assert target.read_text(encoding="utf-8").startswith("CEF:0|")


def test_cef_empty_findings_creates_empty_file(tmp_path) -> None:
    source = tmp_path / "report.json"
    target = tmp_path / "empty.cef"
    source.write_text('{"findings": []}', encoding="utf-8")
    result = export_cef_report(source, target)
    assert result["event_count"] == 0
    assert target.read_text(encoding="utf-8") == ""
