import json
from pathlib import Path

from plcsec.models import AssessmentReport, Finding, Severity
from plcsec.reporting import write_html, write_json, write_report


def test_report_json_and_html_escape(tmp_path: Path) -> None:
    report = AssessmentReport.create("unit-test", {"scope": "lab"})
    report.findings.append(Finding(
        finding_id="TEST-1",
        title="Untrusted <tag>",
        severity=Severity.LOW,
        description="A & B",
        evidence={"sample": "<script>alert(1)</script>"},
    ))
    json_path = write_json(report, tmp_path / "report.json")
    html_path = write_html(report, tmp_path / "report.html")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["findings"][0]["title"] == "Untrusted <tag>"
    html_text = html_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html_text
    assert "<script>alert(1)</script>" not in html_text


def test_write_report_both(tmp_path: Path) -> None:
    report = AssessmentReport.create("unit-test", {})
    paths = write_report(report, tmp_path / "out", "both")
    assert {p.suffix for p in paths} == {".json", ".html"}


def test_write_report_all_includes_csv(tmp_path: Path) -> None:
    report = AssessmentReport.create("unit-test", {})
    report.assets.append(__import__("plcsec.models", fromlist=["Asset"]).Asset(ip="192.0.2.1"))
    paths = write_report(report, tmp_path / "full", "all")
    assert {path.suffix for path in paths} == {".json", ".html", ".csv"}
    assert (tmp_path / "full_flows.csv").exists()
    assert (tmp_path / "full_assets.csv").exists()
    assert (tmp_path / "full_findings.csv").exists()


def test_csv_neutralizes_formula_like_untrusted_values(tmp_path: Path) -> None:
    from plcsec.models import Asset
    from plcsec.reporting import write_csv

    report = AssessmentReport.create("unit-test", {})
    report.assets.append(Asset(ip="192.0.2.5", vendor_hints=["=HYPERLINK(\"https://invalid\")"]))
    paths = write_csv(report, tmp_path / "safe")
    csv_text = paths[0].read_text(encoding="utf-8")
    assert "'=HYPERLINK" in csv_text
