from plcsec.baseline import build_baseline, compare_to_baseline, load_baseline, write_baseline
from plcsec.models import Asset, AssessmentReport, ServiceObservation


def _report() -> AssessmentReport:
    report = AssessmentReport.create("test", {})
    report.assets = [Asset(ip="192.0.2.10", mac_addresses=["02:00:00:00:00:01"], observed_services=[ServiceObservation("Modbus/TCP", 502)])]
    return report


def test_baseline_round_trip(tmp_path) -> None:
    baseline = build_baseline(_report(), "plant-lab")
    path = write_baseline(baseline, tmp_path / "baseline.json")
    loaded = load_baseline(path)
    assert loaded["site_id"] == "plant-lab"
    assert "192.0.2.10" in loaded["assets"]


def test_compare_detects_new_asset_and_service() -> None:
    baseline = build_baseline(_report(), "plant-lab")
    current = _report()
    current.assets[0].observed_services.append(ServiceObservation("Telnet", 23))
    current.assets.append(Asset(ip="192.0.2.30", observed_services=[]))
    compared = compare_to_baseline(current, baseline)
    ids = {finding.finding_id for finding in compared.findings}
    assert "BASELINE-NEW-ASSET-192.0.2.30" in ids
    assert "BASELINE-NEW-SERVICE-192.0.2.10-23" in ids


def test_load_rejects_unknown_schema(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"schema":"wrong","assets":{}}', encoding="utf-8")
    try:
        load_baseline(path)
    except ValueError as exc:
        assert "Unsupported" in str(exc)
    else:
        raise AssertionError("invalid baseline was accepted")
