import json

import pytest

from plcsec.inventory import apply_inventory, load_inventory, validate_inventory
from plcsec.models import Asset, AssessmentReport, ServiceObservation


def _write_inventory(path, assets):
    path.write_text(json.dumps({
        "schema": "plcsec.asset-inventory.v1",
        "site_id": "lab-a",
        "assets": assets,
    }), encoding="utf-8")
    return path


def test_inventory_validates_and_enriches_observed_asset(tmp_path):
    path = _write_inventory(tmp_path / "inventory.json", [{
        "asset_id": "PLC-01",
        "ip": "192.0.2.10",
        "vendor": "Example Controls",
        "model": "PLC-X",
        "role": "cell-controller",
        "criticality": "high",
        "zone": "control",
        "expected_services": [{"protocol": "Modbus/TCP", "port": 502}],
    }])
    assert validate_inventory(path)["asset_count"] == 1
    inventory = load_inventory(path)
    report = AssessmentReport.create("test", {})
    report.assets = [Asset(
        ip="192.0.2.10",
        observed_services=[ServiceObservation("Modbus/TCP", 502)],
    )]
    apply_inventory(report, inventory)
    assert report.assets[0].inventory_metadata["asset_id"] == "PLC-01"
    assert report.findings == []
    assert report.metadata["asset_inventory_analysis"]["observed_inventory_asset_count"] == 1


def test_inventory_flags_unregistered_endpoint_and_unexpected_service(tmp_path):
    path = _write_inventory(tmp_path / "inventory.json", [{
        "asset_id": "PLC-01",
        "ip": "192.0.2.10",
        "criticality": "safety",
        "expected_services": [{"protocol": "Modbus/TCP", "port": 502}],
    }])
    report = AssessmentReport.create("test", {})
    report.assets = [
        Asset(ip="192.0.2.10", observed_services=[ServiceObservation("HTTP", 80)]),
        Asset(ip="192.0.2.20"),
    ]
    apply_inventory(report, load_inventory(path))
    ids = {finding.finding_id for finding in report.findings}
    assert "INV-UNEXPECTED-SERVICE-PLC-01-80" in ids
    assert "INV-UNREGISTERED-ASSET-192.0.2.20" in ids


def test_inventory_rejects_duplicate_ips(tmp_path):
    path = _write_inventory(tmp_path / "inventory.json", [
        {"asset_id": "A", "ip": "192.0.2.1"},
        {"asset_id": "B", "ip": "192.0.2.1"},
    ])
    with pytest.raises(ValueError, match="duplicate inventory IP"):
        load_inventory(path)


def test_inventory_rejects_invalid_criticality(tmp_path):
    path = _write_inventory(tmp_path / "inventory.json", [{
        "asset_id": "A", "ip": "192.0.2.1", "criticality": "unbounded",
    }])
    with pytest.raises(ValueError, match="criticality"):
        load_inventory(path)


def test_inventory_rejects_overlong_metadata(tmp_path):
    path = _write_inventory(tmp_path / "inventory.json", [{
        "asset_id": "A", "ip": "192.0.2.1", "vendor": "V" * 1025,
    }])
    with pytest.raises(ValueError, match="exceeds"):
        load_inventory(path)
