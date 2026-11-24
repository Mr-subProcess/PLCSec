from __future__ import annotations

from plcsec.manufacturers import canonical_vendor, enrich_report_vendors, identify_cip_vendor


def test_only_confirmed_cip_vendor_is_named() -> None:
    assert identify_cip_vendor(1)["manufacturer"] == "Rockwell Automation"
    assert identify_cip_vendor(9999)["manufacturer"] == "Unknown / not mapped"


def test_owner_inventory_vendor_and_model_are_normalized() -> None:
    report = {"assets": [{"ip": "192.0.2.10", "inventory_metadata": {"vendor": "Siemens AG", "model": "SIMATIC S7-1500"}}], "events": []}
    enriched = enrich_report_vendors(report)
    profile = enriched["assets"][0]["inventory_metadata"]["plcsec_manufacturer_profile"]
    assert profile["manufacturer"] == "Siemens"
    assert profile["model_family_hint"] == "Siemens SIMATIC S7-1500"
    assert canonical_vendor("MELSEC iQ-R")[0] == "Mitsubishi Electric"


def test_s7_port_or_event_is_not_used_as_confirmed_manufacturer() -> None:
    report = {"assets": [{"ip": "192.0.2.20", "inventory_metadata": {}}], "events": [{"server_ip": "192.0.2.20", "protocol": "S7comm"}]}
    enrich_report_vendors(report)
    assert "plcsec_manufacturer_profile" not in report["assets"][0]["inventory_metadata"]


def test_cip_vendor_id_one_maps_to_rockwell_only_for_identity_event() -> None:
    report = {
        "assets": [{"ip": "192.0.2.1", "inventory_metadata": {}}],
        "events": [{"server_ip": "192.0.2.1", "event_type": "list_identity", "vendor_id": 1, "product_name": "ControlLogix"}],
    }
    enriched = enrich_report_vendors(report)
    profile = enriched["assets"][0]["inventory_metadata"]["plcsec_manufacturer_profile"]
    assert profile["cip_identity_observations"][0]["manufacturer"] == "Rockwell Automation"
