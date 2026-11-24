from plcsec.vendor_database import get_vendor_profile, load_vendor_database, list_vendors


def test_vendor_database_has_evidence_policy_and_conservative_id_map() -> None:
    database = load_vendor_database()
    assert database["schema"] == "plcsec.vendor-profiles.v1"
    assert database["evidence_policy"]["port_or_protocol_observation"].startswith("never-sufficient")
    assert database["cip_vendor_ids"]["1"]["manufacturer"] == "Rockwell Automation"
    assert len(list_vendors()) >= 8


def test_unknown_vendor_profile_is_not_guessed() -> None:
    assert get_vendor_profile("not-a-real-vendor") is None


def test_cip_vendor_id_1_enriches_as_explicit_mapping_not_port_guess() -> None:
    from plcsec.manufacturers import enrich_report_vendors
    report = {
        "assets": [{"ip": "192.0.2.10", "inventory_metadata": {}}],
        "events": [{"server_ip": "192.0.2.10", "event_type": "list_identity", "vendor_id": 1}],
    }
    result = enrich_report_vendors(report)
    profile = result["assets"][0]["inventory_metadata"]["plcsec_manufacturer_profile"]
    assert profile["manufacturer"] == "Rockwell Automation"
    assert profile["manufacturer_source"] == "ODVA Vendor ID 1"
    assert profile["database_profile_id"] == "rockwell-automation"
