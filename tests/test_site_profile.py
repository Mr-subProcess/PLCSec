import json

import pytest

from plcsec.models import AssessmentReport, FlowObservation
from plcsec.site_profile import apply_site_profile, load_site_profile, validate_site_profile


def _write_profile(path, zones, conduits=None):
    path.write_text(json.dumps({
        "schema": "plcsec.site-profile.v1",
        "site_id": "test-plant",
        "zones": zones,
        "approved_conduits": conduits or [],
    }), encoding="utf-8")
    return path


def test_validate_site_profile(tmp_path):
    path = _write_profile(tmp_path / "site.json", [
        {"name": "dmz", "cidrs": ["192.0.2.0/24"]},
        {"name": "control", "cidrs": ["198.51.100.0/24"]},
    ])
    result = validate_site_profile(path)
    assert result["zone_count"] == 2
    assert result["site_id"] == "test-plant"


def test_overlapping_zone_networks_are_rejected(tmp_path):
    path = _write_profile(tmp_path / "overlap.json", [
        {"name": "zone-a", "cidrs": ["192.0.2.0/24"]},
        {"name": "zone-b", "cidrs": ["192.0.2.128/25"]},
    ])
    with pytest.raises(ValueError, match="overlapping"):
        load_site_profile(path)


def test_site_profile_flags_unapproved_cross_zone_flow(tmp_path):
    path = _write_profile(tmp_path / "site.json", [
        {"name": "dmz", "cidrs": ["192.0.2.0/24"]},
        {"name": "control", "cidrs": ["198.51.100.0/24"]},
    ])
    profile = load_site_profile(path)
    report = AssessmentReport.create("test", {})
    report.flows = [FlowObservation("192.0.2.10", "198.51.100.10", 45000, 502, "tcp", 3, 240)]
    apply_site_profile(report, profile)
    assert len(report.findings) == 1
    assert report.findings[0].finding_id.startswith("ZONE-UNAPPROVED")


def test_site_profile_accepts_explicit_conduit(tmp_path):
    path = _write_profile(tmp_path / "site.json", [
        {"name": "dmz", "cidrs": ["192.0.2.0/24"]},
        {"name": "control", "cidrs": ["198.51.100.0/24"]},
    ], [{"source_zone": "dmz", "destination_zone": "control", "transport": "tcp", "destination_port": 502, "purpose": "SCADA"}])
    profile = load_site_profile(path)
    report = AssessmentReport.create("test", {})
    report.flows = [FlowObservation("192.0.2.10", "198.51.100.10", 45000, 502, "tcp", 3, 240)]
    apply_site_profile(report, profile)
    assert report.findings == []
    assert report.metadata["site_profile_analysis"]["unapproved_cross_zone_flows"] == 0


def test_duplicate_conduits_are_rejected(tmp_path):
    path = _write_profile(tmp_path / "duplicate.json", [
        {"name": "dmz", "cidrs": ["192.0.2.0/24"]},
        {"name": "control", "cidrs": ["198.51.100.0/24"]},
    ], [
        {"source_zone": "dmz", "destination_zone": "control", "transport": "tcp", "destination_port": 502},
        {"source_zone": "dmz", "destination_zone": "control", "transport": "tcp", "destination_port": 502},
    ])
    with pytest.raises(ValueError, match="duplicate approved conduit"):
        load_site_profile(path)
