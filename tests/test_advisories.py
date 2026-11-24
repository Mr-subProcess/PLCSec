from __future__ import annotations

import json
from pathlib import Path

import pytest

from plcsec.advisories import (
    load_advisory_database,
    match_advisories,
    validate_advisory_database,
)
from plcsec.inventory import load_inventory

ROOT = Path(__file__).parents[1]


def test_synthetic_advisory_database_validates() -> None:
    result = validate_advisory_database(ROOT / "examples" / "advisories.example.json")
    assert result["schema"] == "plcsec.advisories.v1"
    assert result["advisory_count"] == 1
    assert "no fuzzy/range matching" in result["match_policy"]


def test_advisory_matches_exact_normalized_identity_and_firmware(tmp_path: Path) -> None:
    inventory_data = json.loads((ROOT / "examples" / "asset_inventory.example.json").read_text())
    inventory_data["assets"][0]["vendor"] = "  example   vendor "
    inventory_data["assets"][0]["model"] = "EXAMPLE CONTROLLER"
    inventory_data["assets"][0]["firmware"] = " DOCUMENTED-FIRMWARE-VERSION "
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(inventory_data), encoding="utf-8")
    inventory = load_inventory(inventory_path)
    database = load_advisory_database(ROOT / "examples" / "advisories.example.json")
    result = match_advisories(inventory, database)
    assert result["match_count"] == 1
    match = result["matches"][0]
    assert match["advisory_id"] == "SYNTHETIC-OT-2026-0001"
    assert match["match_confidence"] == "exact-normalized-string-match"
    assert result["is_vendor_applicability_confirmed"] is False


def test_advisory_does_not_fuzzy_match_firmware(tmp_path: Path) -> None:
    inventory_path = tmp_path / "inventory.json"
    source_inventory = json.loads((ROOT / "examples" / "asset_inventory.example.json").read_text())
    source_inventory["assets"][0]["firmware"] = "documented-firmware-version-plus-build"
    inventory_path.write_text(json.dumps(source_inventory), encoding="utf-8")
    result = match_advisories(
        load_inventory(inventory_path),
        load_advisory_database(ROOT / "examples" / "advisories.example.json"),
    )
    assert result["match_count"] == 0


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source_url", "http://example.invalid/advisory", "HTTPS"),
        ("cves", ["CVE-2026-12"], "invalid CVE"),
        ("severity", "urgent", "severity"),
    ],
)
def test_advisory_rejects_invalid_fields(tmp_path: Path, field: str, value, message: str) -> None:
    data = json.loads((ROOT / "examples" / "advisories.example.json").read_text())
    data["advisories"][0][field] = value
    path = tmp_path / "invalid-advisories.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_advisory_database(path)


def test_advisory_rejects_duplicate_ids_and_oversized_file(tmp_path: Path) -> None:
    data = json.loads((ROOT / "examples" / "advisories.example.json").read_text())
    data["advisories"].append(dict(data["advisories"][0]))
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate advisory_id"):
        load_advisory_database(path)


def test_missing_identity_is_reported_without_guessing(tmp_path: Path) -> None:
    inventory_data = json.loads((ROOT / "examples" / "asset_inventory.example.json").read_text())
    inventory_data["assets"][0]["firmware"] = ""
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(inventory_data), encoding="utf-8")
    result = match_advisories(
        load_inventory(inventory_path),
        load_advisory_database(ROOT / "examples" / "advisories.example.json"),
    )
    assert result["match_count"] == 0
    assert result["assets_missing_identity"][0]["reason"] == "vendor_model_or_firmware_missing"


def test_advisory_rejects_https_userinfo(tmp_path: Path) -> None:
    data = json.loads((ROOT / "examples" / "advisories.example.json").read_text())
    data["advisories"][0]["source_url"] = "https://user:password@example.invalid/advisory"
    path = tmp_path / "userinfo.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="without userinfo"):
        load_advisory_database(path)


def test_advisory_rejects_non_string_and_unknown_fields(tmp_path: Path) -> None:
    data = json.loads((ROOT / "examples" / "advisories.example.json").read_text())
    data["advisories"][0]["title"] = 123
    path = tmp_path / "wrong-type.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="identity fields must be strings"):
        load_advisory_database(path)

    data = json.loads((ROOT / "examples" / "advisories.example.json").read_text())
    data["advisories"][0]["unrecognized"] = "do not silently ignore"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        load_advisory_database(path)


def test_advisory_requires_iso_date_and_unique_casefolded_ids(tmp_path: Path) -> None:
    data = json.loads((ROOT / "examples" / "advisories.example.json").read_text())
    data["advisories"][0]["published"] = "20261101"
    path = tmp_path / "bad-date.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        load_advisory_database(path)

    data = json.loads((ROOT / "examples" / "advisories.example.json").read_text())
    duplicate = dict(data["advisories"][0])
    duplicate["advisory_id"] = duplicate["advisory_id"].lower()
    data["advisories"].append(duplicate)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate advisory_id"):
        load_advisory_database(path)


def test_advisory_database_size_limit_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import plcsec.advisories as advisory_module

    path = tmp_path / "oversized.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(advisory_module, "MAX_ADVISORY_FILE_BYTES", 1)
    with pytest.raises(ValueError, match="exceeds configured limit"):
        load_advisory_database(path)
