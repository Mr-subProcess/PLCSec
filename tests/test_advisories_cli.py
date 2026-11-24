from __future__ import annotations

import json
from pathlib import Path

from plcsec.cli import main

ROOT = Path(__file__).parents[1]


def test_advisory_validate_cli(capsys) -> None:
    source = ROOT / "examples" / "advisories.example.json"
    assert main(["advisories", "validate", "--input", str(source)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["advisory_count"] == 1


def test_advisory_match_cli(tmp_path: Path, capsys) -> None:
    inventory = ROOT / "examples" / "asset_inventory.example.json"
    database = ROOT / "examples" / "advisories.example.json"
    output = tmp_path / "matches.json"
    assert main([
        "advisories", "match", "--inventory", str(inventory),
        "--database", str(database), "--out", str(output),
    ]) == 0
    summary = json.loads(capsys.readouterr().out)
    data = json.loads(output.read_text(encoding="utf-8"))
    assert summary["match_count"] == 1
    assert data["is_vendor_applicability_confirmed"] is False
