import json

from plcsec.cli import main


def test_inventory_validate_cli(tmp_path, capsys):
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps({
        "schema": "plcsec.asset-inventory.v1",
        "site_id": "test-site",
        "assets": [{"asset_id": "PLC-1", "ip": "192.0.2.1"}],
    }), encoding="utf-8")
    assert main(["inventory", "validate", "--input", str(path)]) == 0
    assert '"site_id": "test-site"' in capsys.readouterr().out
