import json

from plcsec.cli import main


def test_site_profile_validate_cli(tmp_path, capsys):
    profile = tmp_path / "site.json"
    profile.write_text(json.dumps({
        "schema": "plcsec.site-profile.v1",
        "site_id": "test",
        "zones": [{"name": "control", "cidrs": ["192.0.2.0/24"]}],
        "approved_conduits": [],
    }), encoding="utf-8")
    assert main(["site-profile", "validate", "--input", str(profile)]) == 0
    assert '"site_id": "test"' in capsys.readouterr().out
