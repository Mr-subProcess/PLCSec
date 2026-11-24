import json
from pathlib import Path

from plcsec.cli import main


def test_export_stix_and_cef_cli(tmp_path: Path) -> None:
    source = tmp_path / "report.json"
    source.write_text(json.dumps({
        "tool_version": "0.6.0", "assessment_type": "test",
        "assets": [{"ip": "192.0.2.5", "packets_seen": 2}],
        "flows": [],
        "findings": [{"finding_id": "F-1", "title": "Observed service", "severity": "low", "description": "Review", "evidence": {"ip": "192.0.2.5"}}],
    }), encoding="utf-8")
    stix_out = tmp_path / "out.stix.json"
    cef_out = tmp_path / "out.cef"
    assert main(["export", "stix", "--input", str(source), "--out", str(stix_out)]) == 0
    assert main(["export", "cef", "--input", str(source), "--out", str(cef_out)]) == 0
    assert json.loads(stix_out.read_text(encoding="utf-8"))["type"] == "bundle"
    assert cef_out.read_text(encoding="utf-8").startswith("CEF:0|")


def test_audit_log_cli_lifecycle(tmp_path: Path) -> None:
    db = tmp_path / "audit.sqlite"
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"assessment_type": "test", "assets": [], "findings": []}), encoding="utf-8")
    output = tmp_path / "audit.jsonl"
    assert main(["audit-log", "init", "--db", str(db)]) == 0
    assert main(["audit-log", "record-report", "--db", str(db), "--input", str(report), "--actor", "qa-user"]) == 0
    assert main(["audit-log", "verify", "--db", str(db)]) == 0
    assert main(["audit-log", "export", "--db", str(db), "--out", str(output)]) == 0
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1


def test_audit_log_signed_checkpoint_cli(tmp_path: Path) -> None:
    db = tmp_path / "audit.sqlite"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    checkpoint = tmp_path / "checkpoint.json"
    signature = tmp_path / "checkpoint.sig.json"
    from plcsec.signing import generate_ed25519_keypair
    generate_ed25519_keypair(private_key, public_key)
    assert main(["audit-log", "init", "--db", str(db)]) == 0
    assert main(["audit-log", "checkpoint-sign", "--db", str(db), "--out", str(checkpoint), "--private-key", str(private_key), "--signature", str(signature)]) == 0
    assert main(["audit-log", "checkpoint-verify", "--db", str(db), "--checkpoint", str(checkpoint), "--public-key", str(public_key), "--signature", str(signature)]) == 0
