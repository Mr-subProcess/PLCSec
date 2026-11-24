from __future__ import annotations

import json
from pathlib import Path

from plcsec.cli import main


def test_firmware_cli_writes_json(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    output = tmp_path / "out" / "firmware.json"
    source.write_bytes(b"\x7fELF" + b"S7-1500 firmware version 1.2.3" + b"\x00" * 40)
    assert main(["firmware", "analyze", "--input", str(source), "--out", str(output)]) == 0
    result = json.loads(output.read_text())
    assert result["analysis_safety"]["executed"] is False


def test_baseline_keygen_sign_verify_cli(tmp_path: Path) -> None:
    private = tmp_path / "priv.pem"
    public = tmp_path / "pub.pem"
    source = tmp_path / "baseline.json"
    signature = tmp_path / "baseline.sig.json"
    source.write_text('{"schema":"plcsec.baseline.v1","site_id":"lab","assets":{}}\n')
    assert main(["baseline", "keygen", "--private-key", str(private), "--public-key", str(public)]) == 0
    assert main(["baseline", "sign", "--input", str(source), "--private-key", str(private), "--signature", str(signature)]) == 0
    assert main(["baseline", "verify", "--input", str(source), "--public-key", str(public), "--signature", str(signature)]) == 0


def test_vendor_and_compliance_cli(tmp_path: Path) -> None:
    source = tmp_path / "report.json"
    source.write_text(json.dumps({
        "schema_version": "plcsec.report.v2", "tool_version": "0.4.0",
        "assets": [{"ip": "192.0.2.5", "inventory_metadata": {"vendor": "Rockwell", "model": "ControlLogix"}}],
        "events": [], "findings": [{"finding_id": "F1", "title": "New asset", "severity": "medium", "tags": ["asset-inventory"]}],
    }))
    vendor_out, compliance_out = tmp_path / "vendor.json", tmp_path / "compliance.json"
    assert main(["vendors", "enrich", "--input", str(source), "--out", str(vendor_out)]) == 0
    assert "Rockwell Automation" in vendor_out.read_text()
    assert main(["compliance", "crosswalk", "--input", str(source), "--out", str(compliance_out)]) == 0
    assert json.loads(compliance_out.read_text())["is_certification"] is False
