from __future__ import annotations

import json
from pathlib import Path

import pytest

from plcsec.cli import main


def test_vendor_database_cli_exports_json(tmp_path: Path) -> None:
    output = tmp_path / "vendor-db.json"
    assert main(["vendors", "database", "--format", "json", "--out", str(output)]) == 0
    data = json.loads(output.read_text())
    assert data["schema"] == "plcsec.vendor-profiles.v1"


def test_report_signing_cli_roundtrip(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    report, signature = tmp_path / "report.json", tmp_path / "report.sig.json"
    report.write_text('{"schema":"plcsec.report.v2","findings":[]}')
    assert main(["baseline", "keygen", "--private-key", str(private), "--public-key", str(public)]) == 0
    assert main(["report", "sign", "--input", str(report), "--private-key", str(private), "--signature", str(signature)]) == 0
    assert main(["report", "verify", "--input", str(report), "--public-key", str(public), "--signature", str(signature)]) == 0


def test_baseline_approval_cli_roundtrip(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    baseline, approval, signature = tmp_path / "baseline.json", tmp_path / "approval.json", tmp_path / "approval.sig.json"
    baseline.write_text(json.dumps({"schema": "plcsec.baseline.v1", "site_id": "lab", "assets": {}}))
    assert main(["baseline", "keygen", "--private-key", str(private), "--public-key", str(public)]) == 0
    assert main(["baseline", "approve", "--input", str(baseline), "--approved-by", "Lab owner", "--reason", "Approved lab baseline", "--private-key", str(private), "--out", str(approval), "--signature", str(signature)]) == 0
    assert main(["baseline", "verify-approval", "--input", str(baseline), "--approval", str(approval), "--signature", str(signature), "--public-key", str(public)]) == 0
