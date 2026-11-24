from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
from plcsec.approvals import create_baseline_approval, verify_baseline_approval
from plcsec.artifact_signing import ArtifactSignatureError, sign_artifact, verify_artifact
from plcsec.signing import generate_ed25519_keypair


def test_signed_report_roundtrip_and_tamper_detection(tmp_path: Path) -> None:
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    report, signature = tmp_path / "assessment.json", tmp_path / "assessment.sig.json"
    report.write_text('{"assessment":"lab","findings":[] }\n')
    generate_ed25519_keypair(private, public)
    sign_artifact(report, private, signature, artifact_type="assessment-report")
    verified = verify_artifact(report, public, signature, expected_type="assessment-report")
    assert verified["valid"] is True
    report.write_text('{"assessment":"changed","findings":[] }\n')
    with pytest.raises(ArtifactSignatureError, match="hash or size"):
        verify_artifact(report, public, signature, expected_type="assessment-report")


def test_baseline_approval_is_bound_to_baseline_and_signer(tmp_path: Path) -> None:
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    baseline, approval, signature = tmp_path / "baseline.json", tmp_path / "approval.json", tmp_path / "approval.sig.json"
    baseline.write_text(json.dumps({"schema": "plcsec.baseline.v1", "site_id": "line-a", "created_at": "2026-01-01T00:00:00Z", "assets": {}}))
    generate_ed25519_keypair(private, public)
    create_baseline_approval(baseline, approved_by="OT Security Lead", reason="Reviewed at change board", private_key_path=private, output_path=approval, signature_path=signature)
    result = verify_baseline_approval(baseline, approval, signature, public)
    assert result["valid"] is True
    assert result["authority_verified"] is False
    baseline.write_text(json.dumps({"schema": "plcsec.baseline.v1", "site_id": "line-b", "assets": {}}))
    with pytest.raises(ValueError, match="different baseline"):
        verify_baseline_approval(baseline, approval, signature, public)
