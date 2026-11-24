from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from plcsec.artifact_signing import sign_artifact, verify_artifact
from plcsec.baseline import load_baseline_bytes, MAX_BASELINE_BYTES
from plcsec.safeio import read_stable_bytes


def create_baseline_approval(
    baseline_path: str | Path,
    *,
    approved_by: str,
    reason: str,
    private_key_path: str | Path,
    output_path: str | Path,
    signature_path: str | Path,
) -> dict[str, Any]:
    if not approved_by.strip() or len(approved_by) > 200:
        raise ValueError("approved_by must be 1..200 characters")
    if not reason.strip() or len(reason) > 2000:
        raise ValueError("reason must be 1..2000 characters")
    baseline_file = Path(baseline_path)
    output_file = Path(output_path)
    signature_file = Path(signature_path)
    if output_file.resolve() in {baseline_file.resolve(), Path(private_key_path).resolve()} or signature_file.resolve() in {baseline_file.resolve(), Path(private_key_path).resolve(), output_file.resolve()}:
        raise ValueError("Approval and signature outputs must not overwrite the baseline, private key, or each other")
    raw = read_stable_bytes(baseline_file, max_bytes=MAX_BASELINE_BYTES, label="Baseline")
    baseline = load_baseline_bytes(raw, source_label=str(baseline_file))
    approval = {
        "schema": "plcsec.baseline-approval.v1",
        "baseline_sha256": hashlib.sha256(raw).hexdigest(),
        "site_id": baseline.get("site_id"),
        "baseline_created_at": baseline.get("created_at"),
        "approved_by": approved_by.strip(),
        "reason": reason.strip(),
        "approved_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "approval_semantics": "This is an attestation by the named approver; PLCSEC does not verify the person's organizational authority.",
    }
    output = output_file
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(approval, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    signature = sign_artifact(output, private_key_path, signature_path, artifact_type="baseline-approval")
    return {"approval": str(output), "signature": str(signature_path), "baseline_sha256": approval["baseline_sha256"], "public_key_sha256": signature["public_key_sha256"]}


def verify_baseline_approval(
    baseline_path: str | Path,
    approval_path: str | Path,
    signature_path: str | Path,
    public_key_path: str | Path,
) -> dict[str, Any]:
    baseline_file = Path(baseline_path)
    approval_file = Path(approval_path)
    raw = read_stable_bytes(baseline_file, max_bytes=MAX_BASELINE_BYTES, label="Baseline")
    baseline = load_baseline_bytes(raw, source_label=str(baseline_file))
    approval_raw = read_stable_bytes(approval_file, max_bytes=64 * 1024, label="Approval record")
    approval = json.loads(approval_raw)
    if not isinstance(approval, dict) or approval.get("schema") != "plcsec.baseline-approval.v1":
        raise ValueError("Unsupported baseline approval schema")
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != approval.get("baseline_sha256"):
        raise ValueError("Approval is bound to a different baseline file")
    if approval.get("site_id") != baseline.get("site_id"):
        raise ValueError("Approval site_id does not match baseline")
    signature_result = verify_artifact(approval_file, public_key_path, signature_path, expected_type="baseline-approval")
    return {"valid": True, "site_id": baseline.get("site_id"), "approved_by": approval.get("approved_by"), "approved_at": approval.get("approved_at"), "baseline_sha256": actual_hash, "signature": signature_result, "authority_verified": False}
