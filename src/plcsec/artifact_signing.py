from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from plcsec.safeio import read_stable_bytes

MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_SIGNATURE_SIDECAR_BYTES = 64 * 1024
_CONTEXT = b"PLCSEC-ARTIFACT-SIGNATURE-V1\x00"


class ArtifactSignatureError(ValueError):
    pass


def _crypto() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise RuntimeError("Artifact signing requires cryptography. Install: pip install 'plcsec[crypto]'") from exc
    return serialization, Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def _payload(path: str | Path) -> bytes:
    return read_stable_bytes(path, max_bytes=MAX_ARTIFACT_BYTES, label="Artifact")


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def sign_artifact(
    input_path: str | Path,
    private_key_path: str | Path,
    signature_path: str | Path,
    *,
    artifact_type: str,
) -> dict[str, Any]:
    if not artifact_type or len(artifact_type) > 64 or not artifact_type.replace("-", "").replace("_", "").isalnum():
        raise ValueError("artifact_type must be a short alphanumeric identifier")
    serialization, PrivateKey, _, _ = _crypto()
    source_path = Path(input_path)
    private_path = Path(private_key_path)
    output_path = Path(signature_path)
    if output_path.resolve() in {source_path.resolve(), private_path.resolve()}:
        raise ValueError("Signature output path must be different from the input artifact and private key")
    payload = _payload(source_path)
    try:
        private_key_bytes = read_stable_bytes(private_key_path, max_bytes=MAX_KEY_BYTES, label="Private key")
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    except (ValueError, TypeError) as exc:
        raise ArtifactSignatureError("Private key is not a valid unencrypted PEM key") from exc
    if not isinstance(private_key, PrivateKey):
        raise ArtifactSignatureError("Only Ed25519 private keys are accepted")
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload_hash = hashlib.sha256(payload).hexdigest()
    public_hash = hashlib.sha256(public_bytes).hexdigest()
    message = _CONTEXT + artifact_type.encode("ascii") + b"\x00" + bytes.fromhex(payload_hash) + bytes.fromhex(public_hash)
    signature = private_key.sign(message)
    record = {
        "schema": "plcsec.artifact-signature.v1",
        "artifact_type": artifact_type,
        "payload_sha256": payload_hash,
        "payload_size_bytes": len(payload),
        "public_key_sha256": public_hash,
        "algorithm": "Ed25519",
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    output = output_path
    encoded_record = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(output, encoded_record)
    return record


def verify_artifact(
    input_path: str | Path,
    public_key_path: str | Path,
    signature_path: str | Path,
    *,
    expected_type: str | None = None,
) -> dict[str, Any]:
    serialization, _, PublicKey, InvalidSignature = _crypto()
    payload = _payload(input_path)
    try:
        sidecar_bytes = read_stable_bytes(signature_path, max_bytes=MAX_SIGNATURE_SIDECAR_BYTES, label="Signature sidecar")
        record = json.loads(sidecar_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ArtifactSignatureError("Signature sidecar is not valid JSON") from exc
    if not isinstance(record, dict) or record.get("schema") != "plcsec.artifact-signature.v1" or record.get("algorithm") != "Ed25519":
        raise ArtifactSignatureError("Unsupported artifact signature schema or algorithm")
    artifact_type = record.get("artifact_type")
    if not isinstance(artifact_type, str) or not artifact_type or len(artifact_type) > 64 or not artifact_type.isascii():
        raise ArtifactSignatureError("Artifact type is missing or malformed")
    if expected_type and artifact_type != expected_type:
        raise ArtifactSignatureError("Artifact type does not match the expected type")
    try:
        public_key_bytes = read_stable_bytes(public_key_path, max_bytes=MAX_KEY_BYTES, label="Public key")
        public_key = serialization.load_pem_public_key(public_key_bytes)
    except ValueError as exc:
        raise ArtifactSignatureError("Public key is not valid PEM") from exc
    if not isinstance(public_key, PublicKey):
        raise ArtifactSignatureError("Only Ed25519 public keys are accepted")
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload_hash = hashlib.sha256(payload).hexdigest()
    public_hash = hashlib.sha256(public_bytes).hexdigest()
    if payload_hash != record.get("payload_sha256") or len(payload) != record.get("payload_size_bytes"):
        raise ArtifactSignatureError("Artifact hash or size does not match signature sidecar")
    if public_hash != record.get("public_key_sha256"):
        raise ArtifactSignatureError("Public-key fingerprint does not match signature sidecar")
    try:
        signature = base64.b64decode(record["signature_base64"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        raise ArtifactSignatureError("Signature field is missing or malformed") from exc
    if len(signature) != 64:
        raise ArtifactSignatureError("Ed25519 signature must be exactly 64 bytes")
    message = _CONTEXT + artifact_type.encode("ascii") + b"\x00" + bytes.fromhex(payload_hash) + bytes.fromhex(public_hash)
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise ArtifactSignatureError("Ed25519 artifact signature verification failed") from exc
    return {"valid": True, "artifact_type": artifact_type, "payload_sha256": payload_hash, "public_key_sha256": public_hash, "created_at": record.get("created_at")}
