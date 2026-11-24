from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from plcsec.safeio import read_stable_bytes
from typing import Any

MAX_SIGNED_FILE_BYTES = 32 * 1024 * 1024
_CONTEXT = b"PLCSEC-BASELINE-ED25519-V1\x00"


class SignatureError(ValueError):
    pass


def _crypto() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise RuntimeError("Ed25519 baseline signing requires cryptography. Install with: pip install 'plcsec[crypto]'") from exc
    return serialization, Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def _atomic_write(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def generate_ed25519_keypair(private_path: str | Path, public_path: str | Path, *, force: bool = False) -> dict[str, str]:
    serialization, PrivateKey, _, _ = _crypto()
    private_file, public_file = Path(private_path), Path(public_path)
    if private_file.resolve() == public_file.resolve():
        raise ValueError("Private-key and public-key paths must be different")
    if private_file.exists() or public_file.exists():
        if not force:
            raise FileExistsError("Key file already exists; pass --force only after making a secure backup")
    private_key = PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Private key is deliberately owner-readable only.
    _atomic_write(private_file, private_bytes, 0o600)
    _atomic_write(public_file, public_bytes, 0o644)
    fingerprint = hashlib.sha256(public_bytes).hexdigest()
    return {"private_key": str(private_file), "public_key": str(public_file), "public_key_sha256": fingerprint}


def sign_baseline(input_path: str | Path, private_key_path: str | Path, signature_path: str | Path) -> dict[str, Any]:
    serialization, _, _, _ = _crypto()
    source = Path(input_path)
    key_path = Path(private_key_path)
    output = Path(signature_path)
    if output.resolve() in {source.resolve(), key_path.resolve()}:
        raise ValueError("Signature output path must not overwrite the baseline or private key")
    payload = read_stable_bytes(source, max_bytes=MAX_SIGNED_FILE_BYTES, label="Baseline")
    try:
        private_key_bytes = read_stable_bytes(key_path, max_bytes=64 * 1024, label="Private key")
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    except (ValueError, TypeError) as exc:
        raise SignatureError("Private key is not a valid unencrypted PEM key") from exc
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SignatureError("Only Ed25519 private keys are accepted")
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload_hash = hashlib.sha256(payload).hexdigest()
    public_hash = hashlib.sha256(public_bytes).hexdigest()
    message = _CONTEXT + bytes.fromhex(payload_hash) + bytes.fromhex(public_hash)
    signature = private_key.sign(message)
    record = {
        "schema": "plcsec.detached-signature.v1",
        "algorithm": "Ed25519",
        "payload_sha256": payload_hash,
        "public_key_sha256": public_hash,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(output, encoded, 0o644)
    return record


def verify_baseline(input_path: str | Path, public_key_path: str | Path, signature_path: str | Path) -> dict[str, Any]:
    serialization, _, PublicKey, InvalidSignature = _crypto()
    payload_path, key_path, sig_path = Path(input_path), Path(public_key_path), Path(signature_path)
    payload = read_stable_bytes(payload_path, max_bytes=MAX_SIGNED_FILE_BYTES, label="Baseline")
    try:
        record_bytes = read_stable_bytes(sig_path, max_bytes=64 * 1024, label="Signature sidecar")
        record = json.loads(record_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SignatureError("Signature sidecar is not valid JSON") from exc
    if not isinstance(record, dict):
        raise SignatureError("Signature sidecar must be a JSON object")
    if record.get("schema") != "plcsec.detached-signature.v1" or record.get("algorithm") != "Ed25519":
        raise SignatureError("Unsupported signature schema or algorithm")
    try:
        public_key_bytes = read_stable_bytes(key_path, max_bytes=64 * 1024, label="Public key")
        public_key = serialization.load_pem_public_key(public_key_bytes)
    except ValueError as exc:
        raise SignatureError("Public key is not valid PEM") from exc
    if not isinstance(public_key, PublicKey):
        raise SignatureError("Only Ed25519 public keys are accepted")
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload_hash = hashlib.sha256(payload).hexdigest()
    public_hash = hashlib.sha256(public_bytes).hexdigest()
    if payload_hash != record.get("payload_sha256"):
        raise SignatureError("Payload SHA-256 does not match signature sidecar")
    if public_hash != record.get("public_key_sha256"):
        raise SignatureError("Public key fingerprint does not match signature sidecar")
    try:
        signature = base64.b64decode(record["signature_base64"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        raise SignatureError("Signature field is missing or malformed") from exc
    message = _CONTEXT + bytes.fromhex(payload_hash) + bytes.fromhex(public_hash)
    if len(signature) != 64:
        raise SignatureError("Ed25519 signature must be exactly 64 bytes")
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise SignatureError("Ed25519 signature verification failed") from exc
    return {
        "valid": True,
        "algorithm": "Ed25519",
        "payload_sha256": payload_hash,
        "public_key_sha256": public_hash,
        "created_at": record.get("created_at"),
    }
