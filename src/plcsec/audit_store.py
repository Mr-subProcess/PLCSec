from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from plcsec.safeio import read_stable_bytes

SCHEMA_VERSION = "1"
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
ZERO_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _connect(path: str | Path) -> sqlite3.Connection:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA synchronous=FULL")
    return connection


def initialize_audit_store(path: str | Path) -> dict[str, Any]:
    connection = _connect(path)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("""CREATE TABLE IF NOT EXISTS audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE
        )""")
        connection.execute("CREATE TABLE IF NOT EXISTS audit_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT OR IGNORE INTO audit_meta(key,value) VALUES('schema_version',?)", (SCHEMA_VERSION,))
        version = connection.execute("SELECT value FROM audit_meta WHERE key='schema_version'").fetchone()[0]
        if version != SCHEMA_VERSION:
            raise ValueError(f"Unsupported audit store schema version: {version}")
        connection.commit()
    finally:
        connection.close()
    return {"database": str(path), "schema_version": SCHEMA_VERSION, "initialized": True}


def _event_hash(sequence: int, timestamp: str, actor: str, event_type: str,
                payload_json: str, previous_hash: str) -> str:
    material = {
        "domain": "PLCSEC-AUDIT-CHAIN-v1",
        "sequence": sequence,
        "timestamp": timestamp,
        "actor": actor,
        "event_type": event_type,
        "payload_json": payload_json,
        "previous_hash": previous_hash,
    }
    return hashlib.sha256(_canonical(material)).hexdigest()


def append_event(path: str | Path, *, actor: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not actor.strip() or len(actor) > 256 or not event_type.strip() or len(event_type) > 256:
        raise ValueError("actor and event_type must be non-empty and at most 256 characters")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    payload_json = _canonical(payload).decode("utf-8")
    if len(payload_json.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise ValueError("Audit event payload exceeds 1 MiB")
    initialize_audit_store(path)
    connection = _connect(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT sequence,event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
        previous_hash = row[1] if row else ZERO_HASH
        sequence = (row[0] + 1) if row else 1
        timestamp = _utc_now()
        event_hash = _event_hash(sequence, timestamp, actor, event_type, payload_json, previous_hash)
        connection.execute(
            "INSERT INTO audit_events(sequence,timestamp,actor,event_type,payload_json,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
            (sequence, timestamp, actor, event_type, payload_json, previous_hash, event_hash),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {"sequence": sequence, "timestamp": timestamp, "event_hash": event_hash, "previous_hash": previous_hash}


def record_report(path: str | Path, report_path: str | Path, *, actor: str) -> dict[str, Any]:
    source = Path(report_path)
    if not source.is_file() or source.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Report is missing or exceeds 64 MiB")
    before = source.stat()
    raw = source.read_bytes()
    after = source.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("Report changed while being read")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Assessment report must be a JSON object")
    payload = {
        "report_path_name": source.name,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "assessment_type": str(data.get("assessment_type", "unknown"))[:256],
        "tool_version": str(data.get("tool_version", "unknown"))[:64],
        "asset_count": len(data.get("assets", [])) if isinstance(data.get("assets"), list) else 0,
        "finding_count": len(data.get("findings", [])) if isinstance(data.get("findings"), list) else 0,
        "event_count": len(data.get("events", [])) if isinstance(data.get("events"), list) else 0,
    }
    return append_event(path, actor=actor, event_type="assessment.report.recorded", payload=payload)


def verify_audit_store(path: str | Path, *, through_sequence: int | None = None) -> dict[str, Any]:
    db_path = Path(path)
    if through_sequence is not None and through_sequence < 0:
        raise ValueError("through_sequence must be non-negative")
    if not db_path.is_file():
        raise FileNotFoundError(db_path)
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    checked = 0
    previous = ZERO_HASH
    try:
        if through_sequence is None:
            cursor = connection.execute(
                "SELECT sequence,timestamp,actor,event_type,payload_json,previous_hash,event_hash FROM audit_events ORDER BY sequence"
            )
        else:
            cursor = connection.execute(
                "SELECT sequence,timestamp,actor,event_type,payload_json,previous_hash,event_hash FROM audit_events WHERE sequence<=? ORDER BY sequence",
                (through_sequence,),
            )
        for expected_sequence, row in enumerate(cursor, start=1):
            sequence, timestamp, actor, event_type, payload_json, stored_previous, stored_hash = row
            if sequence != expected_sequence:
                return {"valid": False, "checked_events": checked, "error": "sequence_gap", "sequence": sequence}
            if stored_previous != previous:
                return {"valid": False, "checked_events": checked, "error": "previous_hash_mismatch", "sequence": sequence}
            try:
                payload = json.loads(payload_json)
                if not isinstance(payload, dict):
                    raise ValueError("payload is not an object")
            except (json.JSONDecodeError, ValueError):
                return {"valid": False, "checked_events": checked, "error": "invalid_payload_json", "sequence": sequence}
            expected_hash = _event_hash(sequence, timestamp, actor, event_type, payload_json, stored_previous)
            if not hmac.compare_digest(expected_hash, stored_hash):
                return {"valid": False, "checked_events": checked, "error": "event_hash_mismatch", "sequence": sequence}
            previous = stored_hash
            checked += 1
    finally:
        connection.close()
    return {"valid": True, "checked_events": checked, "head_hash": previous, "schema_version": SCHEMA_VERSION}


def export_jsonl(path: str | Path, output_path: str | Path) -> dict[str, Any]:
    db_path = Path(path)
    if not db_path.is_file():
        raise FileNotFoundError(db_path)
    target = Path(output_path)
    if target.resolve() == db_path.resolve():
        raise ValueError("JSONL output must not overwrite the audit database")
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    exported = 0
    previous = ZERO_HASH
    try:
        connection.execute("BEGIN")
        cursor = connection.execute(
            "SELECT sequence,timestamp,actor,event_type,payload_json,previous_hash,event_hash FROM audit_events ORDER BY sequence"
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            for expected_sequence, row in enumerate(cursor, start=1):
                sequence, timestamp, actor, event_type, payload_json, stored_previous, stored_hash = row
                if sequence != expected_sequence or stored_previous != previous:
                    raise ValueError(f"Audit chain sequence/link failure at event {sequence}")
                try:
                    payload = json.loads(payload_json)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid payload JSON at audit event {sequence}") from exc
                if not isinstance(payload, dict):
                    raise ValueError(f"Audit event {sequence} payload is not an object")
                expected_hash = _event_hash(sequence, timestamp, actor, event_type, payload_json, stored_previous)
                if not hmac.compare_digest(expected_hash, stored_hash):
                    raise ValueError(f"Audit event hash mismatch at sequence {sequence}")
                stream.write(json.dumps({
                    "sequence": sequence, "timestamp": timestamp, "actor": actor,
                    "event_type": event_type, "payload": payload,
                    "previous_hash": stored_previous, "event_hash": stored_hash,
                }, ensure_ascii=False, sort_keys=True) + "\n")
                previous = stored_hash
                exported += 1
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    finally:
        connection.close()
    return {"output": str(target), "exported_events": exported, "chain_verified": True, "head_hash": previous}


def create_checkpoint(path: str | Path, output_path: str | Path) -> dict[str, Any]:
    verification = verify_audit_store(path)
    if not verification["valid"]:
        raise ValueError(f"Cannot checkpoint an invalid audit store: {verification}")
    target = Path(output_path)
    if target.resolve() == Path(path).resolve():
        raise ValueError("Checkpoint output must not overwrite the audit database")
    checkpoint = {
        "schema": "plcsec.audit-checkpoint.v1",
        "created_at": _utc_now(),
        "schema_version": SCHEMA_VERSION,
        "hash_algorithm": "SHA-256",
        "chain_domain": "PLCSEC-AUDIT-CHAIN-v1",
        "event_count": verification["checked_events"],
        "head_hash": verification["head_hash"],
        "assurance_note": "A signed external checkpoint detects later database rewrites that do not match this checkpoint. The local hash chain alone is not tamper-proof.",
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(checkpoint, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return {"output": str(target), "event_count": checkpoint["event_count"], "head_hash": checkpoint["head_hash"]}


def sign_checkpoint(path: str | Path, output_path: str | Path,
                    private_key_path: str | Path, signature_path: str | Path) -> dict[str, Any]:
    resolved_paths = {
        Path(path).resolve(), Path(output_path).resolve(),
        Path(private_key_path).resolve(), Path(signature_path).resolve(),
    }
    if len(resolved_paths) != 4:
        raise ValueError("Database, checkpoint, private key and signature paths must all be distinct")
    create_result = create_checkpoint(path, output_path)
    from plcsec.artifact_signing import sign_artifact
    signature = sign_artifact(output_path, private_key_path, signature_path, artifact_type="audit-log-checkpoint")
    return {**create_result, "signature": str(signature_path), "signature_valid_at_creation": bool(signature.get("payload_sha256"))}


def verify_checkpoint(path: str | Path, checkpoint_path: str | Path,
                      public_key_path: str | Path, signature_path: str | Path) -> dict[str, Any]:
    from plcsec.artifact_signing import verify_artifact
    signature_result = verify_artifact(
        checkpoint_path, public_key_path, signature_path, expected_type="audit-log-checkpoint"
    )
    checkpoint_file = Path(checkpoint_path)
    checkpoint_bytes = read_stable_bytes(checkpoint_file, max_bytes=64 * 1024, label="Audit checkpoint")
    if hashlib.sha256(checkpoint_bytes).hexdigest() != signature_result.get("payload_sha256"):
        raise ValueError("Checkpoint changed between signature verification and parsing")
    checkpoint = json.loads(checkpoint_bytes)
    if not isinstance(checkpoint, dict) or checkpoint.get("schema") != "plcsec.audit-checkpoint.v1":
        raise ValueError("Unsupported audit checkpoint schema")
    current = verify_audit_store(path)
    if not current["valid"]:
        return {"valid": False, "reason": "audit_chain_invalid", "chain": current, "signature": signature_result}
    checkpoint_count = checkpoint.get("event_count")
    if not isinstance(checkpoint_count, int) or checkpoint_count < 0:
        raise ValueError("Checkpoint event_count is malformed")
    if current["checked_events"] < checkpoint_count:
        return {"valid": False, "reason": "database_is_older_than_checkpoint", "signature": signature_result}
    prefix = verify_audit_store(path, through_sequence=checkpoint_count)
    matches = (
        prefix["valid"]
        and checkpoint.get("schema_version") == SCHEMA_VERSION
        and checkpoint.get("hash_algorithm") == "SHA-256"
        and checkpoint.get("chain_domain") == "PLCSEC-AUDIT-CHAIN-v1"
        and checkpoint.get("head_hash") == prefix["head_hash"]
    )
    return {
        "valid": bool(matches),
        "reason": "checkpoint_prefix_matches" if matches else "checkpoint_does_not_match_chain_prefix",
        "checkpoint_event_count": checkpoint_count,
        "current_event_count": current["checked_events"],
        "later_events": current["checked_events"] - checkpoint_count,
        "checkpoint_head_hash": checkpoint.get("head_hash"),
        "signature": signature_result,
    }

