import json
import sqlite3

from plcsec.audit_store import append_event, export_jsonl, initialize_audit_store, record_report, verify_audit_store


def test_initialize_and_append_and_verify(tmp_path) -> None:
    db = tmp_path / "evidence" / "audit.sqlite"
    assert initialize_audit_store(db)["initialized"] is True
    first = append_event(db, actor="tester", event_type="test.one", payload={"value": 1})
    second = append_event(db, actor="tester", event_type="test.two", payload={"value": 2})
    assert first["sequence"] == 1
    assert second["sequence"] == 2
    assert second["previous_hash"] == first["event_hash"]
    result = verify_audit_store(db)
    assert result["valid"] is True
    assert result["checked_events"] == 2


def test_detect_payload_tampering(tmp_path) -> None:
    db = tmp_path / "audit.sqlite"
    append_event(db, actor="tester", event_type="sample", payload={"approved": True})
    connection = sqlite3.connect(db)
    try:
        connection.execute("UPDATE audit_events SET payload_json=? WHERE sequence=1", (json.dumps({"approved": False}),))
        connection.commit()
    finally:
        connection.close()
    result = verify_audit_store(db)
    assert result["valid"] is False
    assert result["error"] == "event_hash_mismatch"


def test_record_report_stores_hash_not_report_body(tmp_path) -> None:
    db = tmp_path / "audit.sqlite"
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"assessment_type": "passive", "assets": [{"ip": "192.0.2.1"}], "findings": []}), encoding="utf-8")
    result = record_report(db, report, actor="analyst")
    assert result["sequence"] == 1
    connection = sqlite3.connect(db)
    try:
        payload = json.loads(connection.execute("SELECT payload_json FROM audit_events").fetchone()[0])
    finally:
        connection.close()
    assert "report_sha256" in payload
    assert "192.0.2.1" not in json.dumps(payload)


def test_export_jsonl_requires_valid_chain(tmp_path) -> None:
    db = tmp_path / "audit.sqlite"
    output = tmp_path / "events.jsonl"
    append_event(db, actor="analyst", event_type="sample", payload={"n": 3})
    result = export_jsonl(db, output)
    assert result["chain_verified"] is True
    data = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert data["event_type"] == "sample"


def test_reject_oversized_audit_payload(tmp_path) -> None:
    db = tmp_path / "audit.sqlite"
    try:
        append_event(db, actor="analyst", event_type="oversized", payload={"blob": "x" * (1024 * 1024 + 10)})
    except ValueError as exc:
        assert "1 MiB" in str(exc)
    else:
        raise AssertionError("oversized event accepted")


def test_signed_checkpoint_detects_database_rewrite(tmp_path) -> None:
    from plcsec.audit_store import sign_checkpoint, verify_checkpoint
    from plcsec.signing import generate_ed25519_keypair

    db = tmp_path / "audit.sqlite"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    checkpoint = tmp_path / "checkpoint.json"
    signature = tmp_path / "checkpoint.sig.json"
    generate_ed25519_keypair(private_key, public_key)
    append_event(db, actor="analyst", event_type="report", payload={"sha256": "a" * 64})
    signed = sign_checkpoint(db, checkpoint, private_key, signature)
    assert signed["signature_valid_at_creation"] is True
    result = verify_checkpoint(db, checkpoint, public_key, signature)
    assert result["valid"] is True
    append_event(db, actor="analyst", event_type="later-event", payload={"n": 2})
    extended = verify_checkpoint(db, checkpoint, public_key, signature)
    assert extended["valid"] is True
    assert extended["later_events"] == 1


def test_signed_checkpoint_detects_recomputed_database_rewrite(tmp_path) -> None:
    import json
    import sqlite3
    from plcsec.audit_store import ZERO_HASH, _event_hash, sign_checkpoint, verify_checkpoint
    from plcsec.signing import generate_ed25519_keypair

    db = tmp_path / "audit.sqlite"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    checkpoint = tmp_path / "checkpoint.json"
    signature = tmp_path / "checkpoint.sig.json"
    generate_ed25519_keypair(private_key, public_key)
    append_event(db, actor="analyst", event_type="report", payload={"value": "original"})
    sign_checkpoint(db, checkpoint, private_key, signature)

    # Simulate an administrator rewriting the complete local chain and recomputing hashes.
    connection = sqlite3.connect(db)
    try:
        rows = connection.execute("SELECT sequence,timestamp,actor,event_type,payload_json FROM audit_events ORDER BY sequence").fetchall()
        previous = ZERO_HASH
        for sequence, timestamp, actor, event_type, payload_json in rows:
            if sequence == 1:
                payload_json = json.dumps({"value": "rewritten"}, separators=(",", ":"), sort_keys=True)
            digest = _event_hash(sequence, timestamp, actor, event_type, payload_json, previous)
            connection.execute("UPDATE audit_events SET payload_json=?,previous_hash=?,event_hash=? WHERE sequence=?", (payload_json, previous, digest, sequence))
            previous = digest
        connection.commit()
    finally:
        connection.close()
    assert verify_audit_store(db)["valid"] is True
    result = verify_checkpoint(db, checkpoint, public_key, signature)
    assert result["valid"] is False
    assert result["reason"] == "checkpoint_does_not_match_chain_prefix"
