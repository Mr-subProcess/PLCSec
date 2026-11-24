from __future__ import annotations

from plcsec.parsers.opcua import parse_opcua_stream
import pytest


def _ua_string(value: bytes | None) -> bytes:
    if value is None:
        return (0xFFFFFFFF).to_bytes(4, "little")
    return len(value).to_bytes(4, "little") + value


def test_opn_security_policy_none_is_extracted() -> None:
    uri = b"http://opcfoundation.org/UA/SecurityPolicy#None"
    body = (7).to_bytes(4, "little") + _ua_string(uri) + _ua_string(None) + _ua_string(None) + b"\x01" * 8
    length = 8 + len(body)
    frame = b"OPNF" + length.to_bytes(4, "little") + body
    parsed = parse_opcua_stream(frame)
    assert len(parsed.frames) == 1
    observed = parsed.frames[0]
    assert observed.security_policy_name == "None"
    assert observed.policy_assessment == "no-message-security-policy-observed"
    assert observed.secure_channel_id == 7


def test_opn_deprecated_policy_is_flagged() -> None:
    uri = b"http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
    body = (1).to_bytes(4, "little") + _ua_string(uri) + _ua_string(None) + _ua_string(None) + b"\x00" * 8
    length = 8 + len(body)
    parsed = parse_opcua_stream(b"OPNF" + length.to_bytes(4, "little") + body)
    assert parsed.frames[0].policy_assessment == "deprecated-policy-observed"


def test_opn_sender_certificate_fingerprint_and_metadata() -> None:
    pytest.importorskip("cryptography")
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID
    import hashlib

    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PLCSEC Lab OPC UA Server")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, algorithm=None)
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    uri = b"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    body = (9).to_bytes(4, "little") + _ua_string(uri) + _ua_string(cert_der) + _ua_string(None) + b"\x01" * 8
    length = 8 + len(body)
    frame = b"OPNF" + length.to_bytes(4, "little") + body
    parsed = parse_opcua_stream(frame)
    observed = parsed.frames[0]
    assert observed.sender_certificate_sha256 == hashlib.sha256(cert_der).hexdigest()
    assert observed.sender_certificate_subject == "CN=PLCSEC Lab OPC UA Server"
    assert observed.certificate_parse_status == "parsed-x509"


def test_opn_public_certificate_der_is_available_for_opt_in_export() -> None:
    pytest.importorskip("cryptography")
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID
    import base64

    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PLCSEC certificate")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=5))
        .sign(key, algorithm=None))
    der = cert.public_bytes(serialization.Encoding.DER)
    uri = b"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    body = (1).to_bytes(4, "little") + _ua_string(uri) + _ua_string(der) + _ua_string(None) + b"\x00" * 8
    frame = b"OPNF" + (8 + len(body)).to_bytes(4, "little") + body
    parsed = parse_opcua_stream(frame)
    assert base64.b64decode(parsed.frames[0].sender_certificate_der_base64) == der
