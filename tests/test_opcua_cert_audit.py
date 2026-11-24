from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from plcsec.opcua_cert import audit_opcua_certificate_chain, export_opcua_certificates_from_report


def _cert(subject: str, issuer: x509.Name, public_key, signer, *, ca: bool, san_uri: str | None = None, days: int = 30):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    not_after = now + timedelta(days=days)
    not_before = min(now - timedelta(days=1), not_after - timedelta(days=1))
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=2 if ca else None), critical=True)
    )
    if ca:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
    if san_uri:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri), x509.DNSName("plc.example.test")]), critical=False)
    return builder.sign(signer, algorithm=None)


def test_valid_chain_to_explicit_trust_anchor(tmp_path: Path) -> None:
    root_key = ed25519.Ed25519PrivateKey.generate()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PLCSEC Lab Root")])
    root = _cert("PLCSEC Lab Root", root_name, root_key.public_key(), root_key, ca=True)
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    app_uri = "urn:plcsec:lab:server"
    leaf = _cert("PLCSEC OPC UA Server", root.subject, leaf_key.public_key(), root_key, ca=False, san_uri=app_uri)
    leaf_path, root_path = tmp_path / "leaf.der", tmp_path / "root.pem"
    leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.DER))
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    report = audit_opcua_certificate_chain(leaf_path, trust_anchors=[root_path], expected_application_uri=app_uri, expected_dns_name="plc.example.test")
    assert report["trust"]["trusted"] is True
    assert report["trust"]["status"] == "trusted-anchor-reached"
    assert not [item for item in report["findings"] if item["id"] == "OPCUA-CERT-APPURI"]
    assert report["trust"]["revocation_checked"] is False


def test_unknown_trust_anchor_is_not_trusted(tmp_path: Path) -> None:
    root_key = ed25519.Ed25519PrivateKey.generate()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Trusted Root")])
    root = _cert("Trusted Root", root_name, root_key.public_key(), root_key, ca=True)
    rogue_key = ed25519.Ed25519PrivateKey.generate()
    rogue_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Root")])
    rogue = _cert("Rogue Root", rogue_name, rogue_key.public_key(), rogue_key, ca=True)
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    leaf = _cert("Server", root.subject, leaf_key.public_key(), root_key, ca=False)
    leaf_path, rogue_path = tmp_path / "leaf.der", tmp_path / "rogue.pem"
    leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.DER))
    rogue_path.write_bytes(rogue.public_bytes(serialization.Encoding.PEM))
    report = audit_opcua_certificate_chain(leaf_path, trust_anchors=[rogue_path])
    assert report["trust"]["trusted"] is False
    assert any(item["id"] == "OPCUA-CERT-UNTRUSTED" for item in report["findings"])


def test_self_signed_without_trust_anchor_warns(tmp_path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Self Signed")])
    cert = _cert("Self Signed", name, key.public_key(), key, ca=False)
    path = tmp_path / "leaf.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    report = audit_opcua_certificate_chain(path)
    assert report["trust"]["trusted"] is False
    assert report["trust"]["status"] == "self-signed-not-in-trust-store"


def test_export_certificates_from_opt_in_json_report(tmp_path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Export Test")])
    cert = _cert("Export Test", name, key.public_key(), key, ca=False)
    der = cert.public_bytes(serialization.Encoding.DER)
    import base64
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"events": [{"protocol": "OPC UA", "sender_certificate_der_base64": base64.b64encode(der).decode()}]}))
    exported = export_opcua_certificates_from_report(report_path, tmp_path / "certs")
    assert len(exported) == 1
    assert Path(exported[0]["path"]).read_bytes() == der


def test_expired_intermediate_makes_chain_untrusted(tmp_path: Path) -> None:
    root_key = ed25519.Ed25519PrivateKey.generate()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Valid Root")])
    root = _cert("Valid Root", root_name, root_key.public_key(), root_key, ca=True, days=90)

    intermediate_key = ed25519.Ed25519PrivateKey.generate()
    intermediate = _cert(
        "Expired Intermediate",
        root.subject,
        intermediate_key.public_key(),
        root_key,
        ca=True,
        days=-2,
    )

    leaf_key = ed25519.Ed25519PrivateKey.generate()
    leaf = _cert(
        "Valid OPC UA Server",
        intermediate.subject,
        leaf_key.public_key(),
        intermediate_key,
        ca=False,
        days=30,
    )

    leaf_path = tmp_path / "leaf.pem"
    intermediate_path = tmp_path / "intermediate.pem"
    root_path = tmp_path / "root.pem"
    leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    intermediate_path.write_bytes(intermediate.public_bytes(serialization.Encoding.PEM))
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))

    report = audit_opcua_certificate_chain(
        leaf_path,
        intermediates=[intermediate_path],
        trust_anchors=[root_path],
    )

    assert report["trust"]["trusted"] is False
    assert report["trust"]["status"] == "chain-contains-certificate-outside-validity-period"
    assert any(item["id"] == "OPCUA-CERT-CHAIN-TIME" for item in report["findings"])
