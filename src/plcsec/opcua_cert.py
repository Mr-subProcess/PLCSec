from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_CERT_FILE_BYTES = 8 * 1024 * 1024
MAX_CERTIFICATES = 64


class CertificateAuditError(ValueError):
    pass


def _load_crypto() -> tuple[Any, ...]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
    except ImportError as exc:
        raise RuntimeError("OPC UA certificate audit requires cryptography. Install: pip install 'plcsec[crypto]'") from exc
    return x509, dsa, ec, ed25519, ed448, padding, rsa


def load_certificates(path: str | Path) -> list[Any]:
    x509, *_ = _load_crypto()
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    if source.stat().st_size > MAX_CERT_FILE_BYTES:
        raise CertificateAuditError(f"Certificate input exceeds {MAX_CERT_FILE_BYTES} bytes")
    with source.open("rb") as handle:
        before = os.fstat(handle.fileno())
        if before.st_size > MAX_CERT_FILE_BYTES:
            raise CertificateAuditError(f"Certificate input exceeds {MAX_CERT_FILE_BYTES} bytes")
        raw = handle.read(MAX_CERT_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
    try:
        path_after = source.stat()
    except OSError as exc:
        raise CertificateAuditError("Certificate input changed or disappeared while being read") from exc
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) > MAX_CERT_FILE_BYTES or any(getattr(before, key) != getattr(after, key) for key in stable_fields) or any(getattr(after, key) != getattr(path_after, key) for key in stable_fields):
        raise CertificateAuditError("Certificate input changed while being read")
    certs: list[Any] = []
    if b"-----BEGIN CERTIFICATE-----" in raw:
        blocks = re.findall(
            rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----",
            raw,
            flags=re.DOTALL,
        )
        if not blocks:
            raise CertificateAuditError("No PEM certificate blocks found")
        if len(blocks) > MAX_CERTIFICATES:
            raise CertificateAuditError(f"Certificate count exceeds {MAX_CERTIFICATES}")
        for block in blocks:
            certs.append(x509.load_pem_x509_certificate(block + b"\n"))
    else:
        certs.append(x509.load_der_x509_certificate(raw))
    return certs


def _cert_bytes(cert: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return cert.public_bytes(serialization.Encoding.DER)


def _fingerprint(cert: Any) -> str:
    return hashlib.sha256(_cert_bytes(cert)).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _valid_at(cert: Any, now: datetime) -> tuple[bool, str, str]:
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    before, after = _utc(not_before), _utc(not_after)
    valid = before <= now <= after
    status = "valid" if valid else "not-yet-valid" if now < before else "expired"
    return valid, status, after.isoformat().replace("+00:00", "Z")


def _verify_cert_signature(cert: Any, issuer: Any) -> tuple[bool, str]:
    _, dsa, ec, ed25519, ed448, padding, rsa = _load_crypto()
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            # RSA-PSS certificate signature parameter decoding is intentionally not guessed.
            if cert.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.10":
                return False, "rsa-pss-signature-not-supported-by-offline-validator"
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False, f"unsupported-issuer-key-type:{type(public_key).__name__}"
        return True, "signature-valid"
    except Exception as exc:
        return False, f"signature-invalid:{type(exc).__name__}"


def _extension(cert: Any, extension_type: Any) -> Any | None:
    from cryptography.x509 import ExtensionNotFound
    try:
        return cert.extensions.get_extension_for_class(extension_type).value
    except ExtensionNotFound:
        return None


def audit_opcua_certificate_chain(
    leaf_path: str | Path,
    *,
    intermediates: list[str | Path] | None = None,
    trust_anchors: list[str | Path] | None = None,
    expected_application_uri: str | None = None,
    expected_dns_name: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Offline validation of an OPC UA application certificate and supplied chain.

    This is a constrained path builder, not a full RFC 5280/OCSP/CRL validator.
    It verifies certificate signatures and validity periods against caller-supplied
    trust anchors. It never downloads trust material or contacts a PLC.
    """
    x509, *_ = _load_crypto()
    leaf_list = load_certificates(leaf_path)
    if len(leaf_list) != 1:
        raise CertificateAuditError("--leaf must contain exactly one certificate")
    leaf = leaf_list[0]
    intermediate_certs: list[Any] = []
    for path in intermediates or []:
        intermediate_certs.extend(load_certificates(path))
    anchor_certs: list[Any] = []
    for path in trust_anchors or []:
        anchor_certs.extend(load_certificates(path))
    if len(intermediate_certs) + len(anchor_certs) > MAX_CERTIFICATES:
        raise CertificateAuditError(f"Supplied chain and trust anchors exceed {MAX_CERTIFICATES} certificates")

    clock = _utc(now or datetime.now(timezone.utc))
    warnings: list[str] = []
    findings: list[dict[str, str]] = []
    leaf_valid, leaf_time_status, leaf_not_after = _valid_at(leaf, clock)
    if not leaf_valid:
        findings.append({"id": "OPCUA-CERT-TIME", "severity": "high", "detail": f"Leaf certificate is {leaf_time_status}."})

    leaf_bc = _extension(leaf, x509.BasicConstraints)
    if leaf_bc is not None and leaf_bc.ca:
        findings.append({"id": "OPCUA-CERT-LEAF-CA", "severity": "medium", "detail": "The application leaf certificate is marked as a CA certificate."})
    leaf_ku = _extension(leaf, x509.KeyUsage)
    if leaf_ku is not None and not leaf_ku.digital_signature:
        warnings.append("Leaf certificate KeyUsage does not permit digitalSignature; assess against the deployed OPC UA profile.")
    san = _extension(leaf, x509.SubjectAlternativeName)
    uri_names = list(san.get_values_for_type(x509.UniformResourceIdentifier)) if san else []
    dns_names = list(san.get_values_for_type(x509.DNSName)) if san else []
    if expected_application_uri and expected_application_uri not in uri_names:
        findings.append({"id": "OPCUA-CERT-APPURI", "severity": "medium", "detail": "Expected application URI was not present in the leaf certificate SAN URI values."})
    if expected_dns_name:
        import fnmatch
        if not any(fnmatch.fnmatchcase(expected_dns_name.lower(), value.lower()) for value in dns_names):
            findings.append({"id": "OPCUA-CERT-DNS", "severity": "medium", "detail": "Expected DNS name did not match a leaf certificate DNS SAN value."})

    pool = intermediate_certs + anchor_certs
    anchor_fingerprints = {_fingerprint(cert) for cert in anchor_certs}
    current = leaf
    chain: list[dict[str, Any]] = []
    visited: set[str] = set()
    trusted = False
    chain_time_valid = True
    chain_status = "not-validated-no-trust-anchors" if not anchor_certs else "incomplete-chain"
    for depth in range(12):
        fp = _fingerprint(current)
        if fp in visited:
            chain_status = "chain-loop-detected"
            findings.append({"id": "OPCUA-CERT-CHAIN-LOOP", "severity": "high", "detail": "Certificate chain loop detected."})
            break
        visited.add(fp)
        current_valid, current_time_status, current_not_after = _valid_at(current, clock)
        if not current_valid:
            chain_time_valid = False
            findings.append({"id": "OPCUA-CERT-CHAIN-TIME", "severity": "high", "detail": f"Certificate at chain depth {depth} is {current_time_status}."})
        chain.append({
            "subject": current.subject.rfc4514_string(),
            "issuer": current.issuer.rfc4514_string(),
            "sha256": fp,
            "time_status": current_time_status,
            "not_after": current_not_after,
        })
        if fp in anchor_fingerprints:
            trusted = current_valid and chain_time_valid
            chain_status = "trusted-anchor-reached" if trusted else "chain-contains-certificate-outside-validity-period"
            break
        if current.subject == current.issuer:
            self_signed_ok, self_signed_reason = _verify_cert_signature(current, current)
            if self_signed_ok:
                chain_status = "self-signed-not-in-trust-store"
                findings.append({"id": "OPCUA-CERT-SELF-SIGNED", "severity": "medium", "detail": "A self-signed certificate was supplied but is not in the configured trust-anchor set."})
            else:
                chain_status = self_signed_reason
            break
        issuer = next((candidate for candidate in pool if candidate.subject == current.issuer and _fingerprint(candidate) not in visited), None)
        if issuer is None:
            chain_status = "issuer-not-supplied"
            break
        sig_ok, sig_reason = _verify_cert_signature(current, issuer)
        if not sig_ok:
            chain_status = sig_reason
            findings.append({"id": "OPCUA-CERT-SIGNATURE", "severity": "high", "detail": f"Issuer signature validation failed: {sig_reason}."})
            break
        issuer_fp = _fingerprint(issuer)
        if issuer_fp not in anchor_fingerprints:
            issuer_bc = _extension(issuer, x509.BasicConstraints)
            issuer_ku = _extension(issuer, x509.KeyUsage)
            if issuer_bc is None or not issuer_bc.ca:
                chain_status = "intermediate-not-ca"
                findings.append({"id": "OPCUA-CERT-INTERMEDIATE-CA", "severity": "high", "detail": "A supplied intermediate is not marked as a CA."})
                break
            if issuer_ku is not None and not issuer_ku.key_cert_sign:
                chain_status = "intermediate-keyusage-invalid"
                findings.append({"id": "OPCUA-CERT-INTERMEDIATE-KU", "severity": "high", "detail": "A supplied intermediate does not permit keyCertSign."})
                break
        current = issuer
    else:
        chain_status = "maximum-chain-depth-exceeded"

    if not anchor_certs:
        warnings.append("No trust anchors were supplied; certificate trust cannot be established.")
    if not trusted and anchor_certs:
        findings.append({"id": "OPCUA-CERT-UNTRUSTED", "severity": "high", "detail": f"Certificate path did not terminate at a supplied trust anchor ({chain_status})."})
    if trusted and not leaf_valid:
        trusted = False
    if not chain_time_valid:
        trusted = False
    return {
        "schema": "plcsec.opcua-certificate-audit.v1",
        "input": {"leaf": Path(leaf_path).name, "intermediate_files": len(intermediates or []), "trust_anchor_files": len(trust_anchors or [])},
        "leaf": {
            "subject": leaf.subject.rfc4514_string(),
            "issuer": leaf.issuer.rfc4514_string(),
            "sha256": _fingerprint(leaf),
            "serial_number_hex": format(leaf.serial_number, "x"),
            "not_after": leaf_not_after,
            "time_status": leaf_time_status,
            "san_uris": uri_names,
            "san_dns_names": dns_names,
        },
        "chain": chain,
        "trust": {"trusted": trusted, "status": chain_status, "trust_anchor_count": len(anchor_certs), "revocation_checked": False},
        "findings": findings,
        "warnings": warnings,
        "validation_scope": {
            "offline_only": True,
            "signature_verification": "supported RSA-PKCS1v1.5, ECDSA, DSA, Ed25519 and Ed448 certificate signatures",
            "revocation": "not checked; no OCSP or CRL retrieval",
            "name_constraints_and_policy_constraints": "not fully evaluated",
            "rsa_pss_certificate_signatures": "not supported by this constrained validator",
            "result_is_full_rfc5280_validation": False,
        },
    }


def export_opcua_certificates_from_report(
    report_path: str | Path,
    output_dir: str | Path,
    *,
    max_certificates: int = 128,
) -> list[dict[str, str]]:
    """Export public certificate DER blobs explicitly retained in a PLCSEC JSON report."""
    import base64
    import json
    import re

    source = Path(report_path)
    if source.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Report exceeds 128 MiB export limit")
    report = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or not isinstance(report.get("events"), list):
        raise ValueError("Input is not a PLCSEC JSON report with an events list")
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    exported: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, event in enumerate(report["events"]):
        if not isinstance(event, dict):
            continue
        encoded = event.get("sender_certificate_der_base64")
        if not isinstance(encoded, str) or not encoded:
            continue
        try:
            der = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        if not der or len(der) > 4 * 1024 * 1024:
            continue
        digest = hashlib.sha256(der).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        if len(exported) >= max_certificates:
            break
        endpoint = re.sub(r"[^0-9A-Za-z_.-]+", "_", str(event.get("server_ip") or event.get("dst_ip") or "unknown"))[:48]
        output = target / f"opcua-{endpoint}-{digest[:16]}.der"
        output.write_bytes(der)
        exported.append({"path": str(output), "sha256": digest, "endpoint": endpoint})
    return exported
