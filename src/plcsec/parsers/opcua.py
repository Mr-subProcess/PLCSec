from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

MESSAGE_TYPES = {"HEL", "ACK", "ERR", "RHE", "OPN", "MSG", "CLO"}
DEPRECATED_POLICIES = {"Basic128Rsa15", "Basic256"}
KNOWN_POLICIES = {
    "None", "Basic128Rsa15", "Basic256", "Basic256Sha256",
    "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss",
}


@dataclass(frozen=True, slots=True)
class OpcUaFrame:
    message_type: str
    chunk_type: str
    message_length: int
    endpoint_url: str | None = None
    protocol_version: int | None = None
    max_message_size: int | None = None
    max_chunk_count: int | None = None
    secure_channel_id: int | None = None
    security_policy_uri: str | None = None
    security_policy_name: str | None = None
    policy_assessment: str | None = None
    sender_certificate_sha256: str | None = None
    sender_certificate_subject: str | None = None
    sender_certificate_issuer: str | None = None
    sender_certificate_not_after: str | None = None
    certificate_parse_status: str | None = None
    sender_certificate_der_base64: str | None = None


@dataclass(frozen=True, slots=True)
class OpcUaStreamResult:
    frames: tuple[OpcUaFrame, ...]
    trailing_bytes: int
    malformed_frames: int


def _read_u32(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 4], "little"), offset + 4


def _read_ua_string(data: bytes, offset: int, *, max_length: int = 16 * 1024) -> tuple[bytes | None, int] | None:
    value = _read_u32(data, offset)
    if value is None:
        return None
    length, offset = value
    if length == 0xFFFFFFFF:
        return None, offset
    if length < 0 or length > max_length or offset + length > len(data):
        return None
    return data[offset : offset + length], offset + length


def _policy_info(uri: str | None) -> tuple[str | None, str | None]:
    if not uri:
        return None, "not-observed"
    prefix = "http://opcfoundation.org/UA/SecurityPolicy#"
    name = uri.rsplit("#", 1)[-1] if uri.startswith(prefix) else uri
    if name == "None":
        return name, "no-message-security-policy-observed"
    if name in DEPRECATED_POLICIES:
        return name, "deprecated-policy-observed"
    if name in KNOWN_POLICIES:
        return name, "known-policy-observed-mode-not-visible"
    return name, "unknown-policy-observed"


def _certificate_metadata(der: bytes | None) -> tuple[str | None, str | None, str | None, str | None, str]:
    if not der:
        return None, None, None, None, "not-present"
    fingerprint = hashlib.sha256(der).hexdigest()
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_after_obj = getattr(cert, "not_valid_after_utc", None)
        if not_after_obj is None:
            not_after_obj = cert.not_valid_after.replace(tzinfo=None)
            not_after = not_after_obj.isoformat() + "Z"
        else:
            not_after = not_after_obj.isoformat().replace("+00:00", "Z")
        return fingerprint, subject, issuer, not_after, "parsed-x509"
    except ImportError:
        return fingerprint, None, None, None, "fingerprint-only-cryptography-not-installed"
    except Exception:
        return fingerprint, None, None, None, "certificate-bytes-not-valid-der-x509"


def _parse_opn_security_header(body: bytes) -> dict[str, Any]:
    """Parse the unencrypted OPN AsymmetricAlgorithmSecurityHeader, not encrypted payload."""
    # OPN body: SecureChannelId(4), SecurityPolicyUri(String), SenderCertificate(ByteString),
    # ReceiverCertificateThumbprint(ByteString), SequenceHeader(8), then secured payload.
    if len(body) < 4:
        return {}
    channel_id = int.from_bytes(body[:4], "little")
    offset = 4
    policy = _read_ua_string(body, offset, max_length=2048)
    if policy is None:
        return {"secure_channel_id": channel_id, "certificate_parse_status": "malformed-security-policy-uri"}
    raw_policy, offset = policy
    uri = raw_policy.decode("utf-8", errors="replace") if raw_policy else None
    sender = _read_ua_string(body, offset, max_length=4 * 1024 * 1024)
    if sender is None:
        return {"secure_channel_id": channel_id, "security_policy_uri": uri, "certificate_parse_status": "malformed-sender-certificate-field"}
    cert_der, offset = sender
    receiver_thumb = _read_ua_string(body, offset, max_length=4096)
    if receiver_thumb is None:
        return {"secure_channel_id": channel_id, "security_policy_uri": uri, "certificate_parse_status": "malformed-receiver-thumbprint-field"}
    thumb, offset = receiver_thumb
    policy_name, assessment = _policy_info(uri)
    cert_hash, subject, issuer, not_after, cert_status = _certificate_metadata(cert_der)
    return {
        "secure_channel_id": channel_id,
        "security_policy_uri": uri,
        "security_policy_name": policy_name,
        "policy_assessment": assessment,
        "sender_certificate_sha256": cert_hash,
        "sender_certificate_subject": subject,
        "sender_certificate_issuer": issuer,
        "sender_certificate_not_after": not_after,
        "certificate_parse_status": cert_status,
        "sender_certificate_der_base64": base64.b64encode(cert_der).decode("ascii") if cert_der else None,
        "receiver_certificate_thumbprint_sha256": hashlib.sha256(thumb).hexdigest() if thumb else None,
        "sequence_header_present": offset + 8 <= len(body),
    }


def parse_opcua_stream(
    payload: bytes,
    *,
    max_frames: int = 2048,
    max_message_size: int = 16 * 1024 * 1024,
) -> OpcUaStreamResult:
    frames: list[OpcUaFrame] = []
    offset = 0
    malformed = 0
    while offset + 8 <= len(payload) and len(frames) < max_frames:
        message_type = payload[offset : offset + 3].decode("ascii", errors="replace")
        chunk_type = chr(payload[offset + 3]) if 32 <= payload[offset + 3] <= 126 else "?"
        length = int.from_bytes(payload[offset + 4 : offset + 8], "little")
        if message_type not in MESSAGE_TYPES or length < 8 or length > max_message_size:
            malformed += 1
            candidate = _find_header(payload, offset + 1, min(len(payload), offset + 256))
            if candidate is None:
                break
            offset = candidate
            continue
        end = offset + length
        if end > len(payload):
            break
        body = payload[offset + 8 : end]
        values: dict[str, Any] = {}
        if message_type == "HEL" and len(body) >= 20:
            values["protocol_version"] = int.from_bytes(body[0:4], "little")
            values["max_message_size"] = int.from_bytes(body[12:16], "little")
            values["max_chunk_count"] = int.from_bytes(body[16:20], "little")
            if len(body) >= 24:
                url_len = int.from_bytes(body[20:24], "little", signed=True)
                if 0 <= url_len <= 4096 and 24 + url_len <= len(body):
                    values["endpoint_url"] = body[24 : 24 + url_len].decode("utf-8", errors="replace")
        elif message_type == "OPN":
            values.update(_parse_opn_security_header(body))
        frames.append(OpcUaFrame(
            message_type=message_type,
            chunk_type=chunk_type,
            message_length=length,
            endpoint_url=values.get("endpoint_url"),
            protocol_version=values.get("protocol_version"),
            max_message_size=values.get("max_message_size"),
            max_chunk_count=values.get("max_chunk_count"),
            secure_channel_id=values.get("secure_channel_id"),
            security_policy_uri=values.get("security_policy_uri"),
            security_policy_name=values.get("security_policy_name"),
            policy_assessment=values.get("policy_assessment"),
            sender_certificate_sha256=values.get("sender_certificate_sha256"),
            sender_certificate_subject=values.get("sender_certificate_subject"),
            sender_certificate_issuer=values.get("sender_certificate_issuer"),
            sender_certificate_not_after=values.get("sender_certificate_not_after"),
            certificate_parse_status=values.get("certificate_parse_status"),
            sender_certificate_der_base64=values.get("sender_certificate_der_base64"),
        ))
        offset = end
    return OpcUaStreamResult(tuple(frames), len(payload) - offset, malformed)


def _find_header(payload: bytes, start: int, stop: int) -> int | None:
    for offset in range(start, max(start, stop - 7)):
        message_type = payload[offset : offset + 3]
        if message_type in {b"HEL", b"ACK", b"ERR", b"RHE", b"OPN", b"MSG", b"CLO"}:
            length = int.from_bytes(payload[offset + 4 : offset + 8], "little")
            if 8 <= length <= 16 * 1024 * 1024:
                return offset
    return None
