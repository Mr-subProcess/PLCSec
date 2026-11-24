from __future__ import annotations

from dataclasses import dataclass

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}
CONTENT_TYPES = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data", 24: "heartbeat"}
HANDSHAKE_TYPES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate", 14: "ServerHelloDone", 20: "Finished"}


@dataclass(frozen=True, slots=True)
class TLSHandshake:
    handshake_type: int
    handshake_name: str
    legacy_version: str | None = None
    negotiated_version: str | None = None
    cipher_suite: int | None = None
    server_name: str | None = None
    extension_ids: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class TLSStreamResult:
    record_count: int
    content_types: tuple[str, ...]
    record_versions: tuple[str, ...]
    handshakes: tuple[TLSHandshake, ...]
    trailing_bytes: int
    malformed_records: int


def parse_tls_stream(payload: bytes, *, max_records: int = 4096, max_record_length: int = 18_432) -> TLSStreamResult:
    """Parse TLS record framing and cleartext ClientHello/ServerHello metadata.

    The parser never decrypts TLS application data or extracts private keys.
    Hello parsing is best-effort and bounded; encrypted handshake messages are
    represented only by their visible record framing.
    """
    offset = 0
    record_count = 0
    content_types: list[str] = []
    record_versions: list[str] = []
    handshake_data = bytearray()
    malformed = 0
    while offset + 5 <= len(payload) and record_count < max_records:
        content_type = payload[offset]
        version = int.from_bytes(payload[offset + 1 : offset + 3], "big")
        length = int.from_bytes(payload[offset + 3 : offset + 5], "big")
        if content_type not in CONTENT_TYPES or (version >> 8) != 0x03 or length > max_record_length:
            if record_count == 0:
                return TLSStreamResult(0, (), (), (), len(payload), 0)
            malformed += 1
            break
        end = offset + 5 + length
        if end > len(payload):
            break
        record_count += 1
        content_types.append(CONTENT_TYPES[content_type])
        record_versions.append(TLS_VERSIONS.get(version, f"0x{version:04X}"))
        if content_type == 22:
            handshake_data.extend(payload[offset + 5 : end])
        offset = end
    handshakes = _parse_handshake_messages(bytes(handshake_data))
    return TLSStreamResult(record_count, tuple(content_types), tuple(record_versions), tuple(handshakes), len(payload) - offset, malformed)


def _parse_handshake_messages(payload: bytes) -> tuple[TLSHandshake, ...]:
    result: list[TLSHandshake] = []
    offset = 0
    while offset + 4 <= len(payload) and len(result) < 256:
        message_type = payload[offset]
        length = int.from_bytes(payload[offset + 1 : offset + 4], "big")
        end = offset + 4 + length
        if length > 1_000_000 or end > len(payload):
            break
        body = payload[offset + 4 : end]
        if message_type == 1:
            result.append(_parse_client_hello(body))
        elif message_type == 2:
            result.append(_parse_server_hello(body))
        else:
            result.append(TLSHandshake(message_type, HANDSHAKE_TYPES.get(message_type, f"Unknown handshake {message_type}")))
        offset = end
    return tuple(result)


def _parse_client_hello(body: bytes) -> TLSHandshake:
    if len(body) < 34:
        return TLSHandshake(1, "ClientHello")
    legacy = int.from_bytes(body[:2], "big")
    offset = 34
    if offset >= len(body):
        return TLSHandshake(1, "ClientHello", TLS_VERSIONS.get(legacy, f"0x{legacy:04X}"))
    session_len = body[offset]
    offset += 1 + session_len
    if offset + 2 > len(body):
        return TLSHandshake(1, "ClientHello", TLS_VERSIONS.get(legacy, f"0x{legacy:04X}"))
    cipher_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2 + cipher_len
    if offset >= len(body):
        return TLSHandshake(1, "ClientHello", TLS_VERSIONS.get(legacy, f"0x{legacy:04X}"))
    compression_len = body[offset]
    offset += 1 + compression_len
    if offset + 2 > len(body):
        return TLSHandshake(1, "ClientHello", TLS_VERSIONS.get(legacy, f"0x{legacy:04X}"))
    ext_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    ext_end = min(len(body), offset + ext_len)
    extension_ids: list[int] = []
    server_name = None
    negotiated = None
    while offset + 4 <= ext_end:
        ext_type = int.from_bytes(body[offset : offset + 2], "big")
        ext_size = int.from_bytes(body[offset + 2 : offset + 4], "big")
        offset += 4
        if offset + ext_size > ext_end:
            break
        ext = body[offset : offset + ext_size]
        extension_ids.append(ext_type)
        if ext_type == 0 and len(ext) >= 5:
            list_len = int.from_bytes(ext[:2], "big")
            name_type = ext[2]
            name_len = int.from_bytes(ext[3:5], "big")
            if name_type == 0 and 5 + name_len <= min(len(ext), list_len + 2):
                try:
                    server_name = ext[5 : 5 + name_len].decode("idna")
                except UnicodeError:
                    server_name = ext[5 : 5 + name_len].decode("ascii", errors="replace")
        elif ext_type == 43 and len(ext) >= 3:
            versions_len = ext[0]
            if versions_len >= 2 and 1 + versions_len <= len(ext):
                versions = [int.from_bytes(ext[i : i + 2], "big") for i in range(1, 1 + versions_len, 2)]
                if versions:
                    negotiated = ", ".join(TLS_VERSIONS.get(item, f"0x{item:04X}") for item in versions)
        offset += ext_size
    return TLSHandshake(1, "ClientHello", TLS_VERSIONS.get(legacy, f"0x{legacy:04X}"), negotiated, None, server_name, tuple(extension_ids))


def _parse_server_hello(body: bytes) -> TLSHandshake:
    if len(body) < 38:
        return TLSHandshake(2, "ServerHello")
    legacy = int.from_bytes(body[:2], "big")
    offset = 34
    session_len = body[offset]
    offset += 1 + session_len
    if offset + 3 > len(body):
        return TLSHandshake(2, "ServerHello", TLS_VERSIONS.get(legacy, f"0x{legacy:04X}"))
    cipher = int.from_bytes(body[offset : offset + 2], "big")
    offset += 3  # cipher suite + compression method
    extension_ids: list[int] = []
    negotiated = None
    if offset + 2 <= len(body):
        ext_len = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        ext_end = min(len(body), offset + ext_len)
        while offset + 4 <= ext_end:
            ext_type = int.from_bytes(body[offset : offset + 2], "big")
            ext_size = int.from_bytes(body[offset + 2 : offset + 4], "big")
            offset += 4
            if offset + ext_size > ext_end:
                break
            extension_ids.append(ext_type)
            if ext_type == 43 and ext_size == 2:
                selected = int.from_bytes(body[offset : offset + 2], "big")
                negotiated = TLS_VERSIONS.get(selected, f"0x{selected:04X}")
            offset += ext_size
    negotiated = negotiated or TLS_VERSIONS.get(legacy, f"0x{legacy:04X}")
    return TLSHandshake(2, "ServerHello", TLS_VERSIONS.get(legacy, f"0x{legacy:04X}"), negotiated, cipher, None, tuple(extension_ids))


@dataclass(frozen=True, slots=True)
class DTLSObservation:
    content_type: int
    content_name: str
    version: str
    epoch: int
    record_sequence: int
    record_length: int


def parse_dtls_datagram(payload: bytes) -> DTLSObservation | None:
    if len(payload) < 13:
        return None
    content_type = payload[0]
    version = int.from_bytes(payload[1:3], "big")
    if content_type not in CONTENT_TYPES or version not in {0xFEFD, 0xFEFC, 0xFEFF}:
        return None
    length = int.from_bytes(payload[11:13], "big")
    if 13 + length > len(payload):
        return None
    return DTLSObservation(
        content_type, CONTENT_TYPES[content_type],
        {0xFEFF: "DTLS 1.0", 0xFEFD: "DTLS 1.2", 0xFEFC: "DTLS 1.3"}.get(version, f"0x{version:04X}"),
        int.from_bytes(payload[3:5], "big"), int.from_bytes(payload[5:11], "big"), length,
    )
