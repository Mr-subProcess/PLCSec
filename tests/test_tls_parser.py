from plcsec.parsers.tls import parse_dtls_datagram, parse_tls_stream


def _record(handshake_type: int, body: bytes, version: int = 0x0303) -> bytes:
    message = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16" + version.to_bytes(2, "big") + len(message).to_bytes(2, "big") + message


def _client_hello() -> bytes:
    host = b"plc-lab.example"
    # ServerNameList length, name_type, name length, hostname.
    sni_data = (3 + len(host)).to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host
    sni_ext = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
    versions_data = b"\x02\x03\x04"
    versions_ext = b"\x00\x2b" + len(versions_data).to_bytes(2, "big") + versions_data
    extensions = sni_ext + versions_ext
    body = b"\x03\x03" + b"R" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += len(extensions).to_bytes(2, "big") + extensions
    return _record(1, body)


def _server_hello(version: int) -> bytes:
    extensions = b"\x00\x2b\x00\x02" + version.to_bytes(2, "big")
    body = b"\x03\x03" + b"S" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
    body += len(extensions).to_bytes(2, "big") + extensions
    return _record(2, body)


def test_parse_client_hello_sni_and_supported_versions() -> None:
    result = parse_tls_stream(_client_hello())
    assert result.record_count == 1
    hello = result.handshakes[0]
    assert hello.handshake_name == "ClientHello"
    assert hello.server_name == "plc-lab.example"
    assert hello.negotiated_version == "TLS 1.3"


def test_parse_server_hello_negotiated_tls13() -> None:
    result = parse_tls_stream(_server_hello(0x0304))
    assert result.handshakes[0].negotiated_version == "TLS 1.3"
    assert result.handshakes[0].cipher_suite == 0x1301


def test_tls_stream_handles_multiple_records() -> None:
    result = parse_tls_stream(_client_hello() + _server_hello(0x0303))
    assert result.record_count == 2
    assert [item.handshake_name for item in result.handshakes] == ["ClientHello", "ServerHello"]


def test_tls_parser_ignores_non_tls_stream() -> None:
    assert parse_tls_stream(b"not tls bytes").record_count == 0


def test_dtls_record_header() -> None:
    # DTLS 1.2 application-data record, epoch 2, sequence 3, length 2.
    payload = bytes([23]) + b"\xfe\xfd" + (2).to_bytes(2, "big") + (3).to_bytes(6, "big") + (2).to_bytes(2, "big") + b"OK"
    parsed = parse_dtls_datagram(payload)
    assert parsed is not None
    assert parsed.version == "DTLS 1.2"
    assert parsed.content_name == "application_data"
