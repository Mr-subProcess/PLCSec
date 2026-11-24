import struct

from plcsec.parsers.opcua import parse_opcua_stream


def _hello(url: str = "opc.tcp://192.0.2.10:4840") -> bytes:
    encoded = url.encode()
    body = struct.pack("<IIIIIi", 0, 65536, 65536, 4 * 1024 * 1024, 16, len(encoded)) + encoded
    return b"HEL" + b"F" + struct.pack("<I", len(body) + 8) + body


def test_parse_opcua_hello_endpoint() -> None:
    result = parse_opcua_stream(_hello())
    assert len(result.frames) == 1
    frame = result.frames[0]
    assert frame.message_type == "HEL"
    assert frame.endpoint_url == "opc.tcp://192.0.2.10:4840"
    assert frame.protocol_version == 0
    assert frame.max_chunk_count == 16


def test_parse_multiple_opcua_messages() -> None:
    one = b"ACKF" + struct.pack("<I", 8)
    two = b"ERRF" + struct.pack("<I", 8)
    result = parse_opcua_stream(one + two)
    assert [frame.message_type for frame in result.frames] == ["ACK", "ERR"]


def test_opcua_rejects_oversized_length() -> None:
    result = parse_opcua_stream(b"MSGF" + struct.pack("<I", 0x7FFFFFFF))
    assert result.frames == ()
    assert result.malformed_frames == 1
