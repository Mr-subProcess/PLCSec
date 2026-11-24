import struct

from plcsec.parsers.modbus import parse_mbap_stream


def _adu(tid: int, function: int, data: bytes = b"\x00\x00\x00\x01") -> bytes:
    pdu = bytes([function]) + data
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu


def test_multiple_modbus_adus_in_one_stream() -> None:
    result = parse_mbap_stream(_adu(1, 0x03) + _adu(2, 0x06))
    assert len(result.frames) == 2
    assert result.frames[0].transaction_id == 1
    assert result.frames[1].function_name == "Write Single Register"
    assert result.trailing_bytes == 0


def test_incomplete_trailing_modbus_adu_is_not_malformed() -> None:
    payload = _adu(1, 0x03) + _adu(2, 0x10)[:6]
    result = parse_mbap_stream(payload)
    assert len(result.frames) == 1
    assert result.trailing_bytes == 6


def test_modbus_stream_resynchronizes_after_noise() -> None:
    result = parse_mbap_stream(b"\xff\xff\xff" + _adu(5, 0x01))
    assert len(result.frames) == 1
    assert result.frames[0].transaction_id == 5
    assert result.malformed_headers >= 1
