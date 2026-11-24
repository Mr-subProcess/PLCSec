from plcsec.parsers.dnp3 import crc16_dnp, parse_dnp3_stream


def _frame(user_data: bytes = b"") -> bytes:
    length = 5 + len(user_data)
    header = bytes([0x05, 0x64, length, 0xC3, 1, 0, 2, 0])
    encoded = crc16_dnp(header).to_bytes(2, "little")
    blocks = b""
    for start in range(0, len(user_data), 16):
        block = user_data[start : start + 16]
        blocks += block + crc16_dnp(block).to_bytes(2, "little")
    return header + encoded + blocks


def test_crc16_dnp_check_vector() -> None:
    assert crc16_dnp(b"123456789") == 0xEA82


def test_parse_dnp3_link_header_and_crc() -> None:
    result = parse_dnp3_stream(_frame(b"\xC0\xC0"))
    assert len(result.frames) == 1
    frame = result.frames[0]
    assert frame.destination == 1
    assert frame.source == 2
    assert frame.function_name == "CONFIRMED_USER_DATA"
    assert frame.user_data_length == 2
    assert frame.header_crc_valid is True
    assert frame.data_block_crc_valid == (True,)
    assert frame.crc_valid is True
    assert frame.transport_fir is True
    assert frame.transport_fin is True
    assert frame.transport_sequence == 0


def test_parse_multiple_dnp3_frames() -> None:
    result = parse_dnp3_stream(_frame() + _frame(b"\x01\x02\x03"))
    assert len(result.frames) == 2
    assert all(frame.crc_valid for frame in result.frames)


def test_validate_multiple_data_block_crcs() -> None:
    user_data = bytes(range(40))
    result = parse_dnp3_stream(_frame(user_data))
    assert len(result.frames) == 1
    assert result.frames[0].data_block_crc_valid == (True, True, True)
    assert result.frames[0].crc_valid is True


def test_crc_corruption_is_reported_not_silently_accepted() -> None:
    raw = bytearray(_frame(b"\xC0\x01"))
    raw[8] ^= 0x01
    result = parse_dnp3_stream(bytes(raw))
    assert len(result.frames) == 1
    assert result.frames[0].header_crc_valid is False
    assert result.frames[0].crc_valid is False
    assert result.crc_errors == 1


def test_data_crc_corruption_is_reported() -> None:
    raw = bytearray(_frame(b"\xC0\x01"))
    raw[-1] ^= 0x80
    result = parse_dnp3_stream(bytes(raw))
    assert len(result.frames) == 1
    assert result.frames[0].header_crc_valid is True
    assert result.frames[0].data_block_crc_valid == (False,)
    assert result.crc_errors == 1


def test_reject_invalid_dnp3_length() -> None:
    result = parse_dnp3_stream(b"\x05\x64\x01\x00\x00\x00\x00\x00\x00\x00")
    assert result.frames == ()
    assert result.malformed_frames >= 1
