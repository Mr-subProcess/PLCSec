from plcsec.parsers.iec104 import parse_iec104_stream


def _i_frame(asdu: bytes) -> bytes:
    control = b"\x00\x00\x00\x00"
    body = control + asdu
    return b"\x68" + bytes([len(body)]) + body


def test_parse_iec104_information_frame_and_control_asdu() -> None:
    # C_SC_NA_1, one object, activation cause, CA 1, IOA 0x1234, select=1.
    asdu = bytes([45, 1, 6, 0, 1, 0, 0x34, 0x12, 0, 0x81])
    result = parse_iec104_stream(_i_frame(asdu))
    assert len(result.frames) == 1
    frame = result.frames[0]
    assert frame.frame_type == "I"
    assert frame.asdu_type_id == 45
    assert frame.is_control_asdu
    assert frame.common_address == 1
    assert frame.originator_address == 0
    assert frame.object_count == 1
    assert frame.sequence_of_elements is False
    assert frame.first_information_object_address == 0x1234
    assert frame.command_select is True
    assert frame.command_value == 1
    assert frame.cot_name == "activation"


def test_parse_iec104_supervisory_frame() -> None:
    frame = b"\x68\x04\x01\x00\x02\x00"
    result = parse_iec104_stream(frame)
    assert result.frames[0].frame_type == "S"
    assert result.frames[0].receive_sequence == 1


def test_parse_iec104_multiple_frames() -> None:
    one = b"\x68\x04\x01\x00\x00\x00"
    two = b"\x68\x04\x43\x00\x00\x00"
    result = parse_iec104_stream(one + two)
    assert len(result.frames) == 2


def test_incomplete_iec104_frame_is_trailing() -> None:
    result = parse_iec104_stream(b"\x68\x10\x00\x00")
    assert result.frames == ()
    assert result.trailing_bytes == 4


def test_parse_negative_confirmation_and_sequence_vsq() -> None:
    # One sequenced information object, spontaneous cause with negative flag.
    asdu = bytes([1, 0x81, 0x43, 0, 1, 0, 0x20, 0x00, 0x00, 0x01])
    result = parse_iec104_stream(_i_frame(asdu))
    frame = result.frames[0]
    assert frame.negative_confirmation is True
    assert frame.sequence_of_elements is True
    assert frame.object_count == 1
    assert frame.cot_name == "spontaneous"
