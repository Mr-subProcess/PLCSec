from plcsec.parsers.s7 import parse_s7_stream, parse_s7comm_over_tpkt


def _tpkt_s7(rosctr: int = 1, function_code: int | None = None) -> bytes:
    params = bytes([function_code]) if function_code is not None else b""
    s7 = bytes([0x32, rosctr, 0, 0, 0x12, 0x34]) + len(params).to_bytes(2, "big") + b"\x00\x00" + params
    cotp = bytes([2, 0xF0, 0x80])
    total = 4 + len(cotp) + len(s7)
    return bytes([3, 0]) + total.to_bytes(2, "big") + cotp + s7


def test_parse_s7comm_job() -> None:
    observation = parse_s7comm_over_tpkt(_tpkt_s7(1))
    assert observation is not None
    assert observation.pdu_type == "Job/request"
    assert observation.reference == 0x1234


def test_parse_s7comm_ack_data() -> None:
    observation = parse_s7comm_over_tpkt(_tpkt_s7(3))
    assert observation is not None
    assert observation.pdu_type == "Ack-data/response"


def test_recognizes_write_variable_job() -> None:
    observation = parse_s7comm_over_tpkt(_tpkt_s7(1, 0x05))
    assert observation is not None
    assert observation.function_name == "Write Variable"


def test_parses_multiple_tpkt_pdus() -> None:
    result = parse_s7_stream(_tpkt_s7(1) + _tpkt_s7(3))
    assert len(result.observations) == 2
    assert result.trailing_bytes == 0


def test_incomplete_tpkt_is_trailing_not_malformed() -> None:
    frame = _tpkt_s7(1)
    result = parse_s7_stream(frame + frame[:5])
    assert len(result.observations) == 1
    assert result.trailing_bytes == 5


def test_reject_non_tpkt() -> None:
    assert parse_s7comm_over_tpkt(b"hello world") is None


def test_reject_non_s7_payload() -> None:
    payload = bytearray(_tpkt_s7())
    payload[7] = 0x55
    assert parse_s7comm_over_tpkt(bytes(payload)) is None


def _tpkt_s7_with_params(params: bytes) -> bytes:
    s7 = bytes([0x32, 0x01, 0, 0, 0x00, 0x01]) + len(params).to_bytes(2, "big") + b"\x00\x00" + params
    cotp = bytes([2, 0xF0, 0x80])
    total = 4 + len(cotp) + len(s7)
    return bytes([3, 0]) + total.to_bytes(2, "big") + cotp + s7


def test_setup_communication_pdu_limit_is_extracted() -> None:
    params = b"\xF0\x00" + (4).to_bytes(2, "big") + (2).to_bytes(2, "big") + (480).to_bytes(2, "big")
    observation = parse_s7comm_over_tpkt(_tpkt_s7_with_params(params))
    assert observation is not None
    assert observation.setup_max_jobs_calling == 4
    assert observation.setup_max_jobs_called == 2
    assert observation.setup_pdu_length == 480


def test_read_variable_reference_metadata_is_decoded_without_values() -> None:
    item = bytes([0x12, 0x0A, 0x10, 0x02, 0x00, 0x01, 0x00, 0x01, 0x84, 0x00, 0x00, 0x08])
    observation = parse_s7comm_over_tpkt(_tpkt_s7_with_params(b"\x04\x01" + item))
    assert observation is not None
    assert observation.variable_item_count == 1
    assert observation.variable_items[0]["area_name"] == "data-block"
    assert observation.variable_items[0]["db_number"] == 1
    assert observation.variable_items[0]["byte_address"] == 1
    assert observation.variable_items[0]["bit_offset"] == 0
    assert "value" not in observation.variable_items[0]
