from plcsec.parsers.bacnet import parse_bacnet_datagram


def test_parse_bacnet_original_unicast_npdu() -> None:
    payload = bytes([0x81, 0x0A, 0, 7, 1, 0, 0x10])
    result = parse_bacnet_datagram(payload)
    assert result is not None
    assert result.function_name == "Original-Unicast-NPDU"
    assert result.npdu_version == 1
    assert result.apdu_type == 1


def test_bacnet_parser_rejects_invalid_bvlc_length() -> None:
    assert parse_bacnet_datagram(bytes([0x81, 0x0A, 0, 12, 1, 0, 0x10])) is None


def test_bacnet_parser_rejects_non_bacnet_payload() -> None:
    assert parse_bacnet_datagram(b"\x00\x0A\x00\x04") is None
