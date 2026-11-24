import struct

from plcsec.parsers.ethernet_ip import parse_cpf_cip, parse_enip_stream, parse_list_identity


def _encap(command: int, data: bytes) -> bytes:
    return struct.pack("<HHII8sI", command, len(data), 0, 0, b"12345678", 0) + data


def test_parse_enip_register_session_frame() -> None:
    result = parse_enip_stream(_encap(0x0065, b"\x01\x00\x00\x00"))
    assert len(result.frames) == 1
    assert result.frames[0].command_name == "RegisterSession"


def test_parse_list_identity_cpf() -> None:
    product_name = b"PLC"
    identity = (
        b"\x01\x00" + b"\x00" * 16 +
        struct.pack("<HHHBBHI", 1, 14, 20, 1, 2, 3, 0x12345678) +
        bytes([len(product_name)]) + product_name + b"\x01"
    )
    cpf = b"\x00" * 6 + struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(identity)) + identity
    parsed = parse_list_identity(cpf)
    assert parsed is not None
    assert parsed.vendor_id == 1
    assert parsed.product_name == "PLC"
    result = parse_enip_stream(_encap(0x0063, cpf))
    assert result.frames[0].identity is not None
    assert result.frames[0].identity.serial_number == 0x12345678


def test_parse_cip_write_service_is_marked_not_executed() -> None:
    cip = bytes([0x10, 0x02, 0x20, 0x01])
    cpf = b"\x00" * 6 + struct.pack("<H", 2)
    cpf += struct.pack("<HH", 0x0000, 0)
    cpf += struct.pack("<HH", 0x00B2, len(cip)) + cip
    items = parse_cpf_cip(cpf)
    assert len(items) == 1
    assert items[0].service_name == "Set_Attribute_Single"
    assert items[0].write_like_request is True


def test_reject_truncated_enip_header() -> None:
    assert parse_enip_stream(b"\x63\x00\x10").frames == ()


def test_cip_logical_path_metadata_is_decoded() -> None:
    from plcsec.parsers.ethernet_ip import parse_cip_message
    # Get_Attribute_Single, 3-word path: Class 1 / Instance 1 / Attribute 3.
    request = bytes([0x0E, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x03])
    parsed = parse_cip_message(request)
    assert parsed is not None
    assert parsed.class_id == 1
    assert parsed.instance_id == 1
    assert parsed.attribute_id == 3
    assert parsed.path_size_words == 3
    assert parsed.request_data_length == 0


def test_cip_malformed_logical_path_does_not_invent_identifiers() -> None:
    from plcsec.parsers.ethernet_ip import parse_cip_message
    request = bytes([0x0E, 0x05, 0x20, 0x01])
    parsed = parse_cip_message(request)
    assert parsed is not None
    assert parsed.class_id is None
    assert parsed.instance_id is None
    assert parsed.attribute_id is None
