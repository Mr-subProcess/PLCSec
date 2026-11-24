import struct

import pytest

from plcsec.parsers.modbus import parse_device_identification_response, parse_mbap
from plcsec.plugins.modbus_tcp import (
    ModbusProtocolError,
    build_read_device_id_request,
    parse_device_id_adu,
)


def test_parse_mbap_read_registers() -> None:
    payload = struct.pack(">HHHB", 0x1234, 0, 6, 1) + bytes([0x03, 0x00, 0x00, 0x00, 0x01])
    frame = parse_mbap(payload)
    assert frame is not None
    assert frame.transaction_id == 0x1234
    assert frame.unit_id == 1
    assert frame.function_code == 0x03
    assert frame.function_name == "Read Holding Registers"
    assert not frame.is_exception


def test_parse_mbap_write_function_identification() -> None:
    payload = struct.pack(">HHHB", 1, 0, 6, 1) + bytes([0x06, 0, 1, 0, 5])
    frame = parse_mbap(payload)
    assert frame is not None
    assert frame.function_code == 0x06
    assert frame.function_name == "Write Single Register"


def test_parse_mbap_exception() -> None:
    payload = struct.pack(">HHHB", 1, 0, 3, 1) + bytes([0x83, 0x02])
    frame = parse_mbap(payload)
    assert frame is not None
    assert frame.is_exception
    assert frame.function_name == "Read Holding Registers"


def test_parse_mbap_rejects_bad_protocol_id() -> None:
    payload = struct.pack(">HHHB", 1, 9, 3, 1) + bytes([0x03, 0x00])
    assert parse_mbap(payload) is None


def test_parse_mbap_rejects_truncated_payload() -> None:
    payload = struct.pack(">HHHB", 1, 0, 6, 1) + bytes([0x03])
    assert parse_mbap(payload) is None


def test_build_read_device_id_is_single_read_request() -> None:
    request = build_read_device_id_request(unit_id=1, transaction_id=0xBEEF)
    assert request[:7] == struct.pack(">HHHB", 0xBEEF, 0, 5, 1)
    assert request[7:] == bytes([0x2B, 0x0E, 0x01, 0x00])
    assert len(request) == 11


def test_parse_device_id_response_objects() -> None:
    pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 2, 0, 4]) + b"ACME" + bytes([1, 3]) + b"X1A"
    result = parse_device_identification_response(pdu)
    assert result["object_count"] == 2
    objects = result["objects"]
    assert isinstance(objects, dict)
    assert objects["object_0"] == "ACME"
    assert objects["object_1"] == "X1A"


def test_parse_device_id_adu_validates_transaction_id() -> None:
    pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 1, 0, 4]) + b"ACME"
    adu = struct.pack(">HHHB", 7, 0, len(pdu) + 1, 1) + pdu
    with pytest.raises(ModbusProtocolError, match="Transaction ID"):
        parse_device_id_adu(adu, 8, 1)


def test_device_id_parser_rejects_truncated_objects() -> None:
    with pytest.raises(ValueError, match="Truncated"):
        parse_device_identification_response(bytes([0x2B, 0x0E, 1, 1, 0, 0, 1, 0, 8, 65]))


def test_modbus_active_adapter_sends_exactly_one_read_only_request(monkeypatch) -> None:
    from plcsec.plugins import modbus_tcp

    response_pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 1, 0, 4]) + b"ACME"
    response = struct.pack(">HHHB", 0x2222, 0, len(response_pdu) + 1, 1) + response_pdu

    class FakeSocket:
        def __init__(self) -> None:
            self.sent: list[bytes] = []
            self.read_offset = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def settimeout(self, timeout: float) -> None:
            self.timeout = timeout

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

        def recv(self, size: int) -> bytes:
            chunk = response[self.read_offset : self.read_offset + size]
            self.read_offset += len(chunk)
            return chunk

    fake = FakeSocket()
    monkeypatch.setattr(modbus_tcp.secrets, "randbelow", lambda upper: 0x2222)
    monkeypatch.setattr(modbus_tcp.socket, "create_connection", lambda *a, **k: fake)
    report = modbus_tcp.audit_device_identification("192.0.2.10")
    assert len(fake.sent) == 1
    assert fake.sent[0][7:] == bytes([0x2B, 0x0E, 0x01, 0x00])
    assert report.metadata["writes_sent"] == 0
    assert report.findings[0].evidence["objects"]["object_0"] == "ACME"


def test_modbus_active_timeout_is_bounded() -> None:
    from plcsec.plugins.modbus_tcp import audit_device_identification

    with pytest.raises(ValueError, match="Timeout"):
        audit_device_identification("192.0.2.10", timeout=30.0)
