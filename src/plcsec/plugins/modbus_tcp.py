from __future__ import annotations

import secrets
import socket
import struct
from typing import Any

from plcsec.models import Asset, AssessmentReport, Finding, ServiceObservation, Severity


class ModbusProtocolError(RuntimeError):
    pass


def build_read_device_id_request(unit_id: int = 1, transaction_id: int | None = None) -> bytes:
    if not 1 <= unit_id <= 247:
        raise ValueError("Unit ID must be between 1 and 247; broadcast is not supported")
    tid = secrets.randbelow(0x10000) if transaction_id is None else transaction_id
    pdu = bytes((0x2B, 0x0E, 0x01, 0x00))  # Read Device Identification, Basic, VendorName object.
    mbap = struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def parse_device_id_adu(response: bytes, expected_transaction_id: int, expected_unit_id: int) -> dict[str, Any]:
    if len(response) < 8:
        raise ModbusProtocolError("Response is shorter than a Modbus/TCP header and PDU")
    tid, protocol_id, length = struct.unpack(">HHH", response[:6])
    unit_id = response[6]
    if tid != expected_transaction_id:
        raise ModbusProtocolError("Transaction ID mismatch")
    if protocol_id != 0:
        raise ModbusProtocolError("Protocol ID is not zero")
    if length < 2 or length > 254 or len(response) != 6 + length:
        raise ModbusProtocolError("Invalid Modbus/TCP length field")
    if unit_id != expected_unit_id:
        raise ModbusProtocolError("Unit ID mismatch")
    pdu = response[7:]
    from plcsec.parsers.modbus import parse_device_identification_response

    return parse_device_identification_response(pdu)


def audit_device_identification(
    target: str,
    port: int = 502,
    unit_id: int = 1,
    timeout: float = 2.0,
) -> AssessmentReport:
    """Send exactly one read-device-identification request; no retries or writes."""
    if not 0.2 <= timeout <= 5.0:
        raise ValueError("Timeout must be between 0.2 and 5.0 seconds")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    tid = secrets.randbelow(0x10000)
    request = build_read_device_id_request(unit_id=unit_id, transaction_id=tid)
    report = AssessmentReport.create(
        "active-read-only-modbus-device-identification",
        {"target": target, "port": port, "unit_id": unit_id, "requests_max": 1},
    )
    with socket.create_connection((target, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        header = _recv_exact(sock, 7)
        length = int.from_bytes(header[4:6], "big")
        if length < 2 or length > 254:
            raise ModbusProtocolError(f"Invalid response length: {length}")
        remainder = _recv_exact(sock, length - 1)
        response = header + remainder
    identity = parse_device_id_adu(response, tid, unit_id)
    report.assets.append(Asset(
        ip=target,
        observed_services=[ServiceObservation(protocol="Modbus/TCP", port=port, notes=["Active identity check completed; packet count not measured."])],
    ))
    report.findings.append(Finding(
        finding_id="MODBUS-DEVICE-ID-READ",
        title="Modbus device identification completed",
        severity=Severity.INFO,
        description="A single Modbus Read Device Identification request completed successfully.",
        evidence=identity,
        recommendation="Compare returned vendor, product, and revision strings with the approved asset register.",
        confidence="high",
        source="active-read-only-modbus-device-id",
    ))
    report.metadata["request_function"] = "0x2B/0x0E Read Device Identification"
    report.metadata["writes_sent"] = 0
    report.finish()
    return report


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        block = sock.recv(size - len(chunks))
        if not block:
            raise ModbusProtocolError("Connection closed before the full response arrived")
        chunks.extend(block)
    return bytes(chunks)
