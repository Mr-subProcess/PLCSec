from __future__ import annotations

from dataclasses import dataclass
from typing import Any

FUNCTION_NAMES: dict[int, str] = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0B: "Get Comm Event Counter",
    0x0C: "Get Comm Event Log",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x18: "Read FIFO Queue",
    0x2B: "Encapsulated Interface Transport",
}

WRITE_FUNCTIONS = {0x05, 0x06, 0x0F, 0x10, 0x15, 0x16, 0x17}
READ_FUNCTIONS = {0x01, 0x02, 0x03, 0x04, 0x14, 0x17, 0x18}


@dataclass(frozen=True, slots=True)
class ModbusFrame:
    transaction_id: int
    unit_id: int
    function_code: int
    function_name: str
    pdu: bytes
    is_exception: bool


@dataclass(frozen=True, slots=True)
class ModbusStreamResult:
    frames: tuple[ModbusFrame, ...]
    trailing_bytes: int
    malformed_headers: int


def parse_mbap(payload: bytes) -> ModbusFrame | None:
    """Parse the first complete Modbus/TCP ADU from a byte sequence."""
    if len(payload) < 8:
        return None
    transaction_id = int.from_bytes(payload[0:2], "big")
    protocol_id = int.from_bytes(payload[2:4], "big")
    length = int.from_bytes(payload[4:6], "big")
    if protocol_id != 0 or length < 2 or length > 254 or len(payload) < 6 + length:
        return None
    unit_id = payload[6]
    pdu = payload[7 : 6 + length]
    if not pdu:
        return None
    function_code = pdu[0]
    is_exception = bool(function_code & 0x80)
    base_code = function_code & 0x7F if is_exception else function_code
    return ModbusFrame(
        transaction_id=transaction_id,
        unit_id=unit_id,
        function_code=function_code,
        function_name=FUNCTION_NAMES.get(base_code, f"Unknown function 0x{base_code:02X}"),
        pdu=pdu,
        is_exception=is_exception,
    )


def parse_mbap_stream(payload: bytes, *, max_frames: int = 4096, max_resync: int = 64) -> ModbusStreamResult:
    """Extract multiple complete MBAP frames from a reassembled TCP byte stream.

    Incomplete trailing bytes are not treated as malformed. Limited resync is
    used only after an invalid MBAP candidate; all skipped bytes are counted.
    """
    frames: list[ModbusFrame] = []
    offset = 0
    malformed = 0
    while offset + 7 <= len(payload) and len(frames) < max_frames:
        protocol_id = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        length = int.from_bytes(payload[offset + 4 : offset + 6], "big")
        valid_header = protocol_id == 0 and 2 <= length <= 254
        if not valid_header:
            malformed += 1
            found = None
            upper = min(len(payload) - 7, offset + max_resync)
            for candidate in range(offset + 1, upper + 1):
                candidate_protocol = int.from_bytes(payload[candidate + 2 : candidate + 4], "big")
                candidate_length = int.from_bytes(payload[candidate + 4 : candidate + 6], "big")
                if candidate_protocol == 0 and 2 <= candidate_length <= 254:
                    found = candidate
                    break
            if found is None:
                break
            offset = found
            continue
        total_length = 6 + length
        if offset + total_length > len(payload):
            break
        frame = parse_mbap(payload[offset : offset + total_length])
        if frame is None:
            malformed += 1
            offset += 1
            continue
        frames.append(frame)
        offset += total_length
    return ModbusStreamResult(tuple(frames), len(payload) - offset, malformed)


def parse_device_identification_response(pdu: bytes) -> dict[str, Any]:
    """Parse a Modbus 0x2B/0x0E Read Device Identification response PDU."""
    if len(pdu) < 7 or pdu[0] != 0x2B or pdu[1] != 0x0E:
        raise ValueError("Not a valid Read Device Identification response PDU")
    if pdu[2] & 0x80:
        code = pdu[2] & 0x7F
        raise ValueError(f"Modbus exception response for function 0x2B (code 0x{code:02X})")
    conformity, more_follows, next_object_id, count = pdu[3:7]
    offset = 7
    objects: dict[str, str | int] = {}
    for _ in range(count):
        if offset + 2 > len(pdu):
            raise ValueError("Truncated device-identification object header")
        object_id, object_len = pdu[offset], pdu[offset + 1]
        offset += 2
        if offset + object_len > len(pdu):
            raise ValueError("Truncated device-identification object value")
        raw = pdu[offset : offset + object_len]
        offset += object_len
        try:
            value: str | int = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            value = raw.hex()
        objects[f"object_{object_id}"] = value
    if offset != len(pdu):
        # Extra bytes are retained as a bounded hex string for forensic transparency.
        objects["trailing_bytes_hex"] = pdu[offset:].hex()
    return {
        "conformity_level": conformity,
        "more_follows": more_follows,
        "next_object_id": next_object_id,
        "object_count": count,
        "objects": objects,
    }
