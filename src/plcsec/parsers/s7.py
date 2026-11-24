from __future__ import annotations

from dataclasses import dataclass


S7_FUNCTIONS = {
    0x04: "Read Variable",
    0x05: "Write Variable",
    0xF0: "Setup Communication",
}


@dataclass(frozen=True, slots=True)
class S7Observation:
    rosctr: int
    pdu_type: str
    reference: int | None
    parameter_length: int = 0
    data_length: int = 0
    function_code: int | None = None
    function_name: str | None = None
    setup_max_jobs_calling: int | None = None
    setup_max_jobs_called: int | None = None
    setup_pdu_length: int | None = None
    variable_item_count: int | None = None
    variable_items: tuple[dict[str, int | str], ...] = ()
    write_like_request: bool = False


@dataclass(frozen=True, slots=True)
class S7StreamResult:
    observations: tuple[S7Observation, ...]
    trailing_bytes: int
    malformed_frames: int


def parse_s7comm_over_tpkt(payload: bytes) -> S7Observation | None:
    """Recognize and parse one S7comm PDU inside a single TPKT/COTP frame."""
    result = parse_s7_stream(payload, max_frames=1)
    return result.observations[0] if result.observations else None


def parse_s7_stream(payload: bytes, *, max_frames: int = 4096) -> S7StreamResult:
    observations: list[S7Observation] = []
    offset = 0
    malformed = 0
    while offset + 4 <= len(payload) and len(observations) < max_frames:
        if payload[offset : offset + 2] != b"\x03\x00":
            # TPKT framing can begin after a capture starts midstream. Search a bounded next marker.
            candidate = payload.find(b"\x03\x00", offset + 1, min(len(payload), offset + 256))
            if candidate < 0:
                malformed += 1
                break
            malformed += 1
            offset = candidate
            continue
        frame_len = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        if frame_len < 7 or frame_len > 65535:
            malformed += 1
            offset += 2
            continue
        if offset + frame_len > len(payload):
            break
        frame = payload[offset : offset + frame_len]
        obs = _parse_tpkt_frame(frame)
        if obs is None:
            malformed += 1
        else:
            observations.append(obs)
        offset += frame_len
    return S7StreamResult(tuple(observations), len(payload) - offset, malformed)


def _parse_tpkt_frame(frame: bytes) -> S7Observation | None:
    if len(frame) < 7 or frame[0:2] != b"\x03\x00":
        return None
    frame_len = int.from_bytes(frame[2:4], "big")
    if frame_len != len(frame):
        return None
    cotp_li = frame[4]
    if cotp_li < 2 or 5 + cotp_li > len(frame):
        return None
    cotp_type = frame[5] & 0xF0
    if cotp_type != 0xF0:  # COTP Data TPDU only; connection setup is not an S7 PDU.
        return None
    s7_offset = 5 + cotp_li
    if s7_offset + 10 > len(frame) or frame[s7_offset] != 0x32:
        return None
    rosctr = frame[s7_offset + 1] & 0x0F
    reference = int.from_bytes(frame[s7_offset + 4 : s7_offset + 6], "big")
    parameter_length = int.from_bytes(frame[s7_offset + 6 : s7_offset + 8], "big")
    data_length = int.from_bytes(frame[s7_offset + 8 : s7_offset + 10], "big")
    pdu_end = s7_offset + 10 + parameter_length + data_length
    if pdu_end > len(frame):
        return None
    params = frame[s7_offset + 10 : s7_offset + 10 + parameter_length]
    function_code = params[0] if params and rosctr in (0x01, 0x07) else None
    setup_calling = setup_called = setup_pdu = None
    variable_count = None
    variable_items: tuple[dict[str, int | str], ...] = ()
    if rosctr == 0x01 and function_code == 0xF0 and len(params) >= 8:
        setup_calling = int.from_bytes(params[2:4], "big")
        setup_called = int.from_bytes(params[4:6], "big")
        setup_pdu = int.from_bytes(params[6:8], "big")
    elif rosctr == 0x01 and function_code in (0x04, 0x05) and len(params) >= 2:
        variable_count = params[1]
        parsed_items: list[dict[str, int | str]] = []
        cursor = 2
        area_names = {0x81: "inputs", 0x82: "outputs", 0x83: "markers", 0x84: "data-block", 0x1C: "counters", 0x1D: "timers"}
        transport_names = {0x01: "BIT", 0x02: "BYTE/WORD/DWORD", 0x03: "INTEGER", 0x04: "DOUBLE-INTEGER", 0x05: "REAL", 0x06: "DATE/TIME", 0x07: "TIME-OF-DAY", 0x08: "TIME", 0x09: "DATE", 0x0A: "CHAR", 0x0B: "WORD", 0x0C: "DWORD", 0x0E: "COUNTER", 0x0F: "TIMER"}
        for _ in range(min(variable_count, 64)):
            item = params[cursor : cursor + 12]
            if len(item) < 12:
                break
            if item[0] != 0x12 or item[1] != 0x0A or item[2] != 0x10:
                break
            transport = item[3]
            amount = int.from_bytes(item[4:6], "big")
            db_number = int.from_bytes(item[6:8], "big")
            area = item[8]
            bit_address = int.from_bytes(item[9:12], "big")
            parsed_items.append({
                "transport_code": transport,
                "transport_name": transport_names.get(transport, f"unknown-0x{transport:02x}"),
                "element_count": amount,
                "db_number": db_number,
                "area_code": area,
                "area_name": area_names.get(area, f"unknown-0x{area:02x}"),
                "bit_address": bit_address,
                "byte_address": bit_address // 8,
                "bit_offset": bit_address % 8,
            })
            cursor += 12
        variable_items = tuple(parsed_items)
    return S7Observation(
        rosctr=rosctr,
        pdu_type={
            0x01: "Job/request",
            0x02: "Ack",
            0x03: "Ack-data/response",
            0x07: "Userdata",
        }.get(rosctr, f"Unknown ROSCTR 0x{rosctr:X}"),
        reference=reference,
        parameter_length=parameter_length,
        data_length=data_length,
        function_code=function_code,
        function_name=S7_FUNCTIONS.get(function_code) if function_code is not None else None,
        setup_max_jobs_calling=setup_calling,
        setup_max_jobs_called=setup_called,
        setup_pdu_length=setup_pdu,
        variable_item_count=variable_count,
        variable_items=variable_items,
        write_like_request=bool(rosctr == 0x01 and function_code == 0x05),
    )
