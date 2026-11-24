from __future__ import annotations

from dataclasses import dataclass

ASDU_TYPES = {
    1: "M_SP_NA_1 single-point information",
    3: "M_DP_NA_1 double-point information",
    9: "M_ME_NA_1 measured value, normalized",
    13: "M_ME_NC_1 measured value, short floating point",
    30: "M_SP_TB_1 single-point information with CP56Time2a",
    36: "M_ME_TF_1 measured value, short floating point with CP56Time2a",
    45: "C_SC_NA_1 single command",
    46: "C_DC_NA_1 double command",
    48: "C_SE_NA_1 set-point command, normalized",
    50: "C_SE_NC_1 set-point command, short floating point",
    100: "C_IC_NA_1 interrogation command",
    103: "C_CS_NA_1 clock synchronization command",
}

COT_NAMES = {
    1: "periodic",
    2: "background_scan",
    3: "spontaneous",
    4: "initialized",
    5: "request",
    6: "activation",
    7: "activation_confirmation",
    8: "deactivation",
    9: "deactivation_confirmation",
    10: "activation_termination",
    20: "interrogated_by_station",
}


@dataclass(frozen=True, slots=True)
class IEC104Frame:
    frame_type: str
    length: int
    send_sequence: int | None = None
    receive_sequence: int | None = None
    supervisory_function: int | None = None
    asdu_type_id: int | None = None
    asdu_type_name: str | None = None
    vsq: int | None = None
    cause_of_transmission: int | None = None
    common_address: int | None = None
    is_control_asdu: bool = False
    originator_address: int | None = None
    object_count: int | None = None
    sequence_of_elements: bool | None = None
    first_information_object_address: int | None = None
    command_select: bool | None = None
    command_qualifier: int | None = None
    command_value: int | None = None
    cot_name: str | None = None
    negative_confirmation: bool = False


@dataclass(frozen=True, slots=True)
class IEC104StreamResult:
    frames: tuple[IEC104Frame, ...]
    trailing_bytes: int
    malformed_frames: int


def parse_iec104_stream(payload: bytes, *, max_frames: int = 4096) -> IEC104StreamResult:
    if max_frames < 1 or max_frames > 100_000:
        raise ValueError("max_frames must be between 1 and 100000")
    frames: list[IEC104Frame] = []
    offset = 0
    malformed = 0
    while offset + 2 <= len(payload) and len(frames) < max_frames:
        if payload[offset] != 0x68:
            found = payload.find(b"\x68", offset + 1, min(len(payload), offset + 256))
            malformed += 1
            if found < 0:
                break
            offset = found
            continue
        length = payload[offset + 1]
        if length < 4 or length > 253:
            malformed += 1
            offset += 1
            continue
        end = offset + 2 + length
        if end > len(payload):
            break
        frame = payload[offset + 2 : end]
        parsed = _parse_frame(frame, length)
        if parsed is None:
            malformed += 1
            offset = end
            continue
        frames.append(parsed)
        offset = end
    return IEC104StreamResult(tuple(frames), len(payload) - offset, malformed)


def _parse_frame(frame: bytes, length: int) -> IEC104Frame | None:
    if len(frame) < 4:
        return None
    c0, c1, c2, c3 = frame[:4]
    if (c0 & 0x01) == 0:
        send_seq = ((c1 << 8) | c0) >> 1
        receive_seq = ((c3 << 8) | c2) >> 1
        asdu = frame[4:]
        if len(asdu) < 6:
            return IEC104Frame("I", length, send_seq, receive_seq)
        type_id = asdu[0]
        vsq = asdu[1]
        cot_raw = asdu[2]
        cot = cot_raw & 0x3F
        negative = bool(cot_raw & 0x40)
        originator = asdu[3]
        common_address = int.from_bytes(asdu[4:6], "little")
        object_count = vsq & 0x7F
        sequence = bool(vsq & 0x80)
        first_ioa = int.from_bytes(asdu[6:9], "little") if len(asdu) >= 9 else None
        command_select: bool | None = None
        command_qualifier: int | None = None
        command_value: int | None = None
        value_offset = 9 if first_ioa is not None else len(asdu)
        if type_id in {45, 46} and len(asdu) > value_offset:
            command_byte = asdu[value_offset]
            command_select = bool(command_byte & 0x80)
            command_qualifier = (command_byte >> 2) & 0x1F
            command_value = command_byte & 0x03
        elif type_id in {48, 50}:
            value_len = 2 if type_id == 48 else 4
            qualifier_offset = value_offset + value_len
            if len(asdu) > qualifier_offset:
                qualifier = asdu[qualifier_offset]
                command_select = bool(qualifier & 0x80)
                command_qualifier = qualifier & 0x7F
        return IEC104Frame(
            frame_type="I",
            length=length,
            send_sequence=send_seq,
            receive_sequence=receive_seq,
            asdu_type_id=type_id,
            asdu_type_name=ASDU_TYPES.get(type_id, f"Unknown ASDU type {type_id}"),
            vsq=vsq,
            cause_of_transmission=cot,
            common_address=common_address,
            is_control_asdu=type_id in {45, 46, 48, 50, 100, 103},
            originator_address=originator,
            object_count=object_count,
            sequence_of_elements=sequence,
            first_information_object_address=first_ioa,
            command_select=command_select,
            command_qualifier=command_qualifier,
            command_value=command_value,
            cot_name=COT_NAMES.get(cot, f"unknown_{cot}"),
            negative_confirmation=negative,
        )
    if (c0 & 0x03) == 0x01:
        receive_seq = ((c3 << 8) | c2) >> 1
        return IEC104Frame("S", length, None, receive_seq)
    return IEC104Frame("U", length, None, None, c0 & 0xFC)
