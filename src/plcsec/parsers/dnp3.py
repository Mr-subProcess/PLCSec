from __future__ import annotations

from dataclasses import dataclass

LINK_FUNCTIONS = {
    0: "RESET_LINK_STATES",
    1: "RESET_USER_PROCESS",
    2: "TEST_LINK_STATES",
    3: "CONFIRMED_USER_DATA",
    4: "UNCONFIRMED_USER_DATA",
    9: "REQUEST_LINK_STATUS",
}


def crc16_dnp(data: bytes) -> int:
    """Return CRC-16/DNP (reflected poly 0xA6BC, init 0, xorout 0xFFFF)."""
    crc = 0
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA6BC if crc & 1 else 0)
    return crc ^ 0xFFFF


def _crc_matches(data: bytes, encoded: bytes) -> bool:
    return len(encoded) == 2 and int.from_bytes(encoded, "little") == crc16_dnp(data)


@dataclass(frozen=True, slots=True)
class DNP3Frame:
    length_field: int
    control: int
    destination: int
    source: int
    direction: bool
    primary: bool
    function_code: int
    function_name: str
    user_data_length: int
    header_crc_valid: bool = False
    data_block_crc_valid: tuple[bool, ...] = ()
    crc_valid: bool = False
    transport_fir: bool | None = None
    transport_fin: bool | None = None
    transport_sequence: int | None = None
    application_data_length: int = 0


@dataclass(frozen=True, slots=True)
class DNP3StreamResult:
    frames: tuple[DNP3Frame, ...]
    trailing_bytes: int
    malformed_frames: int
    crc_errors: int = 0


def parse_dnp3_stream(payload: bytes, *, max_frames: int = 4096) -> DNP3StreamResult:
    """Parse DNP3 link frames and validate the header/data-block CRCs.

    The function deliberately does not reassemble DNP3 transport fragments or
    decode application objects. CRC failures remain visible as observations.
    """
    if max_frames < 1 or max_frames > 100_000:
        raise ValueError("max_frames must be between 1 and 100000")
    frames: list[DNP3Frame] = []
    offset = 0
    malformed = 0
    crc_errors = 0
    while offset + 10 <= len(payload) and len(frames) < max_frames:
        if payload[offset : offset + 2] != b"\x05\x64":
            found = payload.find(b"\x05\x64", offset + 1, min(len(payload), offset + 512))
            malformed += 1
            if found < 0:
                break
            offset = found
            continue
        length = payload[offset + 2]
        if length < 5 or length > 255:
            malformed += 1
            offset += 2
            continue
        user_len = length - 5
        block_count = (user_len + 15) // 16
        total = 10 + user_len + 2 * block_count
        if total > 292:
            malformed += 1
            offset += 2
            continue
        if offset + total > len(payload):
            break

        frame_start = offset
        header = payload[frame_start : frame_start + 8]
        encoded_header_crc = payload[frame_start + 8 : frame_start + 10]
        header_crc_valid = _crc_matches(header, encoded_header_crc)

        user_start = frame_start + 10
        data_blocks: list[bool] = []
        data_offset = user_start
        remaining = user_len
        while remaining:
            block_size = min(16, remaining)
            block = payload[data_offset : data_offset + block_size]
            encoded_crc = payload[data_offset + block_size : data_offset + block_size + 2]
            data_blocks.append(_crc_matches(block, encoded_crc))
            data_offset += block_size + 2
            remaining -= block_size
        all_crc_valid = header_crc_valid and all(data_blocks)
        if not all_crc_valid:
            crc_errors += 1

        control = payload[frame_start + 3]
        destination = int.from_bytes(payload[frame_start + 4 : frame_start + 6], "little")
        source = int.from_bytes(payload[frame_start + 6 : frame_start + 8], "little")
        function = control & 0x0F
        transport_fir = transport_fin = None
        transport_sequence = None
        application_length = 0
        if user_len:
            transport = payload[user_start]
            transport_fir = bool(transport & 0x80)
            transport_fin = bool(transport & 0x40)
            transport_sequence = transport & 0x3F
            application_length = max(0, user_len - 1)

        frames.append(DNP3Frame(
            length_field=length,
            control=control,
            destination=destination,
            source=source,
            direction=bool(control & 0x80),
            primary=bool(control & 0x40),
            function_code=function,
            function_name=LINK_FUNCTIONS.get(function, f"Unknown link function {function}"),
            user_data_length=user_len,
            header_crc_valid=header_crc_valid,
            data_block_crc_valid=tuple(data_blocks),
            crc_valid=all_crc_valid,
            transport_fir=transport_fir,
            transport_fin=transport_fin,
            transport_sequence=transport_sequence,
            application_data_length=application_length,
        ))
        offset += total

    return DNP3StreamResult(tuple(frames), len(payload) - offset, malformed, crc_errors)
