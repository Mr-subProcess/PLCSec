from __future__ import annotations

from dataclasses import dataclass, field


ENCAP_COMMANDS = {
    0x0004: "ListServices",
    0x0063: "ListIdentity",
    0x0064: "ListInterfaces",
    0x0065: "RegisterSession",
    0x0066: "UnregisterSession",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
    0x0072: "IndicateStatus",
    0x0073: "Cancel",
}

CIP_SERVICES = {
    0x01: "Get_Attributes_All",
    0x05: "Reset",
    0x0A: "Multiple_Service_Packet",
    0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single",
    0x4C: "Read_Tag",
    0x4D: "Write_Tag",
    0x52: "Unconnected_Send",
    0x54: "Forward_Open",
    0x5B: "Large_Forward_Open",
}

WRITE_LIKE_CIP_SERVICES = {0x05, 0x10, 0x4D}


@dataclass(frozen=True, slots=True)
class CIPObservation:
    service_code: int
    service_name: str
    is_response: bool
    general_status: int | None = None
    additional_status_words: tuple[int, ...] = ()
    write_like_request: bool = False
    path_size_words: int | None = None
    class_id: int | None = None
    instance_id: int | None = None
    attribute_id: int | None = None
    request_data_length: int = 0


@dataclass(frozen=True, slots=True)
class IdentityInfo:
    vendor_id: int
    device_type: int
    product_code: int
    revision_major: int
    revision_minor: int
    status: int
    serial_number: int
    product_name: str
    state: int


@dataclass(frozen=True, slots=True)
class EncapFrame:
    command: int
    command_name: str
    session_handle: int
    status: int
    data_length: int
    cip_messages: tuple[CIPObservation, ...] = ()
    identity: IdentityInfo | None = None


@dataclass(frozen=True, slots=True)
class EnipStreamResult:
    frames: tuple[EncapFrame, ...]
    trailing_bytes: int
    malformed_frames: int


def parse_enip_stream(payload: bytes, *, max_frames: int = 2048) -> EnipStreamResult:
    frames: list[EncapFrame] = []
    offset = 0
    malformed = 0
    while offset + 24 <= len(payload) and len(frames) < max_frames:
        command = int.from_bytes(payload[offset : offset + 2], "little")
        length = int.from_bytes(payload[offset + 2 : offset + 4], "little")
        if command not in ENCAP_COMMANDS or length > 65_511:
            # Limited marker search; EtherNet/IP has no magic marker, so only known command IDs qualify.
            malformed += 1
            candidate = _find_valid_header(payload, offset + 1, min(len(payload), offset + 256))
            if candidate is None:
                break
            offset = candidate
            continue
        frame_end = offset + 24 + length
        if frame_end > len(payload):
            break
        session = int.from_bytes(payload[offset + 4 : offset + 8], "little")
        status = int.from_bytes(payload[offset + 8 : offset + 12], "little")
        data = payload[offset + 24 : frame_end]
        identity = parse_list_identity(data) if command == 0x0063 else None
        cip_messages = parse_cpf_cip(data) if command in (0x006F, 0x0070) else ()
        frames.append(EncapFrame(
            command=command,
            command_name=ENCAP_COMMANDS[command],
            session_handle=session,
            status=status,
            data_length=length,
            cip_messages=cip_messages,
            identity=identity,
        ))
        offset = frame_end
    return EnipStreamResult(tuple(frames), len(payload) - offset, malformed)


def _find_valid_header(payload: bytes, start: int, stop: int) -> int | None:
    for candidate in range(start, max(start, stop - 23)):
        command = int.from_bytes(payload[candidate : candidate + 2], "little")
        length = int.from_bytes(payload[candidate + 2 : candidate + 4], "little")
        if command in ENCAP_COMMANDS and length <= 65_511:
            return candidate
    return None


def parse_cpf_cip(data: bytes) -> tuple[CIPObservation, ...]:
    """Parse bounded CPF items in SendRRData/SendUnitData encapsulation payloads."""
    if len(data) < 8:
        return ()
    # Interface handle (4), timeout (2), item count (2).
    item_count = int.from_bytes(data[6:8], "little")
    if item_count > 128:
        return ()
    offset = 8
    observations: list[CIPObservation] = []
    for _ in range(item_count):
        if offset + 4 > len(data):
            break
        item_type = int.from_bytes(data[offset : offset + 2], "little")
        item_len = int.from_bytes(data[offset + 2 : offset + 4], "little")
        offset += 4
        if offset + item_len > len(data):
            break
        item_data = data[offset : offset + item_len]
        offset += item_len
        if item_type == 0x00B2:  # Unconnected Data Item.
            observation = parse_cip_message(item_data)
            if observation:
                observations.append(observation)
        elif item_type == 0x00B1:  # Connected Data Item; first two bytes are sequence count.
            if len(item_data) >= 3:
                observation = parse_cip_message(item_data[2:])
                if observation:
                    observations.append(observation)
    return tuple(observations)


def _parse_cip_logical_path(path: bytes) -> tuple[int | None, int | None, int | None]:
    class_id = instance_id = attribute_id = None
    offset = 0
    while offset < len(path):
        segment = path[offset]
        segment_type = segment & 0xE0
        logical_type = segment & 0x1C
        fmt = segment & 0x03
        offset += 1
        # Logical segments: class=0x00, instance=0x04, attribute=0x10.
        if segment_type != 0x20:
            # Port, network, electronic-key and other segment types are intentionally opaque.
            if fmt == 1 and offset < len(path):
                offset += 1
            elif fmt == 2 and offset + 2 <= len(path):
                offset += 2
            elif fmt == 3 and offset + 4 <= len(path):
                offset += 4
            continue
        width = {0: 1, 1: 2, 2: 4}.get(fmt)
        if width is None:
            return class_id, instance_id, attribute_id
        if width > 1:
            if offset >= len(path) or path[offset] != 0:
                return class_id, instance_id, attribute_id
            offset += 1
        if offset + width > len(path):
            return class_id, instance_id, attribute_id
        value = int.from_bytes(path[offset : offset + width], "little")
        offset += width
        if logical_type == 0x00:
            class_id = value
        elif logical_type == 0x04:
            instance_id = value
        elif logical_type == 0x10:
            attribute_id = value
    return class_id, instance_id, attribute_id


def parse_cip_message(data: bytes) -> CIPObservation | None:
    if not data:
        return None
    service = data[0]
    is_response = bool(service & 0x80)
    base_service = service & 0x7F if is_response else service
    general_status: int | None = None
    additional: tuple[int, ...] = ()
    path_size: int | None = None
    class_id = instance_id = attribute_id = None
    request_data_length = 0
    if is_response:
        if len(data) < 4:
            return None
        additional_count = data[3]
        end = 4 + additional_count * 2
        if end > len(data):
            return None
        additional = tuple(int.from_bytes(data[i : i + 2], "little") for i in range(4, end, 2))
        general_status = data[2]
        request_data_length = max(0, len(data) - end)
    else:
        if len(data) >= 2:
            path_size = data[1]
            path_bytes = path_size * 2
            if path_size <= 64 and 2 + path_bytes <= len(data):
                class_id, instance_id, attribute_id = _parse_cip_logical_path(data[2 : 2 + path_bytes])
                request_data_length = len(data) - (2 + path_bytes)
            else:
                path_size = None
                request_data_length = max(0, len(data) - 2)
    return CIPObservation(
        service_code=base_service,
        service_name=CIP_SERVICES.get(base_service, f"Unknown service 0x{base_service:02X}"),
        is_response=is_response,
        general_status=general_status,
        additional_status_words=additional,
        write_like_request=not is_response and base_service in WRITE_LIKE_CIP_SERVICES,
        path_size_words=path_size,
        class_id=class_id,
        instance_id=instance_id,
        attribute_id=attribute_id,
        request_data_length=request_data_length,
    )


def parse_list_identity(data: bytes) -> IdentityInfo | None:
    """Parse the common ListIdentity CPF response item without retaining raw packet bytes."""
    if len(data) < 8:
        return None
    count = int.from_bytes(data[6:8], "little")
    offset = 8
    for _ in range(min(count, 32)):
        if offset + 4 > len(data):
            return None
        item_type = int.from_bytes(data[offset : offset + 2], "little")
        item_len = int.from_bytes(data[offset + 2 : offset + 4], "little")
        offset += 4
        if offset + item_len > len(data):
            return None
        item = data[offset : offset + item_len]
        offset += item_len
        if item_type != 0x000C:
            continue
        # Encapsulation protocol version (2) + sockaddr (16), followed by identity fields.
        if len(item) < 33:
            return None
        pos = 18
        vendor = int.from_bytes(item[pos : pos + 2], "little")
        device_type = int.from_bytes(item[pos + 2 : pos + 4], "little")
        product_code = int.from_bytes(item[pos + 4 : pos + 6], "little")
        revision_major, revision_minor = item[pos + 6], item[pos + 7]
        status = int.from_bytes(item[pos + 8 : pos + 10], "little")
        serial = int.from_bytes(item[pos + 10 : pos + 14], "little")
        name_len = item[pos + 14]
        name_start = pos + 15
        if name_start + name_len + 1 > len(item):
            return None
        name = item[name_start : name_start + name_len].decode("ascii", errors="replace")
        state = item[name_start + name_len]
        return IdentityInfo(vendor, device_type, product_code, revision_major, revision_minor, status, serial, name, state)
    return None
