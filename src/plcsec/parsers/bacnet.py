from __future__ import annotations

from dataclasses import dataclass

BVLC_FUNCTIONS = {
    0x00: "Result",
    0x01: "Write-Broadcast-Distribution-Table",
    0x02: "Read-Broadcast-Distribution-Table",
    0x03: "Read-Broadcast-Distribution-Table-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-Foreign-Device-Table",
    0x07: "Read-Foreign-Device-Table-Ack",
    0x08: "Delete-Foreign-Device-Table-Entry",
    0x09: "Distribute-Broadcast-To-Network",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
}


@dataclass(frozen=True, slots=True)
class BACnetObservation:
    bvlc_type: int
    function: int
    function_name: str
    declared_length: int
    npdu_version: int | None = None
    npdu_control: int | None = None
    apdu_type: int | None = None


def parse_bacnet_datagram(payload: bytes) -> BACnetObservation | None:
    if len(payload) < 4 or payload[0] != 0x81:
        return None
    length = int.from_bytes(payload[2:4], "big")
    if length < 4 or length > len(payload):
        return None
    function = payload[1]
    npdu_offset = 4
    if function == 0x04:  # Forwarded-NPDU includes IPv4 address and UDP port before NPDU.
        npdu_offset += 6
    version = payload[npdu_offset] if length > npdu_offset else None
    control = payload[npdu_offset + 1] if length > npdu_offset + 1 else None
    apdu_type = None
    # Only decode the APDU nibble when no optional DNET/SNET or network-layer
    # message fields shift the APDU offset.
    if version == 1 and control is not None and (control & 0xA8) == 0 and length > npdu_offset + 2:
        apdu_type = payload[npdu_offset + 2] >> 4
    return BACnetObservation(
        0x81, function, BVLC_FUNCTIONS.get(function, f"Unknown BVLC function 0x{function:02X}"),
        length, version, control, apdu_type,
    )
