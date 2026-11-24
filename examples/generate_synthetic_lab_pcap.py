#!/usr/bin/env python3
"""Create a synthetic offline OT PCAP fixture; this script transmits no packets."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path


def _modbus_device_id_response() -> bytes:
    pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x01, 0x00, 0x07]) + b"PLC-LAB"
    body = bytes([0x01]) + pdu
    return struct.pack(">HHH", 1, 0, len(body)) + body


def _s7_setup_request() -> bytes:
    params = bytes([0xF0, 0x00, 0x00, 0x04, 0x00, 0x04, 0x01, 0xE0])
    s7 = bytes([0x32, 0x01, 0, 0, 0, 1]) + len(params).to_bytes(2, "big") + b"\x00\x00" + params
    cotp = bytes([0x02, 0xF0, 0x80])
    frame = cotp + s7
    return b"\x03\x00" + (4 + len(frame)).to_bytes(2, "big") + frame


def _opcua_hello() -> bytes:
    endpoint = b"opc.tcp://192.0.2.10:4840/PLCSEC-LAB"
    body = b"".join(value.to_bytes(4, "little") for value in (0, 65536, 65536, 4 * 1024 * 1024, 64, len(endpoint))) + endpoint
    return b"HELF" + (8 + len(body)).to_bytes(4, "little") + body


def _enip_register_session() -> bytes:
    data = b"\x01\x00\x00\x00"
    return struct.pack("<HHII8sI", 0x0065, len(data), 0, 0, b"PLCSECLAB", 0) + data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("synthetic-ot-lab.pcap"))
    args = parser.parse_args()
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError as exc:
        raise SystemExit("Scapy is required only to write the fixture: pip install 'plcsec[pcap]'") from exc

    packets = []
    flows = [
        (51514, 502, _modbus_device_id_response()),
        (51515, 102, _s7_setup_request()),
        (51516, 4840, _opcua_hello()),
        (51517, 44818, _enip_register_session()),
    ]
    sequence = 1000
    for source_port, destination_port, payload in flows:
        packet = (
            Ether(src="02:00:00:00:00:20", dst="02:00:00:00:00:10")
            / IP(src="198.51.100.20", dst="192.0.2.10")
            / TCP(sport=source_port, dport=destination_port, flags="PA", seq=sequence, ack=1)
            / Raw(load=payload)
        )
        packets.append(packet)
        sequence += len(payload)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(args.out), packets)
    print(f"Wrote {len(packets)} synthetic Ethernet/IP/TCP packets to {args.out}")
    print("Documentation-only address space is used; no network packets were transmitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
