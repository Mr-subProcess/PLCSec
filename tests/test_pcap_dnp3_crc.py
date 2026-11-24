import sys
import types
from pathlib import Path

from plcsec.parsers.dnp3 import crc16_dnp
from plcsec.pcap import analyze_capture


def _dnp3_frame(*, corrupt_header_crc: bool = False) -> bytes:
    header = bytes([0x05, 0x64, 6, 0xC3, 1, 0, 2, 0])  # 1 transport byte included in length.
    crc = bytearray(crc16_dnp(header).to_bytes(2, "little"))
    if corrupt_header_crc:
        crc[0] ^= 0x01
    user_data = b"\xC0"
    user_crc = crc16_dnp(user_data).to_bytes(2, "little")
    return header + bytes(crc) + user_data + user_crc


def test_pcap_report_surfaces_dnp3_crc_failure(monkeypatch, tmp_path: Path) -> None:
    class IP: pass
    class IPv6: pass
    class TCP: pass
    class UDP: pass
    class Ether: pass

    class Payload:
        def __init__(self, raw: bytes) -> None:
            self.raw = raw
        def __bytes__(self) -> bytes:
            return self.raw

    class Packet:
        def __init__(self) -> None:
            self.layers = {
                Ether: types.SimpleNamespace(src="02:00:00:00:00:01", dst="02:00:00:00:00:02"),
                IP: types.SimpleNamespace(src="192.0.2.10", dst="192.0.2.20"),
                UDP: types.SimpleNamespace(sport=40000, dport=20000, payload=Payload(_dnp3_frame(corrupt_header_crc=True))),
            }
            self.time = 1.0
        def __contains__(self, layer) -> bool:
            return layer in self.layers
        def __getitem__(self, layer):
            return self.layers[layer]
        def __len__(self) -> int:
            return 100

    class Reader:
        def __init__(self, _path: str) -> None: pass
        def __enter__(self): return iter([Packet()])
        def __exit__(self, *args) -> bool: return False

    fake_scapy = types.SimpleNamespace(IP=IP, IPv6=IPv6, TCP=TCP, UDP=UDP, Ether=Ether, PcapReader=Reader)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy)
    capture = tmp_path / "dnp3.pcap"
    capture.write_bytes(b"synthetic")
    report = analyze_capture(capture)
    assert report.metadata["dnp3_crc_failure_count"] == 1
    finding = next(item for item in report.findings if item.finding_id == "OBS-DNP3-CRC-VALIDATION-FAILURES")
    assert finding.severity.value == "low"
    assert finding.evidence["failure_count"] == 1
    assert any(event.get("event_type") == "crc_validation_failed" for event in report.events)
