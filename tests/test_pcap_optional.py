from pathlib import Path
import importlib.util
import sys
import types

import pytest

from plcsec.pcap import analyze_capture


def test_pcap_analysis_handles_tcp_split_and_reassembled_modbus(monkeypatch, tmp_path: Path) -> None:
    """Exercise passive capture analysis with a tiny Scapy-compatible fake reader."""
    class IP:
        pass

    class IPv6:
        pass

    class TCP:
        pass

    class UDP:
        pass

    class Ether:
        pass

    class Payload:
        def __init__(self, raw: bytes) -> None:
            self.raw = raw

        def __bytes__(self) -> bytes:
            return self.raw

    class Packet:
        def __init__(self, layers, timestamp: float) -> None:
            self.layers = layers
            self.time = timestamp

        def __contains__(self, layer) -> bool:
            return layer in self.layers

        def __getitem__(self, layer):
            return self.layers[layer]

        def __len__(self) -> int:
            return 100

    class Reader:
        packets = []

        def __init__(self, _path: str) -> None:
            pass

        def __enter__(self):
            return iter(self.packets)

        def __exit__(self, *args) -> bool:
            return False

    adu = bytes.fromhex("000100000006010600010005")
    split = 7
    Reader.packets = [
        Packet({Ether: types.SimpleNamespace(src="02:00:00:00:00:01", dst="02:00:00:00:00:02"),
                IP: types.SimpleNamespace(src="192.0.2.10", dst="192.0.2.20"),
                TCP: types.SimpleNamespace(sport=40000, dport=502, seq=100, flags=0x18, payload=Payload(adu[:split]))}, 1.0),
        Packet({Ether: types.SimpleNamespace(src="02:00:00:00:00:01", dst="02:00:00:00:00:02"),
                IP: types.SimpleNamespace(src="192.0.2.10", dst="192.0.2.20"),
                TCP: types.SimpleNamespace(sport=40000, dport=502, seq=100 + split, flags=0x18, payload=Payload(adu[split:]))}, 2.0),
    ]
    fake_scapy = types.SimpleNamespace(IP=IP, IPv6=IPv6, TCP=TCP, UDP=UDP, Ether=Ether, PcapReader=Reader)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy)
    capture = tmp_path / "synthetic.pcap"
    capture.write_bytes(b"synthetic-capture-placeholder")
    report = analyze_capture(capture)
    assert report.metadata["packet_count"] == 2
    assert report.metadata["tcp_directional_stream_count"] == 1
    assert report.metadata["flow_count"] == 1
    assert report.metadata["write_capable_request_count"] == 1
    assert any(event.get("function_name") == "Write Single Register" for event in report.events)

    bounded_report = analyze_capture(capture, max_assets=1, max_services=1)
    assert len(bounded_report.assets) == 1
    assert bounded_report.metadata["asset_limit_reached"] is True


def test_real_scapy_reader_integration_when_installed(tmp_path: Path) -> None:
    if importlib.util.find_spec("scapy") is None:
        pytest.skip("Scapy is not installed; fake-reader integration test covers analyzer logic")
    from scapy.all import Ether, IP, Raw, TCP, wrpcap

    mbap = bytes.fromhex("000100000006010300000001")
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src="192.0.2.10", dst="192.0.2.20"
    ) / TCP(sport=41000, dport=502, flags="PA", seq=1, ack=1) / Raw(load=mbap)
    path = tmp_path / "modbus.pcap"
    wrpcap(str(path), [packet])
    report = analyze_capture(path)
    assert report.metadata["packet_count"] == 1
    assert report.metadata["asset_count"] == 2
    assert any(f.finding_id.startswith("OBS-CLEARTEXT-OT-") for f in report.findings)
