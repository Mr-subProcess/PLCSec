from __future__ import annotations

import sys
import types
from pathlib import Path

from plcsec.manufacturers import enrich_report_vendors
from plcsec.pcap import analyze_capture


class _IP: pass
class _IPv6: pass
class _TCP: pass
class _UDP: pass
class _Ether: pass


class _Payload:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
    def __bytes__(self) -> bytes:
        return self.raw


class _Packet:
    def __init__(self, layers: dict[type, object], timestamp: float = 1.0) -> None:
        self.layers = layers
        self.time = timestamp
    def __contains__(self, layer: type) -> bool:
        return layer in self.layers
    def __getitem__(self, layer: type) -> object:
        return self.layers[layer]
    def __len__(self) -> int:
        return 128


def _install_fake_scapy(monkeypatch, packets: list[_Packet]) -> None:
    class Reader:
        def __init__(self, _path: str) -> None:
            pass
        def __enter__(self):
            return iter(packets)
        def __exit__(self, *_args) -> bool:
            return False
    fake = types.SimpleNamespace(IP=_IP, IPv6=_IPv6, TCP=_TCP, UDP=_UDP, Ether=_Ether, PcapReader=Reader)
    monkeypatch.setitem(sys.modules, "scapy.all", fake)


def _tcp_packet(server_port: int, payload: bytes) -> _Packet:
    return _Packet({
        _Ether: types.SimpleNamespace(src="02:00:00:00:00:02", dst="02:00:00:00:00:01"),
        _IP: types.SimpleNamespace(src="192.0.2.20", dst="192.0.2.10"),
        _TCP: types.SimpleNamespace(sport=server_port, dport=41000, seq=1000, flags=0x18, payload=_Payload(payload)),
    })


def test_modbus_device_identification_is_passively_extracted_and_vendor_is_low_confidence(monkeypatch, tmp_path: Path) -> None:
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04]) + b"ACME"
    adu = b"\x00\x01\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + b"\x01" + pdu
    _install_fake_scapy(monkeypatch, [_tcp_packet(502, adu)])
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"synthetic")
    report = analyze_capture(capture)
    event = next(event for event in report.events if event.get("event_type") == "modbus_device_identity")
    assert event["vendor_name"] == "ACME"
    enriched = enrich_report_vendors(report.to_dict())
    server_asset = next(asset for asset in enriched["assets"] if asset["ip"] == "192.0.2.20")
    profile = server_asset["inventory_metadata"].get("plcsec_manufacturer_profile")
    assert profile is not None
    assert profile["manufacturer"] is None
    assert profile["modbus_self_reported_identity"][0]["confidence"] == "low"


def test_opcua_security_policy_observation_becomes_finding(monkeypatch, tmp_path: Path) -> None:
    uri = b"http://opcfoundation.org/UA/SecurityPolicy#None"
    def ua_string(value: bytes | None) -> bytes:
        return (0xFFFFFFFF).to_bytes(4, "little") if value is None else len(value).to_bytes(4, "little") + value
    body = (4).to_bytes(4, "little") + ua_string(uri) + ua_string(None) + ua_string(None) + b"\x01" * 8
    length = 8 + len(body)
    opn = b"OPNF" + length.to_bytes(4, "little") + body
    _install_fake_scapy(monkeypatch, [_tcp_packet(4840, opn)])
    capture = tmp_path / "opcua.pcap"
    capture.write_bytes(b"synthetic")
    report = analyze_capture(capture)
    assert any(f.finding_id.startswith("OPCUA-POLICY-None-") for f in report.findings)
