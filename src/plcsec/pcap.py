from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from typing import Any

from plcsec.models import Asset, AssessmentReport, Finding, FlowObservation, ServiceObservation, Severity
from plcsec.parsers.bacnet import parse_bacnet_datagram
from plcsec.parsers.dnp3 import parse_dnp3_stream
from plcsec.parsers.ethernet_ip import parse_enip_stream
from plcsec.parsers.iec104 import parse_iec104_stream
from plcsec.parsers.modbus import WRITE_FUNCTIONS, parse_device_identification_response, parse_mbap_stream
from plcsec.parsers.opcua import parse_opcua_stream
from plcsec.parsers.s7 import parse_s7_stream
from plcsec.parsers.tls import parse_dtls_datagram, parse_tls_stream
from plcsec.reassembly import TCPSegment, reassemble_tcp_segments

TCP_PORT_PROTOCOLS = {
    502: "Modbus/TCP",
    102: "S7comm (ISO-on-TCP)",
    44818: "EtherNet/IP (CIP)",
    4840: "OPC UA",
    802: "Modbus Security (TLS)",
    2221: "EtherNet/IP Security (TLS)",
    2404: "IEC 60870-5-104",
    20000: "DNP3/TCP",
    1962: "PCWorx (port association only)",
}
UDP_PORT_PROTOCOLS = {
    502: "Modbus/UDP (MBAP observation)",
    2221: "EtherNet/IP Security (DTLS)",
    2222: "EtherNet/IP implicit messaging",
    47808: "BACnet/IP",
    20000: "DNP3/UDP",
    161: "SNMP",
}
MANAGEMENT_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 161: "SNMP", 5900: "VNC"}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def analyze_capture(
    path: str | Path,
    *,
    max_packets: int = 5_000_000,
    max_stream_bytes: int = 4 * 1024 * 1024,
    max_flows: int = 100_000,
    max_assets: int = 100_000,
    max_services: int = 100_000,
    max_segments: int = 250_000,
    max_total_stream_mb: int = 256,
    include_opcua_certificates: bool = False,
) -> AssessmentReport:
    """Passively analyze PCAP/PCAPNG with bounded TCP reassembly and OT parsers.

    No packets are transmitted. Raw application payloads are not included in
    reports; only protocol metadata and selected bounded identity fields are. OPC UA
    public certificate DER is retained only when include_opcua_certificates=True.
    """
    try:
        scapy_all = import_module("scapy.all")
    except ImportError as exc:
        raise RuntimeError("PCAP analysis requires Scapy. Install with: pip install 'plcsec[pcap]'") from exc

    IP, IPv6, TCP, UDP = scapy_all.IP, scapy_all.IPv6, scapy_all.TCP, scapy_all.UDP
    Ether, PcapReader = scapy_all.Ether, scapy_all.PcapReader
    capture = Path(path)
    if not capture.is_file():
        raise FileNotFoundError(capture)
    if max_packets < 1 or max_packets > 20_000_000:
        raise ValueError("max_packets must be between 1 and 20,000,000")
    if max_stream_bytes < 1024 or max_stream_bytes > 64 * 1024 * 1024:
        raise ValueError("max_stream_bytes must be between 1 KiB and 64 MiB")
    if max_flows < 1 or max_flows > 500_000:
        raise ValueError("max_flows must be between 1 and 500,000")
    if max_assets < 1 or max_assets > 1_000_000:
        raise ValueError("max_assets must be between 1 and 1,000,000")
    if max_services < 1 or max_services > 500_000:
        raise ValueError("max_services must be between 1 and 500,000")
    if max_segments < 1 or max_segments > 2_000_000:
        raise ValueError("max_segments must be between 1 and 2,000,000")
    if max_total_stream_mb < 1 or max_total_stream_mb > 4096:
        raise ValueError("max_total_stream_mb must be between 1 and 4096 MiB")

    report = AssessmentReport.create("passive-pcap-analysis", {"capture": str(capture.resolve()), "active_network_requests": 0})
    assets: dict[str, Asset] = {}
    service_map: dict[tuple[str, int, str], ServiceObservation] = {}
    service_flow_sets: dict[tuple[str, int, str], set[tuple[tuple[str, int], tuple[str, int]]]] = defaultdict(set)
    service_flow_pair_count = 0
    segments: list[TCPSegment] = []
    tcp_flow_keys: set[tuple[str, int, str, int]] = set()
    tcp_segments_per_flow: Counter[tuple[str, int, str, int]] = Counter()
    protocol_counts: Counter[str] = Counter()
    modbus_function_counts: Counter[str] = Counter()
    s7_function_counts: Counter[str] = Counter()
    cip_service_counts: Counter[str] = Counter()
    opcua_message_counts: Counter[str] = Counter()
    opcua_security_findings: set[tuple[str, str]] = set()
    write_events: list[dict[str, Any]] = []
    write_event_count = 0
    dnp3_crc_failures: list[dict[str, Any]] = []
    dnp3_crc_failure_count = 0
    protocol_events: list[dict[str, Any]] = []
    protocol_event_count = 0
    flow_bytes: Counter[tuple[str, int, str, int, str]] = Counter()
    flow_packets: Counter[tuple[str, int, str, int, str]] = Counter()
    flow_first: dict[tuple[str, int, str, int, str], float] = {}
    flow_last: dict[tuple[str, int, str, int, str], float] = {}
    total_packets = 0
    total_bytes = 0
    first_ts: float | None = None
    last_ts: float | None = None
    truncated_capture = False
    flow_limit_reached = False
    segment_limit_reached = False
    total_stream_bytes = 0
    total_stream_limit_reached = False
    asset_limit_reached = False
    service_limit_reached = False
    service_flow_limit_reached = False
    mac_observation_limit_reached = False

    def add_protocol_event(event: dict[str, Any]) -> None:
        nonlocal protocol_event_count
        protocol_event_count += 1
        if len(protocol_events) < 5000:
            protocol_events.append(event)

    def add_write_event(event: dict[str, Any]) -> None:
        nonlocal write_event_count
        write_event_count += 1
        if len(write_events) < 500:
            write_events.append(event)

    def observe_service(server_ip: str, server_port: int, protocol: str, client_ip: str, src_ip: str, dst_ip: str, packet_len: int, flow_key: tuple[str, int, str, int]) -> None:
        nonlocal service_limit_reached, service_flow_pair_count, service_flow_limit_reached
        key = (server_ip, server_port, protocol)
        if key not in service_map and len(service_map) >= max_services:
            service_limit_reached = True
            return
        observation = service_map.setdefault(key, ServiceObservation(protocol=protocol, port=server_port))
        observation.packets += 1
        observation.bytes_observed += packet_len
        canonical_flow = tuple(sorted(((flow_key[0], flow_key[1]), (flow_key[2], flow_key[3]))))
        if canonical_flow not in service_flow_sets[key]:
            if service_flow_pair_count < max_flows:
                service_flow_sets[key].add(canonical_flow)
                service_flow_pair_count += 1
            else:
                service_flow_limit_reached = True
        if client_ip == src_ip and server_ip == dst_ip:
            observation.client_to_server += 1
        else:
            observation.server_to_client += 1

    with PcapReader(str(capture)) as reader:
        for packet in reader:
            if total_packets >= max_packets:
                truncated_capture = True
                break
            total_packets += 1
            packet_len = len(packet)
            total_bytes += packet_len
            ts = float(getattr(packet, "time", 0.0))
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)

            if IP in packet:
                ip_layer = packet[IP]
                src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)
            elif IPv6 in packet:
                ip_layer = packet[IPv6]
                src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)
            else:
                continue

            src_mac = str(packet[Ether].src).lower() if Ether in packet else None
            dst_mac = str(packet[Ether].dst).lower() if Ether in packet else None
            for address, mac in ((src_ip, src_mac), (dst_ip, dst_mac)):
                asset = assets.get(address)
                if asset is None:
                    if len(assets) >= max_assets:
                        asset_limit_reached = True
                        continue
                    asset = assets.setdefault(address, Asset(ip=address))
                asset.packets_seen += 1
                if mac and mac not in asset.mac_addresses:
                    if len(asset.mac_addresses) < 32:
                        asset.mac_addresses.append(mac)
                    else:
                        mac_observation_limit_reached = True
                stamp = _iso(ts) if ts else None
                if stamp:
                    if asset.first_seen is None or stamp < asset.first_seen:
                        asset.first_seen = stamp
                    if asset.last_seen is None or stamp > asset.last_seen:
                        asset.last_seen = stamp

            if TCP in packet:
                transport = packet[TCP]
                sport, dport = int(transport.sport), int(transport.dport)
                payload = bytes(transport.payload)
                flow_key = (src_ip, sport, dst_ip, dport)
                flow_id = (src_ip, sport, dst_ip, dport, "tcp")
                if flow_id in flow_packets or len(flow_packets) < max_flows:
                    flow_packets[flow_id] += 1
                    flow_bytes[flow_id] += packet_len
                    flow_first[flow_id] = min(flow_first.get(flow_id, ts), ts)
                    flow_last[flow_id] = max(flow_last.get(flow_id, ts), ts)
                else:
                    flow_limit_reached = True
                if payload:
                    if flow_key not in tcp_flow_keys and len(tcp_flow_keys) >= max_flows:
                        flow_limit_reached = True
                    elif tcp_segments_per_flow[flow_key] >= 100_000:
                        segment_limit_reached = True
                    elif len(segments) >= max_segments or total_stream_bytes + len(payload) > max_total_stream_mb * 1024 * 1024:
                        segment_limit_reached = True
                        total_stream_limit_reached = True
                    else:
                        tcp_flow_keys.add(flow_key)
                        tcp_segments_per_flow[flow_key] += 1
                        total_stream_bytes += len(payload)
                        segments.append(TCPSegment(
                            src=src_ip, dst=dst_ip, sport=sport, dport=dport,
                            seq=int(transport.seq), payload=payload, timestamp=ts,
                            syn=bool(int(transport.flags) & 0x02),
                        ))
                if dport in TCP_PORT_PROTOCOLS:
                    observe_service(dst_ip, dport, TCP_PORT_PROTOCOLS[dport], src_ip, src_ip, dst_ip, packet_len, flow_key)
                elif sport in TCP_PORT_PROTOCOLS:
                    observe_service(src_ip, sport, TCP_PORT_PROTOCOLS[sport], dst_ip, src_ip, dst_ip, packet_len, (dst_ip, dport, src_ip, sport))
                if dport in MANAGEMENT_PORTS:
                    observe_service(dst_ip, dport, MANAGEMENT_PORTS[dport], src_ip, src_ip, dst_ip, packet_len, flow_key)
                elif sport in MANAGEMENT_PORTS:
                    observe_service(src_ip, sport, MANAGEMENT_PORTS[sport], dst_ip, src_ip, dst_ip, packet_len, (dst_ip, dport, src_ip, sport))
            elif UDP in packet:
                transport = packet[UDP]
                sport, dport = int(transport.sport), int(transport.dport)
                flow_key = (src_ip, sport, dst_ip, dport)
                flow_id = (src_ip, sport, dst_ip, dport, "udp")
                if flow_id in flow_packets or len(flow_packets) < max_flows:
                    flow_packets[flow_id] += 1
                    flow_bytes[flow_id] += packet_len
                    flow_first[flow_id] = min(flow_first.get(flow_id, ts), ts)
                    flow_last[flow_id] = max(flow_last.get(flow_id, ts), ts)
                else:
                    flow_limit_reached = True
                if dport in UDP_PORT_PROTOCOLS:
                    observe_service(dst_ip, dport, UDP_PORT_PROTOCOLS[dport], src_ip, src_ip, dst_ip, packet_len, flow_key)
                elif sport in UDP_PORT_PROTOCOLS:
                    observe_service(src_ip, sport, UDP_PORT_PROTOCOLS[sport], dst_ip, src_ip, dst_ip, packet_len, (dst_ip, dport, src_ip, sport))
                udp_payload = bytes(transport.payload)
                if sport == 502 or dport == 502:
                    parsed_modbus_udp = parse_mbap_stream(udp_payload)
                    for frame in parsed_modbus_udp.frames:
                        code = frame.function_code & 0x7F if frame.is_exception else frame.function_code
                        protocol_counts["Modbus/UDP ADUs"] += 1
                        add_protocol_event({
                            "protocol": "Modbus/UDP", "event_type": "request_or_response_function",
                            "client_ip": src_ip if dport == 502 else dst_ip,
                            "server_ip": dst_ip if dport == 502 else src_ip,
                            "function_code": f"0x{code:02X}", "function_name": frame.function_name,
                            "unit_id": frame.unit_id, "transaction_id": frame.transaction_id,
                        })
                        if dport == 502 and code in WRITE_FUNCTIONS and not frame.is_exception:
                            add_write_event({
                                "protocol": "Modbus/UDP", "client_ip": src_ip, "server_ip": dst_ip,
                                "function_code": f"0x{code:02X}", "function_name": frame.function_name,
                                "unit_id": frame.unit_id,
                            })
                if sport == 2221 or dport == 2221:
                    dtls = parse_dtls_datagram(udp_payload)
                    if dtls:
                        protocol_counts["EtherNet/IP Security DTLS records"] += 1
                        add_protocol_event({
                            "protocol": "DTLS", "event_type": "record",
                            "client_ip": src_ip if dport == 2221 else dst_ip,
                            "server_ip": dst_ip if dport == 2221 else src_ip,
                            "content_type": dtls.content_name, "version": dtls.version,
                            "epoch": dtls.epoch, "record_sequence": dtls.record_sequence,
                            "record_length": dtls.record_length,
                        })
                if sport == 47808 or dport == 47808:
                    parsed_bacnet = parse_bacnet_datagram(udp_payload)
                    if parsed_bacnet:
                        server_ip = dst_ip if dport == 47808 else src_ip
                        protocol_counts["BACnet/IP datagrams"] += 1
                        add_protocol_event({
                            "protocol": "BACnet/IP", "event_type": "bvlc_message",
                            "client_ip": src_ip if dport == 47808 else dst_ip,
                            "server_ip": server_ip, "bvlc_function": parsed_bacnet.function_name,
                            "bvlc_function_code": f"0x{parsed_bacnet.function:02X}",
                            "npdu_version": parsed_bacnet.npdu_version,
                            "npdu_control": parsed_bacnet.npdu_control,
                            "apdu_type": parsed_bacnet.apdu_type,
                        })
                if sport == 20000 or dport == 20000:
                    parsed_dnp3 = parse_dnp3_stream(udp_payload)
                    for frame in parsed_dnp3.frames:
                        protocol_counts["DNP3/UDP frames"] += 1
                        add_protocol_event({
                            "protocol": "DNP3/UDP", "event_type": "data_link_frame",
                            "client_ip": src_ip if dport == 20000 else dst_ip,
                            "server_ip": dst_ip if dport == 20000 else src_ip,
                            "source_link_address": frame.source,
                            "destination_link_address": frame.destination,
                            "link_function": frame.function_name,
                            "user_data_length": frame.user_data_length,
                            "header_crc_valid": frame.header_crc_valid,
                            "data_block_crc_valid": list(frame.data_block_crc_valid),
                            "crc_valid": frame.crc_valid,
                            "transport_fir": frame.transport_fir,
                            "transport_fin": frame.transport_fin,
                            "transport_sequence": frame.transport_sequence,
                        })
                        if not frame.crc_valid:
                            dnp3_crc_failure_count += 1
                            if len(dnp3_crc_failures) < 100:
                                dnp3_crc_failures.append({
                                    "transport": "udp", "client_ip": src_ip if dport == 20000 else dst_ip,
                                    "server_ip": dst_ip if dport == 20000 else src_ip,
                                    "source_link_address": frame.source,
                                    "destination_link_address": frame.destination,
                                    "header_crc_valid": frame.header_crc_valid,
                                    "data_block_crc_valid": list(frame.data_block_crc_valid),
                                })
                            add_protocol_event({
                                "protocol": "DNP3/UDP", "event_type": "crc_validation_failed",
                                "client_ip": src_ip if dport == 20000 else dst_ip,
                                "server_ip": dst_ip if dport == 20000 else src_ip,
                                "source_link_address": frame.source,
                                "destination_link_address": frame.destination,
                                "header_crc_valid": frame.header_crc_valid,
                                "data_block_crc_valid": list(frame.data_block_crc_valid),
                            })

    for key, observation in service_map.items():
        server_ip, _, _ = key
        observation.flows_observed = len(service_flow_sets[key])
        if server_ip in assets:
            assets[server_ip].observed_services.append(observation)
            if observation.protocol in {"Modbus/TCP", "Modbus/UDP (MBAP observation)", "S7comm (ISO-on-TCP)", "EtherNet/IP (CIP)", "OPC UA"}:
                label = "ot_protocol_endpoint_observed"
                if label not in assets[server_ip].labels:
                    assets[server_ip].labels.append(label)

    streams, reassembly_stats = reassemble_tcp_segments(
        segments, max_bytes_per_flow=max_stream_bytes, max_segments_per_flow=100_000,
    )
    for stream in streams:
        tls_result = parse_tls_stream(stream.data)
        if tls_result.record_count:
            for handshake in tls_result.handshakes:
                if handshake.handshake_name == "ClientHello":
                    tls_client, tls_server = stream.src, stream.dst
                elif handshake.handshake_name == "ServerHello":
                    tls_client, tls_server = stream.dst, stream.src
                else:
                    tls_client, tls_server = stream.src, stream.dst
                add_protocol_event({
                    "protocol": "TLS", "event_type": "handshake",
                    "client_ip": tls_client, "server_ip": tls_server,
                    "handshake_type": handshake.handshake_name,
                    "legacy_version": handshake.legacy_version,
                    "negotiated_version": handshake.negotiated_version,
                    "cipher_suite": f"0x{handshake.cipher_suite:04X}" if handshake.cipher_suite is not None else None,
                    "server_name": handshake.server_name,
                    "extension_ids": list(handshake.extension_ids),
                })
                if handshake.handshake_name == "ServerHello" and handshake.negotiated_version in {"SSL 3.0", "TLS 1.0", "TLS 1.1"}:
                    report.findings.append(Finding(
                        finding_id=f"TLS-LEGACY-{tls_server}-{handshake.negotiated_version.replace(' ', '-')}",
                        title=f"Legacy TLS version observed: {handshake.negotiated_version}",
                        severity=Severity.MEDIUM if handshake.negotiated_version == "SSL 3.0" else Severity.LOW,
                        description="A server handshake selected a legacy TLS protocol version. Capture visibility and middleboxes can affect interpretation; confirm the actual endpoint configuration and client population.",
                        evidence={"server_ip": tls_server, "client_ip": tls_client, "negotiated_version": handshake.negotiated_version, "cipher_suite": handshake.cipher_suite},
                        recommendation="Review vendor support and compatibility requirements, then plan a controlled migration to a currently supported TLS configuration.",
                        confidence="high", source="pcap.tls-handshake", priority_score=35,
                        tags=["cryptographic-protocol", "legacy-tls"],
                    ))
            protocol_counts["TLS streams"] += 1

        server_port = stream.dport if stream.dport in TCP_PORT_PROTOCOLS else stream.sport if stream.sport in TCP_PORT_PROTOCOLS else None
        if server_port is None:
            continue
        request_direction = stream.dport == server_port
        server_ip = stream.dst if request_direction else stream.src
        client_ip = stream.src if request_direction else stream.dst
        base_event = {
            "client_ip": client_ip,
            "server_ip": server_ip,
            "server_port": server_port,
            "direction": "client_to_server" if request_direction else "server_to_client",
            "stream_bytes": len(stream.data),
            "segment_count": stream.segment_count,
            "retransmissions": stream.retransmissions,
            "overlap_conflicts": stream.overlap_conflicts,
            "sequence_gap_before": stream.sequence_gaps_before,
            "first_seen_utc": _iso(stream.first_timestamp),
            "last_seen_utc": _iso(stream.last_timestamp),
            "stream_truncated": stream.truncated,
        }
        if stream.overlap_conflicts:
            add_protocol_event({**base_event, "protocol": "TCP", "event_type": "overlap_conflict", "count": stream.overlap_conflicts})
        if stream.sequence_gaps_before:
            add_protocol_event({**base_event, "protocol": "TCP", "event_type": "sequence_gap", "count": stream.sequence_gaps_before})

        if server_port == 502:
            parsed = parse_mbap_stream(stream.data)
            protocol_counts["Modbus/TCP streams"] += 1
            if parsed.malformed_headers:
                add_protocol_event({**base_event, "protocol": "Modbus/TCP", "event_type": "malformed_or_resync_headers", "count": parsed.malformed_headers})
            for frame in parsed.frames:
                code = frame.function_code & 0x7F if frame.is_exception else frame.function_code
                name = frame.function_name
                modbus_function_counts[f"0x{code:02X} {name}"] += 1
                event = {
                    **base_event,
                    "protocol": "Modbus/TCP",
                    "event_type": "exception_response" if frame.is_exception else "request_or_response_function",
                    "function_code": f"0x{code:02X}",
                    "function_name": name,
                    "transaction_id": frame.transaction_id,
                    "unit_id": frame.unit_id,
                    "is_exception": frame.is_exception,
                }
                add_protocol_event(event)
                if not request_direction and code == 0x2B and not frame.is_exception:
                    try:
                        device_id = parse_device_identification_response(frame.pdu)
                    except ValueError:
                        device_id = None
                    if device_id is not None:
                        objects = device_id.get("objects", {})
                        vendor_name = objects.get("object_0") if isinstance(objects, dict) else None
                        product_name = objects.get("object_4") if isinstance(objects, dict) else None
                        model_name = objects.get("object_5") if isinstance(objects, dict) else None
                        if server_ip in assets:
                            hint = f"Modbus Device Identification vendor: {vendor_name}" if vendor_name else None
                            if hint and hint not in assets[server_ip].vendor_hints and len(assets[server_ip].vendor_hints) < 32:
                                assets[server_ip].vendor_hints.append(hint)
                        add_protocol_event({
                            **base_event,
                            "protocol": "Modbus/TCP",
                            "event_type": "modbus_device_identity",
                            "transaction_id": frame.transaction_id,
                            "unit_id": frame.unit_id,
                            "conformity_level": device_id.get("conformity_level"),
                            "vendor_name": vendor_name,
                            "product_name": product_name,
                            "model_name": model_name,
                            "objects": objects,
                            "identity_source": "device-self-reported-modbus-object-dictionary",
                        })
                if request_direction and code in WRITE_FUNCTIONS and not frame.is_exception:
                    add_write_event({
                        "protocol": "Modbus/TCP", "client_ip": client_ip, "server_ip": server_ip,
                        "unit_id": frame.unit_id, "function_code": f"0x{code:02X}",
                        "function_name": name, "transaction_id": frame.transaction_id,
                    })
        elif server_port == 102:
            parsed = parse_s7_stream(stream.data)
            protocol_counts["S7comm streams"] += 1
            for observation in parsed.observations:
                s7_function = observation.function_name or observation.pdu_type
                s7_function_counts[s7_function] += 1
                event = {
                    **base_event,
                    "protocol": "S7comm",
                    "event_type": "s7_pdu",
                    "rosctr": observation.rosctr,
                    "pdu_type": observation.pdu_type,
                    "pdu_reference": observation.reference,
                    "parameter_length": observation.parameter_length,
                    "data_length": observation.data_length,
                    "function_code": observation.function_code,
                    "function_name": observation.function_name,
                    "setup_max_jobs_calling": observation.setup_max_jobs_calling,
                    "setup_max_jobs_called": observation.setup_max_jobs_called,
                    "setup_pdu_length": observation.setup_pdu_length,
                    "variable_item_count": observation.variable_item_count,
                    "variable_items": list(observation.variable_items),
                    "write_like_request": observation.write_like_request,
                }
                add_protocol_event(event)
                if request_direction and observation.rosctr == 0x01 and observation.function_code == 0x05:
                    add_write_event({
                        "protocol": "S7comm", "client_ip": client_ip, "server_ip": server_ip,
                        "function_code": "0x05", "function_name": "Write Variable",
                        "pdu_reference": observation.reference,
                    })
            if parsed.malformed_frames:
                add_protocol_event({**base_event, "protocol": "S7comm", "event_type": "malformed_frames", "count": parsed.malformed_frames})
        elif server_port == 44818:
            parsed = parse_enip_stream(stream.data)
            protocol_counts["EtherNet/IP streams"] += 1
            for frame in parsed.frames:
                add_protocol_event({
                    **base_event, "protocol": "EtherNet/IP", "event_type": "encapsulation_command",
                    "command": f"0x{frame.command:04X}", "command_name": frame.command_name,
                    "status": frame.status, "data_length": frame.data_length,
                })
                identity = frame.identity
                if identity:
                    if server_ip in assets:
                        vendor_hint = f"CIP vendor {identity.vendor_id} / {identity.product_name}"
                        if vendor_hint not in assets[server_ip].vendor_hints and len(assets[server_ip].vendor_hints) < 32:
                            assets[server_ip].vendor_hints.append(vendor_hint)
                    add_protocol_event({
                        **base_event, "protocol": "EtherNet/IP", "event_type": "list_identity",
                        "vendor_id": identity.vendor_id, "device_type": identity.device_type,
                        "product_code": identity.product_code,
                        "revision": f"{identity.revision_major}.{identity.revision_minor}",
                        "serial_number": identity.serial_number, "product_name": identity.product_name,
                        "state": identity.state,
                    })
                for cip in frame.cip_messages:
                    cip_service_counts[cip.service_name] += 1
                    add_protocol_event({
                        **base_event, "protocol": "CIP", "event_type": "cip_service",
                        "service_code": f"0x{cip.service_code:02X}", "service_name": cip.service_name,
                        "is_response": cip.is_response, "general_status": cip.general_status,
                        "additional_status_words": list(cip.additional_status_words),
                        "path_size_words": cip.path_size_words,
                        "class_id": cip.class_id,
                        "instance_id": cip.instance_id,
                        "attribute_id": cip.attribute_id,
                        "request_data_length": cip.request_data_length,
                        "write_like_request": cip.write_like_request,
                    })
                    if request_direction and cip.write_like_request:
                        add_write_event({
                            "protocol": "CIP", "client_ip": client_ip, "server_ip": server_ip,
                            "service_code": f"0x{cip.service_code:02X}", "service_name": cip.service_name,
                        })
            if parsed.malformed_frames:
                add_protocol_event({**base_event, "protocol": "EtherNet/IP", "event_type": "malformed_frames", "count": parsed.malformed_frames})
        elif server_port == 2404:
            parsed = parse_iec104_stream(stream.data)
            protocol_counts["IEC 60870-5-104 streams"] += 1
            for frame in parsed.frames:
                add_protocol_event({
                    **base_event, "protocol": "IEC 60870-5-104", "event_type": "apdu",
                    "frame_type": frame.frame_type, "send_sequence": frame.send_sequence,
                    "receive_sequence": frame.receive_sequence, "asdu_type_id": frame.asdu_type_id,
                    "asdu_type": frame.asdu_type_name, "vsq": frame.vsq,
                    "cause_of_transmission": frame.cause_of_transmission,
                    "common_address": frame.common_address,
                    "originator_address": frame.originator_address,
                    "object_count": frame.object_count,
                    "sequence_of_elements": frame.sequence_of_elements,
                    "first_information_object_address": frame.first_information_object_address,
                    "command_select": frame.command_select,
                    "command_qualifier": frame.command_qualifier,
                    "command_value": frame.command_value,
                    "cause_of_transmission_name": frame.cot_name,
                    "negative_confirmation": frame.negative_confirmation,
                    "is_control_asdu": frame.is_control_asdu,
                })
                if request_direction and frame.is_control_asdu:
                    add_write_event({
                        "protocol": "IEC 60870-5-104", "client_ip": client_ip,
                        "server_ip": server_ip, "asdu_type_id": frame.asdu_type_id,
                        "asdu_type": frame.asdu_type_name,
                        "common_address": frame.common_address,
                        "originator_address": frame.originator_address,
                        "first_information_object_address": frame.first_information_object_address,
                        "command_select": frame.command_select,
                        "command_qualifier": frame.command_qualifier,
                        "command_value": frame.command_value,
                        "cause_of_transmission": frame.cause_of_transmission,
                    })
            if parsed.malformed_frames:
                add_protocol_event({**base_event, "protocol": "IEC 60870-5-104", "event_type": "malformed_frames", "count": parsed.malformed_frames})
        elif server_port == 20000:
            parsed = parse_dnp3_stream(stream.data)
            protocol_counts["DNP3/TCP streams"] += 1
            for frame in parsed.frames:
                add_protocol_event({
                    **base_event, "protocol": "DNP3/TCP", "event_type": "data_link_frame",
                    "source_link_address": frame.source,
                    "destination_link_address": frame.destination,
                    "link_function": frame.function_name,
                    "direction": frame.direction,
                    "primary": frame.primary,
                    "user_data_length": frame.user_data_length,
                    "header_crc_valid": frame.header_crc_valid,
                    "data_block_crc_valid": list(frame.data_block_crc_valid),
                    "crc_valid": frame.crc_valid,
                    "transport_fir": frame.transport_fir,
                    "transport_fin": frame.transport_fin,
                    "transport_sequence": frame.transport_sequence,
                })
                if not frame.crc_valid:
                    dnp3_crc_failure_count += 1
                    if len(dnp3_crc_failures) < 100:
                        dnp3_crc_failures.append({
                            "transport": "tcp", "src_ip": stream.src, "dst_ip": stream.dst,
                            "source_link_address": frame.source,
                            "destination_link_address": frame.destination,
                            "header_crc_valid": frame.header_crc_valid,
                            "data_block_crc_valid": list(frame.data_block_crc_valid),
                        })
                    add_protocol_event({
                        **base_event, "protocol": "DNP3/TCP", "event_type": "crc_validation_failed",
                        "source_link_address": frame.source,
                        "destination_link_address": frame.destination,
                        "header_crc_valid": frame.header_crc_valid,
                        "data_block_crc_valid": list(frame.data_block_crc_valid),
                    })
        elif server_port == 4840:
            parsed = parse_opcua_stream(stream.data)
            protocol_counts["OPC UA streams"] += 1
            for frame in parsed.frames:
                opcua_message_counts[f"{frame.message_type}/{frame.chunk_type}"] += 1
                add_protocol_event({
                    **base_event, "protocol": "OPC UA", "event_type": "uacp_message",
                    "message_type": frame.message_type, "chunk_type": frame.chunk_type,
                    "message_length": frame.message_length, "endpoint_url": frame.endpoint_url,
                    "protocol_version": frame.protocol_version,
                    "peer_max_message_size": frame.max_message_size,
                    "peer_max_chunk_count": frame.max_chunk_count,
                    "secure_channel_id": frame.secure_channel_id,
                    "security_policy_uri": frame.security_policy_uri,
                    "security_policy_name": frame.security_policy_name,
                    "policy_assessment": frame.policy_assessment,
                    "sender_certificate_sha256": frame.sender_certificate_sha256,
                    "sender_certificate_subject": frame.sender_certificate_subject,
                    "sender_certificate_issuer": frame.sender_certificate_issuer,
                    "sender_certificate_not_after": frame.sender_certificate_not_after,
                    "certificate_parse_status": frame.certificate_parse_status,
                    **({"sender_certificate_der_base64": frame.sender_certificate_der_base64} if include_opcua_certificates and frame.sender_certificate_der_base64 else {}),
                })
                if frame.policy_assessment in {"no-message-security-policy-observed", "deprecated-policy-observed"}:
                    policy_name = frame.security_policy_name or "unknown"
                    add_protocol_event({
                        **base_event,
                        "protocol": "OPC UA",
                        "event_type": "security_policy_observation",
                        "security_policy": policy_name,
                        "assessment": frame.policy_assessment,
                    })
                    finding_key = (server_ip, policy_name)
                    if finding_key not in opcua_security_findings:
                        opcua_security_findings.add(finding_key)
                        is_none = frame.policy_assessment == "no-message-security-policy-observed"
                        report.findings.append(Finding(
                            finding_id=f"OPCUA-POLICY-{policy_name}-{server_ip}",
                            title=("OPC UA SecurityPolicy None observed" if is_none else f"Deprecated OPC UA SecurityPolicy observed: {policy_name}"),
                            severity=Severity.MEDIUM if is_none else Severity.LOW,
                            description=(
                                "An OPC UA OPN message exposed SecurityPolicy#None in its asymmetric security header. This indicates no OPC UA message security policy for that OpenSecureChannel message; it does not by itself describe every endpoint offered by the server."
                                if is_none else
                                f"An OPC UA OPN message exposed the deprecated policy {policy_name}. The observation is limited to this captured channel and does not establish all server endpoint configurations."
                            ),
                            evidence={"server_ip": server_ip, "security_policy": policy_name, "security_policy_uri": frame.security_policy_uri, "sender_certificate_sha256": frame.sender_certificate_sha256},
                            recommendation="Review the server's configured endpoints and approved OPC UA security profile. Prefer supported Sign or SignAndEncrypt endpoints with current SecurityPolicies where the application and vendor support them; validate compatibility before changes.",
                            confidence="high", source="pcap.opcua-opn-security-header", priority_score=45 if is_none else 30,
                            tags=["opcua-security", "certificate" if frame.sender_certificate_sha256 else "security-policy"],
                            references=["https://reference.opcfoundation.org/specs/OPC-10000-4/full"],
                        ))

    # Passive observations are deliberately phrased as exposure indicators, never as exploitability claims.
    for (ip, port, protocol), observation in sorted(service_map.items()):
        if protocol in MANAGEMENT_PORTS.values():
            severity = Severity.LOW if protocol in {"Telnet", "FTP"} else Severity.INFO
            report.findings.append(Finding(
                finding_id=f"OBS-MGMT-{port}-{ip}",
                title=f"Management service traffic observed: {protocol}",
                severity=severity,
                description="The capture contains traffic involving a common management service. This does not prove exposure beyond the observed capture path.",
                evidence={"asset": ip, "port": port, "protocol": protocol, "packets": observation.packets},
                recommendation="Verify that the service is necessary and restricted to approved engineering and administration paths.",
                confidence="medium", source="pcap.passive-observation", priority_score=20 if severity == Severity.LOW else 5,
                tags=["management-plane", "passive-observation"],
            ))
        if protocol in {"Modbus/TCP", "Modbus/UDP (MBAP observation)", "S7comm (ISO-on-TCP)", "EtherNet/IP (CIP)", "IEC 60870-5-104"}:
            report.findings.append(Finding(
                finding_id=f"OBS-CLEARTEXT-OT-{port}-{ip}",
                title=f"Classic OT protocol traffic observed: {protocol}",
                severity=Severity.LOW,
                description="Traffic for this classic OT protocol was observed. This capture does not establish whether transport protection, network segmentation, secure gateways, or compensating controls protect the communication path.",
                evidence={"asset": ip, "port": port, "protocol": protocol, "packets": observation.packets},
                recommendation="Review conduit segmentation, engineering workstation access, protocol security extensions, and monitoring. Do not change production configurations without an approved change process.",
                confidence="high", source="pcap.passive-observation", priority_score=25,
                tags=["industrial-protocol", "cleartext-observation", "defense-in-depth"],
                references=["https://www.nist.gov/publications/guide-operational-technology-ot-security"],
            ))

    if dnp3_crc_failure_count:
        report.findings.append(Finding(
            finding_id="OBS-DNP3-CRC-VALIDATION-FAILURES",
            title="DNP3 link CRC validation failures observed",
            severity=Severity.LOW,
            description="One or more DNP3 link frames failed header or per-block CRC validation in the captured traffic. This can result from capture truncation, line/noise errors, malformed traffic, parser vantage-point effects, or intentional packet modification; CRC is not cryptographic authentication.",
            evidence={"failure_count": dnp3_crc_failure_count, "examples": dnp3_crc_failures, "examples_truncated": dnp3_crc_failure_count > len(dnp3_crc_failures)},
            recommendation="Validate the capture source and link-layer integrity using an independent tap or device diagnostics. Correlate repeated failures with controller and network-device logs before treating them as security events.",
            confidence="high", source="pcap.dnp3-crc", priority_score=20,
            tags=["dnp3", "frame-integrity", "passive-observation"],
        ))

    if write_events:
        report.findings.append(Finding(
            finding_id="OBS-OT-WRITE-ACTIVITY",
            title="Control or write-capable industrial protocol requests observed",
            severity=Severity.INFO,
            description="The capture includes protocol requests classified as control-related or write-capable. Such traffic may be routine HMI, SCADA, engineering or control activity; it is not proof of malicious behavior.",
            evidence={"events": write_events, "event_count": write_event_count, "truncated_in_report": write_event_count > len(write_events)},
            recommendation="Compare source endpoints and timing with approved HMI, engineering workstation, and controller communication matrices.",
            confidence="high", source="pcap.passive-protocol-analysis", priority_score=15,
            tags=["write-capable-traffic", "process-change-path"],
        ))

    for stream in streams:
        if stream.overlap_conflicts:
            report.findings.append(Finding(
                finding_id=f"OBS-TCP-OVERLAP-{stream.src}-{stream.sport}-{stream.dst}-{stream.dport}",
                title="Conflicting TCP payload overlaps observed",
                severity=Severity.LOW,
                description="Overlapping TCP sequence ranges contained different payload bytes. Endpoint reassembly behavior can vary; PLCSEC reports the ambiguity and does not choose an endpoint-specific interpretation.",
                evidence={"src": stream.src, "sport": stream.sport, "dst": stream.dst, "dport": stream.dport, "conflicts": stream.overlap_conflicts},
                recommendation="Validate the capture point, packet deduplication, network taps, and endpoint behavior before drawing protocol conclusions.",
                confidence="medium", source="pcap.tcp-reassembly", priority_score=20,
                tags=["forensic-ambiguity", "tcp-reassembly"],
            ))

    report.assets = sorted(assets.values(), key=lambda item: item.ip)
    report.events = protocol_events
    report.flows = [
        FlowObservation(
            src_ip=flow[0], dst_ip=flow[2], src_port=flow[1], dst_port=flow[3],
            transport=flow[4], packets=count,
            bytes_observed=flow_bytes.get(flow, 0),
            first_seen=_iso(flow_first[flow]) if flow_first.get(flow) else None,
            last_seen=_iso(flow_last[flow]) if flow_last.get(flow) else None,
        )
        for flow, count in sorted(flow_packets.items())
    ][:250_000]
    report.metadata = {
        "capture_format": capture.suffix.lower().lstrip("."),
        "capture_sha256": _sha256(capture),
        "packet_count": total_packets,
        "capture_packet_limit_reached": truncated_capture,
        "tcp_flow_limit_reached": flow_limit_reached,
        "directional_flow_limit_reached": flow_limit_reached,
        "tcp_segment_limit_reached": segment_limit_reached,
        "tcp_total_stream_limit_reached": total_stream_limit_reached,
        "tcp_payload_bytes_retained_for_reassembly": total_stream_bytes,
        "capture_bytes": total_bytes,
        "asset_count": len(assets),
        "asset_limit": max_assets,
        "service_limit": max_services,
        "flow_count": len(report.flows),
        "flow_count_truncated": len(flow_packets) > len(report.flows),
        "asset_count_truncated": asset_limit_reached,
        "service_observation_truncated": service_limit_reached,
        "service_observation_count": len(service_map),
        "service_flow_limit_reached": service_flow_limit_reached,
        "service_flow_pairs_retained": service_flow_pair_count,
        "mac_observation_limit_reached": mac_observation_limit_reached,
        "tcp_directional_stream_count": reassembly_stats.streams_emitted,
        "tcp_reassembly": {
            "directional_flows": reassembly_stats.directional_flows,
            "segments_seen": reassembly_stats.segments_seen,
            "retransmissions": reassembly_stats.retransmissions,
            "overlap_conflicts": reassembly_stats.overlap_conflicts,
            "sequence_gaps": reassembly_stats.sequence_gaps,
            "truncated_flows": reassembly_stats.truncated_flows,
        },
        "protocol_packet_counts": dict(protocol_counts),
        "modbus_function_counts": dict(modbus_function_counts),
        "s7_function_counts": dict(s7_function_counts),
        "cip_service_counts": dict(cip_service_counts),
        "opcua_message_counts": dict(opcua_message_counts),
        "dnp3_crc_failure_count": dnp3_crc_failure_count,
        "dnp3_crc_failure_examples_retained": len(dnp3_crc_failures),
        "write_capable_request_count": write_event_count,
        "write_capable_events_retained": len(write_events),
        "write_capable_events_truncated": write_event_count > len(write_events),
        "event_count": protocol_event_count,
        "event_count_reported": len(report.events),
        "event_count_truncated": protocol_event_count > len(report.events),
        "asset_limit_reached": asset_limit_reached,
        "service_limit_reached": service_limit_reached,
        "capture_first_packet_utc": _iso(first_ts) if first_ts else None,
        "capture_last_packet_utc": _iso(last_ts) if last_ts else None,
        "limitations": [
            "Passive analysis only observes traffic present in the capture.",
            "TCP reassembly is bounded and does not emulate an endpoint TCP stack.",
            "Conflicting TCP overlaps and sequence gaps are reported as forensic ambiguity.",
            "Asset, service, service-flow, MAC, flow, segment and event ceilings can truncate high-cardinality captures; check all limit flags.",
            "Protocol ports and signatures are indicators, not conclusive PLC identities.",
            "Encrypted or authenticated application payloads are not decrypted.",
            "OPC UA OPN asymmetric security headers may expose a SecurityPolicyUri and sender certificate; the negotiated MessageSecurityMode and full endpoint configuration are not inferred from this header alone.",
            "Certificate parsing is optional and reports a fingerprint even when X.509 metadata cannot be parsed; this is not a trust-chain validation.",
            "TLS parsing extracts visible record and hello metadata only; encrypted application data and certificate chains are not decrypted or fully validated.",
            "IEC 60870-5-104 parsing is framing and bounded ASDU-header/selected command metadata; DNP3 validates link header and data-block CRCs but does not reassemble transport fragments or decode all application objects; BACnet/IP parsing is BVLC/limited NPDU metadata only.",
            "No raw application payloads are stored in reports.",
        ],
    }
    report.finish()
    return report
