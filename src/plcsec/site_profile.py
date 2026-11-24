from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from plcsec.models import AssessmentReport, Finding, FlowObservation, Severity

SITE_PROFILE_SCHEMA = "plcsec.site-profile.v1"
MAX_SITE_PROFILE_BYTES = 5 * 1024 * 1024
MAX_ZONES = 512
MAX_NETWORKS = 4096
MAX_CONDUITS = 100_000


@dataclass(frozen=True, slots=True)
class Zone:
    name: str
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]


@dataclass(frozen=True, slots=True)
class Conduit:
    source_zone: str
    destination_zone: str
    transport: str
    destination_port: int
    purpose: str = ""


@dataclass(frozen=True, slots=True)
class SiteProfile:
    site_id: str
    zones: tuple[Zone, ...]
    conduits: tuple[Conduit, ...]

    def zone_for(self, address: str) -> str | None:
        ip = ipaddress.ip_address(address)
        matches = [zone.name for zone in self.zones if any(ip.version == net.version and ip in net for net in zone.networks)]
        if len(matches) > 1:
            raise ValueError(f"IP address {address} maps to overlapping zones: {', '.join(matches)}")
        return matches[0] if matches else None

    def permits(self, source_zone: str, destination_zone: str, transport: str, destination_port: int) -> bool:
        return any(
            item.source_zone == source_zone
            and item.destination_zone == destination_zone
            and item.transport == transport
            and item.destination_port == destination_port
            for item in self.conduits
        )


def load_site_profile(path: str | Path) -> SiteProfile:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    if source.stat().st_size > MAX_SITE_PROFILE_BYTES:
        raise ValueError(f"Site profile exceeds the {MAX_SITE_PROFILE_BYTES}-byte size limit")
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SITE_PROFILE_SCHEMA:
        raise ValueError(f"Unsupported site profile schema: {source}")
    site_id = data.get("site_id")
    raw_zones = data.get("zones")
    raw_conduits = data.get("approved_conduits", [])
    if not isinstance(site_id, str) or not site_id.strip():
        raise ValueError("site profile requires a non-empty site_id")
    if not isinstance(raw_zones, list) or not raw_zones or len(raw_zones) > MAX_ZONES:
        raise ValueError(f"site profile requires 1..{MAX_ZONES} zones")
    if not isinstance(raw_conduits, list) or len(raw_conduits) > MAX_CONDUITS:
        raise ValueError(f"approved_conduits must be an array with at most {MAX_CONDUITS} entries")

    zones: list[Zone] = []
    zone_names: set[str] = set()
    all_networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    network_count = 0
    for item in raw_zones:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("cidrs"), list):
            raise ValueError("each zone requires a name and a cidrs array")
        name = item["name"].strip()
        if not name or name in zone_names:
            raise ValueError(f"duplicate or empty zone name: {name!r}")
        if len(item["cidrs"]) < 1:
            raise ValueError(f"zone {name!r} must contain at least one CIDR")
        network_count += len(item["cidrs"])
        if network_count > MAX_NETWORKS:
            raise ValueError(f"site profile exceeds the {MAX_NETWORKS}-network limit")
        networks = tuple(ipaddress.ip_network(str(value), strict=False) for value in item["cidrs"])
        if not networks:
            raise ValueError(f"zone {name!r} has no CIDR networks")
        for network in networks:
            for other_name, other_network in all_networks:
                if network.version == other_network.version and network.overlaps(other_network):
                    raise ValueError(f"overlapping zone networks: {name}:{network} overlaps {other_name}:{other_network}")
            all_networks.append((name, network))
        zones.append(Zone(name, networks))
        zone_names.add(name)

    conduits: list[Conduit] = []
    seen_conduits: set[tuple[str, str, str, int]] = set()
    for item in raw_conduits:
        if not isinstance(item, dict):
            raise ValueError("each approved conduit must be an object")
        source_zone = str(item.get("source_zone", ""))
        destination_zone = str(item.get("destination_zone", ""))
        transport = str(item.get("transport", "")).lower()
        try:
            destination_port = int(item.get("destination_port"))
        except (TypeError, ValueError) as exc:
            raise ValueError("approved conduit destination_port must be an integer") from exc
        if source_zone not in zone_names or destination_zone not in zone_names:
            raise ValueError("approved conduit references an unknown zone")
        if transport not in {"tcp", "udp"} or not 1 <= destination_port <= 65535:
            raise ValueError("approved conduit requires transport tcp/udp and port 1..65535")
        conduit_key = (source_zone, destination_zone, transport, destination_port)
        if conduit_key in seen_conduits:
            raise ValueError(f"duplicate approved conduit: {conduit_key}")
        seen_conduits.add(conduit_key)
        conduits.append(Conduit(source_zone, destination_zone, transport, destination_port, str(item.get("purpose", ""))))
    return SiteProfile(site_id.strip(), tuple(zones), tuple(conduits))


def validate_site_profile(path: str | Path) -> dict[str, Any]:
    profile = load_site_profile(path)
    return {
        "schema": SITE_PROFILE_SCHEMA,
        "site_id": profile.site_id,
        "zone_count": len(profile.zones),
        "network_count": sum(len(zone.networks) for zone in profile.zones),
        "approved_conduit_count": len(profile.conduits),
    }


def apply_site_profile(report: AssessmentReport, profile: SiteProfile) -> AssessmentReport:
    cross_zone_flows = 0
    unapproved_flows = 0
    unknown_zone_flows = 0
    seen_conversations: set[tuple[str, str, str, int]] = set()
    for flow in report.flows:
        client_ip, server_ip = flow.src_ip, flow.dst_ip
        server_port = flow.dst_port
        # Orient known services as client -> server even when this is a response segment.
        known_server_ports = {21, 22, 23, 80, 102, 161, 443, 502, 802, 20000, 2221, 2222, 2404, 44818, 47808, 4840, 5900}
        if flow.src_port in known_server_ports and flow.dst_port not in known_server_ports:
            client_ip, server_ip = flow.dst_ip, flow.src_ip
            server_port = flow.src_port
        source_zone = profile.zone_for(client_ip)
        destination_zone = profile.zone_for(server_ip)
        if source_zone is None or destination_zone is None:
            unknown_zone_flows += 1
            continue
        if source_zone == destination_zone:
            continue
        conversation_key = (client_ip, server_ip, flow.transport, server_port)
        if conversation_key in seen_conversations:
            continue
        seen_conversations.add(conversation_key)
        cross_zone_flows += 1
        if profile.permits(source_zone, destination_zone, flow.transport, server_port):
            continue
        unapproved_flows += 1
        report.findings.append(Finding(
            finding_id=f"ZONE-UNAPPROVED-{flow.transport}-{client_ip}-{server_ip}-{server_port}",
            title="Observed cross-zone flow is not in the approved conduit profile",
            severity=Severity.MEDIUM,
            description="A flow crossing two configured security zones was observed, but no matching directed conduit rule was found in the supplied site profile. The profile may be incomplete and the capture may not represent the complete network path.",
            evidence={
                "site_id": profile.site_id,
                "source_ip": client_ip,
                "destination_ip": server_ip,
                "source_zone": source_zone,
                "destination_zone": destination_zone,
                "transport": flow.transport,
                "destination_port": server_port,
                "packets": flow.packets,
                "bytes_observed": flow.bytes_observed,
            },
            recommendation="Validate the observed path with the OT network owner and firewall/conduit configuration. Add a rule only after confirming business need and safety approval.",
            confidence="medium", source="site-profile-segmentation-review", priority_score=50,
            tags=["network-segmentation", "zone-conduit", "site-profile"],
            references=["https://csrc.nist.gov/pubs/sp/800/82/r3/final"],
        ))
    report.scope["site_profile"] = profile.site_id
    report.metadata["site_profile_analysis"] = {
        "site_id": profile.site_id,
        "zone_count": len(profile.zones),
        "approved_conduit_count": len(profile.conduits),
        "cross_zone_flows_observed": cross_zone_flows,
        "unapproved_cross_zone_flows": unapproved_flows,
        "flows_with_unmapped_endpoint": unknown_zone_flows,
        "interpretation": "Observed flow differences require owner validation; they are not proof of unauthorized access.",
    }
    report.finish()
    return report
