from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from plcsec.models import AssessmentReport, Finding, Severity

INVENTORY_SCHEMA = "plcsec.asset-inventory.v1"
MAX_INVENTORY_BYTES = 10 * 1024 * 1024
MAX_INVENTORY_ASSETS = 100_000
MAX_EXPECTED_SERVICES_PER_ASSET = 1024
MAX_METADATA_TEXT_LENGTH = 1024
VALID_CRITICALITIES = {"low", "medium", "high", "critical", "safety"}


@dataclass(frozen=True, slots=True)
class ExpectedService:
    protocol: str
    port: int
    purpose: str = ""


@dataclass(frozen=True, slots=True)
class InventoryAsset:
    asset_id: str
    ip: str
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    firmware: str = ""
    role: str = ""
    owner: str = ""
    criticality: str = "medium"
    zone: str = ""
    expected_services: tuple[ExpectedService, ...] = ()
    notes: str = ""


@dataclass(frozen=True, slots=True)
class AssetInventory:
    site_id: str
    assets: tuple[InventoryAsset, ...]

    @property
    def by_ip(self) -> dict[str, InventoryAsset]:
        return {asset.ip: asset for asset in self.assets}


def load_inventory(path: str | Path) -> AssetInventory:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    if source.stat().st_size > MAX_INVENTORY_BYTES:
        raise ValueError(f"Inventory exceeds the {MAX_INVENTORY_BYTES}-byte size limit")
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != INVENTORY_SCHEMA:
        raise ValueError(f"Unsupported asset inventory schema: {source}")
    site_id = data.get("site_id")
    raw_assets = data.get("assets")
    if not isinstance(site_id, str) or not site_id.strip():
        raise ValueError("Inventory requires a non-empty site_id")
    if not isinstance(raw_assets, list) or not raw_assets or len(raw_assets) > MAX_INVENTORY_ASSETS:
        raise ValueError(f"Inventory requires 1..{MAX_INVENTORY_ASSETS} asset entries")

    result: list[InventoryAsset] = []
    seen_ids: set[str] = set()
    seen_ips: set[str] = set()
    for index, raw in enumerate(raw_assets):
        if not isinstance(raw, dict):
            raise ValueError(f"assets[{index}] must be an object")
        asset_id = str(raw.get("asset_id", "")).strip()
        if not asset_id or len(asset_id) > 128 or asset_id in seen_ids:
            raise ValueError(f"assets[{index}] has a duplicate, empty or overlong asset_id")
        try:
            address = str(ipaddress.ip_address(str(raw.get("ip", ""))))
        except ValueError as exc:
            raise ValueError(f"assets[{index}] has an invalid IP address") from exc
        if address in seen_ips:
            raise ValueError(f"duplicate inventory IP address: {address}")
        criticality = str(raw.get("criticality", "medium")).lower()
        if criticality not in VALID_CRITICALITIES:
            raise ValueError(f"assets[{index}] criticality must be one of {sorted(VALID_CRITICALITIES)}")
        raw_services = raw.get("expected_services", [])
        if not isinstance(raw_services, list) or len(raw_services) > MAX_EXPECTED_SERVICES_PER_ASSET:
            raise ValueError(f"assets[{index}].expected_services must be an array with at most {MAX_EXPECTED_SERVICES_PER_ASSET} entries")
        expected_services: list[ExpectedService] = []
        seen_services: set[tuple[str, int]] = set()
        for service_index, service in enumerate(raw_services):
            if not isinstance(service, dict):
                raise ValueError(f"assets[{index}].expected_services[{service_index}] must be an object")
            protocol = str(service.get("protocol", "")).strip()
            try:
                port = int(service.get("port"))
            except (TypeError, ValueError) as exc:
                raise ValueError("expected service port must be an integer") from exc
            if not protocol or not 1 <= port <= 65535:
                raise ValueError("expected service requires a protocol name and port 1..65535")
            key = (protocol, port)
            if key in seen_services:
                raise ValueError(f"duplicate expected service in inventory asset {asset_id}: {key}")
            seen_services.add(key)
            expected_services.append(ExpectedService(protocol, port, str(service.get("purpose", ""))))
        text_fields = {key: str(raw.get(key, "")) for key in ("hostname", "vendor", "model", "firmware", "role", "owner", "zone", "notes")}
        for field_name, field_value in text_fields.items():
            if len(field_value) > MAX_METADATA_TEXT_LENGTH:
                raise ValueError(f"assets[{index}].{field_name} exceeds {MAX_METADATA_TEXT_LENGTH} characters")
        result.append(InventoryAsset(
            asset_id=asset_id,
            ip=address,
            hostname=text_fields["hostname"],
            vendor=text_fields["vendor"],
            model=text_fields["model"],
            firmware=text_fields["firmware"],
            role=text_fields["role"],
            owner=text_fields["owner"],
            criticality=criticality,
            zone=text_fields["zone"],
            expected_services=tuple(expected_services),
            notes=text_fields["notes"],
        ))
        seen_ids.add(asset_id)
        seen_ips.add(address)
    return AssetInventory(site_id.strip(), tuple(result))


def validate_inventory(path: str | Path) -> dict[str, Any]:
    inventory = load_inventory(path)
    return {
        "schema": INVENTORY_SCHEMA,
        "site_id": inventory.site_id,
        "asset_count": len(inventory.assets),
        "expected_service_count": sum(len(asset.expected_services) for asset in inventory.assets),
        "criticality_counts": {
            level: sum(asset.criticality == level for asset in inventory.assets)
            for level in sorted(VALID_CRITICALITIES)
        },
    }


def apply_inventory(report: AssessmentReport, inventory: AssetInventory) -> AssessmentReport:
    """Enrich observed endpoints and compare traffic with an owner-provided inventory."""
    expected = inventory.by_ip
    observed = {asset.ip: asset for asset in report.assets}
    unknown_observed = 0
    expected_not_observed = 0
    unexpected_services = 0
    expected_services_not_seen = 0

    for ip, asset in observed.items():
        record = expected.get(ip)
        if record is None:
            unknown_observed += 1
            report.findings.append(Finding(
                finding_id=f"INV-UNREGISTERED-ASSET-{ip}",
                title="Observed IP asset is not present in the supplied inventory",
                severity=Severity.MEDIUM,
                description="An endpoint was observed in the capture but has no matching IP entry in the supplied site inventory. It may be an unregistered device, temporary host, gateway, NAT address, or a mismatch between capture scope and inventory scope.",
                evidence={"ip": ip, "observed_services": [f"{item.protocol}:{item.port}" for item in asset.observed_services]},
                recommendation="Validate the endpoint with the OT asset owner and network team before adding it to the authoritative inventory.",
                confidence="medium", source="asset-inventory-review", priority_score=45,
                tags=["asset-inventory", "unregistered-observation"],
            ))
            continue

        asset.inventory_metadata = {
            "asset_id": record.asset_id,
            "hostname": record.hostname,
            "vendor": record.vendor,
            "model": record.model,
            "firmware": record.firmware,
            "role": record.role,
            "owner": record.owner,
            "criticality": record.criticality,
            "zone": record.zone,
        }
        expected_services = {(service.protocol, service.port): service for service in record.expected_services}
        observed_services = {(service.protocol, service.port) for service in asset.observed_services}
        for protocol, port in sorted(observed_services - set(expected_services)):
            unexpected_services += 1
            report.findings.append(Finding(
                finding_id=f"INV-UNEXPECTED-SERVICE-{record.asset_id}-{port}",
                title=f"Observed service is not listed for inventory asset {record.asset_id}",
                severity=Severity.LOW,
                description="The capture shows a protocol/port for an inventoried endpoint that is not listed in its expected_services entries. This is a traffic observation, not proof of a listening service or unauthorized exposure.",
                evidence={"asset_id": record.asset_id, "ip": ip, "protocol": protocol, "port": port, "criticality": record.criticality},
                recommendation="Confirm whether the communication is required. Update the approved inventory or network design only after owner review and change approval.",
                confidence="medium", source="asset-inventory-review", priority_score=35 if record.criticality in {"high", "critical", "safety"} else 25,
                tags=["asset-inventory", "service-drift", record.criticality],
            ))
        for protocol, port in sorted(set(expected_services) - observed_services):
            expected_services_not_seen += 1
            report.findings.append(Finding(
                finding_id=f"INV-EXPECTED-SERVICE-NOT-OBSERVED-{record.asset_id}-{port}",
                title=f"Expected service not observed for inventory asset {record.asset_id}",
                severity=Severity.INFO,
                description="The configured capture did not contain traffic for an expected service. An idle device, capture placement, observation window, encryption, or network path may explain the absence.",
                evidence={"asset_id": record.asset_id, "ip": ip, "expected_protocol": protocol, "expected_port": port},
                recommendation="Check capture coverage and observation window. Do not infer that the service is disabled or the device is offline.",
                confidence="low", source="asset-inventory-review", priority_score=5,
                tags=["asset-inventory", "visibility-gap"],
            ))

    for ip, record in expected.items():
        if ip in observed:
            continue
        expected_not_observed += 1
        report.findings.append(Finding(
            finding_id=f"INV-ASSET-NOT-OBSERVED-{record.asset_id}",
            title=f"Inventory asset not observed in this capture: {record.asset_id}",
            severity=Severity.INFO,
            description="An inventory entry was not observed during this capture window. The device may be idle, outside the capture vantage point, behind a gateway, or temporarily unavailable; this is not proof of an outage.",
            evidence={"asset_id": record.asset_id, "ip": ip, "criticality": record.criticality, "zone": record.zone},
            recommendation="Confirm that the capture covers the expected communication paths and compare against passive network and operational monitoring sources.",
            confidence="low", source="asset-inventory-review", priority_score=10,
            tags=["asset-inventory", "not-observed", record.criticality],
        ))

    report.scope["asset_inventory_site_id"] = inventory.site_id
    report.metadata["asset_inventory_analysis"] = {
        "site_id": inventory.site_id,
        "inventory_asset_count": len(inventory.assets),
        "observed_inventory_asset_count": len(set(observed) & set(expected)),
        "unregistered_observed_asset_count": unknown_observed,
        "inventory_asset_not_observed_count": expected_not_observed,
        "unexpected_service_count": unexpected_services,
        "expected_service_not_observed_count": expected_services_not_seen,
        "interpretation": "Inventory comparisons are evidence for owner review; capture absence is not proof of outage and observed traffic is not proof of unauthorized exposure.",
    }
    report.finish()
    return report
