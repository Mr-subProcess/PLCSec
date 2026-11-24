from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from plcsec.models import AssessmentReport, Finding, Severity, utc_now
from plcsec.safeio import read_stable_bytes

BASELINE_SCHEMA = "plcsec.baseline.v1"
MAX_BASELINE_BYTES = 32 * 1024 * 1024


def build_baseline(report: AssessmentReport, site_id: str) -> dict[str, Any]:
    if not site_id.strip():
        raise ValueError("site_id must not be empty")
    assets: dict[str, dict[str, Any]] = {}
    for asset in report.assets:
        services = sorted({(service.protocol, service.port) for service in asset.observed_services})
        assets[asset.ip] = {
            "mac_addresses": sorted(asset.mac_addresses),
            "services": [{"protocol": protocol, "port": port} for protocol, port in services],
        }
    return {
        "schema": BASELINE_SCHEMA,
        "site_id": site_id.strip(),
        "created_at": utc_now(),
        "source_capture_sha256": report.metadata.get("capture_sha256"),
        "asset_count": len(assets),
        "assets": dict(sorted(assets.items())),
        "notes": "A passive observation baseline, not an authoritative asset register.",
    }


def write_baseline(baseline: dict[str, Any], path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def load_baseline_bytes(raw: bytes, *, source_label: str = "<memory>") -> dict[str, Any]:
    if len(raw) > MAX_BASELINE_BYTES:
        raise ValueError(f"Baseline exceeds {MAX_BASELINE_BYTES} bytes")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Baseline is not valid UTF-8 JSON: {source_label}") from exc
    if not isinstance(data, dict) or data.get("schema") != BASELINE_SCHEMA:
        raise ValueError(f"Unsupported or invalid PLCSEC baseline schema: {source_label}")
    assets = data.get("assets")
    if not isinstance(assets, dict):
        raise ValueError("Baseline 'assets' must be an object keyed by IP address")
    return data


def load_baseline(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    raw = read_stable_bytes(source, max_bytes=MAX_BASELINE_BYTES, label="Baseline")
    return load_baseline_bytes(raw, source_label=str(source))


def compare_to_baseline(report: AssessmentReport, baseline: dict[str, Any]) -> AssessmentReport:
    baseline_assets = baseline.get("assets", {})
    if not isinstance(baseline_assets, dict):
        raise ValueError("Baseline 'assets' must be an object")
    current = {asset.ip: asset for asset in report.assets}
    known = set(str(key) for key in baseline_assets)
    for ip, asset in current.items():
        if ip not in known:
            report.findings.append(Finding(
                finding_id=f"BASELINE-NEW-ASSET-{ip}",
                title="New IP asset observed compared with baseline",
                severity=Severity.MEDIUM,
                description="This IP address was observed in the current capture but is absent from the selected passive baseline. It may be a newly deployed device, a previously unseen asset, or a capture-scope change.",
                evidence={"ip": ip, "current_services": sorted({f"{s.protocol}:{s.port}" for s in asset.observed_services})},
                recommendation="Validate the device with the site asset owner and network architecture. Update the approved inventory only after verification.",
                confidence="medium", source="baseline-diff", priority_score=45,
                tags=["asset-drift", "inventory-validation"],
            ))
            continue
        baseline_entry = baseline_assets.get(ip, {})
        baseline_services = {
            (str(item.get("protocol")), int(item.get("port")))
            for item in baseline_entry.get("services", []) if isinstance(item, dict)
        }
        current_services = {(service.protocol, service.port) for service in asset.observed_services}
        for protocol, port in sorted(current_services - baseline_services):
            report.findings.append(Finding(
                finding_id=f"BASELINE-NEW-SERVICE-{ip}-{port}",
                title=f"New service observation: {protocol}",
                severity=Severity.LOW,
                description="A service was observed for an asset but was not present in the selected baseline. This is a traffic observation, not proof that a listening service is reachable from every network zone.",
                evidence={"ip": ip, "protocol": protocol, "port": port},
                recommendation="Confirm whether the service is expected, document its owner and required conduits, and compare with the approved network design.",
                confidence="medium", source="baseline-diff", priority_score=30,
                tags=["service-drift", "network-baseline"],
            ))
        baseline_macs = set(str(item).lower() for item in baseline_entry.get("mac_addresses", []))
        current_macs = set(item.lower() for item in asset.mac_addresses)
        if baseline_macs and current_macs and not (baseline_macs & current_macs):
            report.findings.append(Finding(
                finding_id=f"BASELINE-MAC-CHANGE-{ip}",
                title="Observed MAC address differs from baseline",
                severity=Severity.LOW,
                description="The current capture associates this IP with MAC addresses not seen in the baseline. Address changes, redundancy, virtualization, NAT, and capture location can all explain this observation.",
                evidence={"ip": ip, "baseline_macs": sorted(baseline_macs), "current_macs": sorted(current_macs)},
                recommendation="Validate against switch, DHCP, ARP, redundancy, and asset-management records before classifying as unauthorized replacement.",
                confidence="low", source="baseline-diff", priority_score=20,
                tags=["asset-drift", "mac-change"],
            ))
    for ip in sorted(known - set(current)):
        report.findings.append(Finding(
            finding_id=f"BASELINE-MISSING-ASSET-{ip}",
            title="Baseline asset not observed in current capture",
            severity=Severity.INFO,
            description="An asset in the passive baseline was not observed in the current capture. Capture vantage point, observation window, idle devices, and topology changes can cause this.",
            evidence={"ip": ip},
            recommendation="Do not infer that the device is offline. Confirm capture coverage and consult operational inventory.",
            confidence="low", source="baseline-diff", priority_score=5,
            tags=["asset-visibility", "baseline-diff"],
        ))
    report.metadata["baseline_comparison"] = {
        "site_id": baseline.get("site_id"),
        "baseline_created_at": baseline.get("created_at"),
        "baseline_asset_count": len(known),
        "current_asset_count": len(current),
    }
    report.assessment_type = "passive-pcap-baseline-comparison"
    report.finish()
    return report
