from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 64 * 1024 * 1024
STIX_SPEC_VERSION = "2.1"


def _stix_id(kind: str) -> str:
    return f"{kind}--{uuid.uuid4()}"


def _timestamp(value: str | None, fallback: str) -> str:
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, TypeError):
        return fallback


def report_to_stix_bundle(report: dict[str, Any], *, producer_name: str = "PLCSEC") -> dict[str, Any]:
    """Convert a PLCSEC JSON report to a conservative STIX 2.1 bundle.

    Observations remain observations; PLCSEC findings are represented as STIX
    Notes, not Vulnerability or Indicator objects. This avoids implying a CVE
    or malicious attribution where the report has neither.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    identity_id = _stix_id("identity")
    objects: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": STIX_SPEC_VERSION, "id": identity_id,
        "created": now, "modified": now, "name": producer_name,
        "identity_class": "system", "sectors": ["technology"],
    }]
    asset_obs_ids: dict[str, str] = {}

    for asset in report.get("assets", []) if isinstance(report.get("assets", []), list) else []:
        if not isinstance(asset, dict):
            continue
        raw_ip = asset.get("ip")
        try:
            ip_obj = ipaddress.ip_address(str(raw_ip))
        except ValueError:
            continue
        sco_type = "ipv4-addr" if ip_obj.version == 4 else "ipv6-addr"
        sco_id = _stix_id(sco_type)
        objects.append({"type": sco_type, "spec_version": STIX_SPEC_VERSION, "id": sco_id, "value": str(ip_obj)})
        observed_id = _stix_id("observed-data")
        first_seen = _timestamp(asset.get("first_seen"), now)
        last_seen = _timestamp(asset.get("last_seen"), first_seen)
        objects.append({
            "type": "observed-data", "spec_version": STIX_SPEC_VERSION, "id": observed_id,
            "created": now, "modified": now, "created_by_ref": identity_id,
            "first_observed": first_seen, "last_observed": max(first_seen, last_seen),
            "number_observed": max(1, int(asset.get("packets_seen", 1) or 1)),
            "object_refs": [sco_id],
            "labels": ["plcsec-asset-observation"],
        })
        asset_obs_ids[str(ip_obj)] = observed_id

    flows = report.get("flows", [])
    for flow in flows if isinstance(flows, list) else []:
        if not isinstance(flow, dict):
            continue
        sco_refs: list[str] = []
        address_families: list[str] = []
        for address_key in ("src_ip", "dst_ip"):
            try:
                parsed_address = ipaddress.ip_address(str(flow.get(address_key, "")))
                address_families.append("ipv4" if parsed_address.version == 4 else "ipv6")
            except ValueError:
                pass
        family = address_families[0] if address_families else "ipv4"
        transport = str(flow.get("transport", "tcp")).lower()
        if transport not in {"tcp", "udp", "icmp", "icmpv6", "sctp"}:
            transport = "tcp"
        traffic: dict[str, Any] = {
            "type": "network-traffic", "spec_version": STIX_SPEC_VERSION,
            "id": _stix_id("network-traffic"),
            "protocols": [family, transport],
        }
        for key, stix_key in (("src_ip", "src_ref"), ("dst_ip", "dst_ref")):
            try:
                address = ipaddress.ip_address(str(flow.get(key, "")))
            except ValueError:
                continue
            # The object_refs for flows are SCO references, so a dedicated SCO is
            # emitted even when the same IP already appears in an observed-data object.
            sco_type = "ipv4-addr" if address.version == 4 else "ipv6-addr"
            sco_id = _stix_id(sco_type)
            objects.append({"type": sco_type, "spec_version": STIX_SPEC_VERSION, "id": sco_id, "value": str(address)})
            traffic[stix_key] = sco_id
            sco_refs.append(sco_id)
        for key in ("src_port", "dst_port"):
            value = flow.get(key)
            if isinstance(value, int) and 0 <= value <= 65535:
                traffic[key] = value
        first_seen = _timestamp(flow.get("first_seen"), now)
        last_seen = _timestamp(flow.get("last_seen"), first_seen)
        traffic["start"] = first_seen
        traffic["end"] = max(first_seen, last_seen)
        objects.append(traffic)
        sco_refs.append(traffic["id"])
        objects.append({
            "type": "observed-data", "spec_version": STIX_SPEC_VERSION,
            "id": _stix_id("observed-data"), "created": now, "modified": now,
            "created_by_ref": identity_id, "first_observed": first_seen,
            "last_observed": max(first_seen, last_seen), "number_observed": max(1, int(flow.get("packets", 1) or 1)),
            "object_refs": sco_refs, "labels": ["plcsec-network-flow-observation"],
        })

    findings = report.get("findings", [])
    for finding in findings if isinstance(findings, list) else []:
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence", {})
        refs: list[str] = []
        if isinstance(evidence, dict):
            candidate_ip = evidence.get("ip") or evidence.get("src_ip") or evidence.get("dst_ip")
            if candidate_ip is not None:
                try:
                    refs_id = asset_obs_ids.get(str(ipaddress.ip_address(str(candidate_ip))))
                    if refs_id:
                        refs.append(refs_id)
                except ValueError:
                    pass
        if not refs:
            refs.append(identity_id)
        title = str(finding.get("title", "PLCSEC finding"))[:512]
        description = str(finding.get("description", ""))[:8192]
        content = json.dumps({
            "finding_id": str(finding.get("finding_id", "")),
            "title": title,
            "severity": str(finding.get("severity", "info")),
            "confidence": str(finding.get("confidence", "unknown")),
            "description": description,
            "evidence": evidence if isinstance(evidence, dict) else {},
            "recommendation": str(finding.get("recommendation", ""))[:4096],
            "source": str(finding.get("source", "plcsec")),
            "interpretation": "A PLCSEC finding is an assessment observation, not a confirmed vulnerability or attribution.",
        }, ensure_ascii=False, sort_keys=True)
        objects.append({
            "type": "note", "spec_version": STIX_SPEC_VERSION, "id": _stix_id("note"),
            "created": now, "modified": now, "created_by_ref": identity_id,
            "abstract": title, "content": content, "authors": [producer_name],
            "object_refs": refs,
        })

    bundle = {"type": "bundle", "id": _stix_id("bundle"), "objects": objects}
    validate_stix_bundle(bundle)
    return bundle


def validate_stix_bundle(bundle: dict[str, Any]) -> None:
    if bundle.get("type") != "bundle" or not str(bundle.get("id", "")).startswith("bundle--"):
        raise ValueError("Invalid STIX bundle envelope")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or len(objects) > 1_000_000:
        raise ValueError("STIX bundle objects must be a bounded array")
    identifiers: set[str] = set()
    for item in objects:
        if not isinstance(item, dict) or not isinstance(item.get("type"), str):
            raise ValueError("Invalid STIX object")
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id.startswith(item["type"] + "--"):
            raise ValueError("STIX object ID does not match object type")
        if item_id in identifiers:
            raise ValueError("Duplicate STIX object ID")
        identifiers.add(item_id)
        if item.get("spec_version") != STIX_SPEC_VERSION:
            raise ValueError("Only STIX 2.1 objects are emitted")
    for item in objects:
        if item.get("type") in {"observed-data", "note"}:
            refs = item.get("object_refs")
            if not isinstance(refs, list) or not refs:
                raise ValueError(f"{item['type']} requires object_refs")
            if any(ref not in identifiers for ref in refs):
                raise ValueError(f"{item['type']} references a missing object")
        creator = item.get("created_by_ref")
        if creator is not None and creator not in identifiers:
            raise ValueError("STIX created_by_ref references a missing object")


def export_stix_report(input_path: str | Path, output_path: str | Path) -> dict[str, Any]:
    source = Path(input_path)
    if not source.is_file() or source.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Input report is missing or exceeds the 64 MiB limit")
    report = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("Input PLCSEC report must be a JSON object")
    bundle = report_to_stix_bundle(report)
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"output": str(target), "object_count": len(bundle["objects"]), "stix_version": STIX_SPEC_VERSION}
