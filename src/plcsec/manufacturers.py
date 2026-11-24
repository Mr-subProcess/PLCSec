from __future__ import annotations

import re
from typing import Any

# ODVA Vendor ID 1 is confirmed for Rockwell Automation / Allen-Bradley.
# Other vendor identification is intentionally based on owner-supplied inventory text,
# not on guessed CIP IDs.
CIP_VENDOR_IDS: dict[int, dict[str, str]] = {
    1: {"manufacturer": "Rockwell Automation", "confidence": "high", "source": "ODVA Vendor ID 1"},
}

VENDOR_ALIASES: dict[str, tuple[str, ...]] = {
    "Siemens": ("siemens", "simatic", "s7-1200", "s7-1500", "s7-300", "s7-400", "et 200"),
    "Rockwell Automation": ("rockwell", "allen-bradley", "allen bradley", "controllogix", "compactlogix", "micro800"),
    "Schneider Electric": ("schneider", "modicon", "m340", "m580", "control expert"),
    "Mitsubishi Electric": ("mitsubishi", "melsec", "iq-r", "iq-f", "fx5"),
    "ABB": ("abb", "ac500", "800xa"),
    "Beckhoff": ("beckhoff", "twincat", "cx9020", "cx2040"),
    "Omron": ("omron", "nj-series", "nx-series"),
    "WAGO": ("wago", "pfc200", "pfc100"),
    "Yokogawa": ("yokogawa", "fa-m3", "centum"),
    "Emerson": ("emerson", "roc800", "rx3i"),
}

MODEL_FAMILY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Siemens SIMATIC S7-1200", re.compile(r"\bS7[- ]?1200\b", re.I)),
    ("Siemens SIMATIC S7-1500", re.compile(r"\bS7[- ]?1500\b", re.I)),
    ("Siemens SIMATIC S7-300", re.compile(r"\bS7[- ]?300\b", re.I)),
    ("Siemens SIMATIC S7-400", re.compile(r"\bS7[- ]?400\b", re.I)),
    ("Rockwell ControlLogix", re.compile(r"\bCONTROLLOGIX\b", re.I)),
    ("Rockwell CompactLogix", re.compile(r"\bCOMPACTLOGIX\b", re.I)),
    ("Schneider Modicon M580", re.compile(r"\bM580\b", re.I)),
    ("Schneider Modicon M340", re.compile(r"\bM340\b", re.I)),
    ("Mitsubishi MELSEC iQ-R", re.compile(r"\bMELSEC\s*iQ[- ]?R\b", re.I)),
    ("Mitsubishi MELSEC iQ-F", re.compile(r"\bMELSEC\s*iQ[- ]?F\b", re.I)),
)


def canonical_vendor(value: str | None, *, source: str = "owner-inventory") -> tuple[str | None, str]:
    if not value:
        return None, "not-supplied"
    normalized = value.casefold().strip()
    for canonical, aliases in VENDOR_ALIASES.items():
        if normalized == canonical.casefold() or any(alias in normalized for alias in aliases):
            return canonical, source
    return None, "unclassified"


def identify_cip_vendor(vendor_id: int) -> dict[str, str | int]:
    known = CIP_VENDOR_IDS.get(vendor_id)
    if known:
        return {"vendor_id": vendor_id, **known}
    return {
        "vendor_id": vendor_id,
        "manufacturer": "Unknown / not mapped",
        "confidence": "none",
        "source": "CIP Vendor ID not present in PLCSEC's conservative built-in mapping",
    }


def enrich_report_vendors(report: dict[str, Any]) -> dict[str, Any]:
    """Return manufacturer hints without overwriting owner-provided inventory values."""
    events_by_ip: dict[str, list[dict[str, Any]]] = {}
    for event in report.get("events", []):
        if isinstance(event, dict):
            endpoint = event.get("server_ip") or event.get("dst_ip")
            if isinstance(endpoint, str):
                events_by_ip.setdefault(endpoint, []).append(event)

    for asset in report.get("assets", []):
        if not isinstance(asset, dict):
            continue
        ip = asset.get("ip")
        metadata = asset.get("inventory_metadata") or {}
        explicit_vendor, source = canonical_vendor(metadata.get("vendor"))
        model = str(metadata.get("model") or "")
        family = None
        for family_name, pattern in MODEL_FAMILY_PATTERNS:
            if pattern.search(model):
                family = family_name
                break

        cip_observations: list[dict[str, Any]] = []
        modbus_claims: list[dict[str, Any]] = []
        for event in events_by_ip.get(ip, []):
            if event.get("event_type") == "list_identity" and isinstance(event.get("vendor_id"), int):
                cip_observations.append(identify_cip_vendor(event["vendor_id"]))
            elif event.get("event_type") == "modbus_device_identity":
                modbus_claims.append({
                    "vendor_name": event.get("vendor_name"),
                    "product_name": event.get("product_name"),
                    "model_name": event.get("model_name"),
                    "source": "device-self-reported-modbus-object-dictionary",
                    "confidence": "low",
                })

        # Prefer owner-supplied context, then explicitly reviewed CIP IDs, then
        # lower-confidence Modbus self-reported strings.
        cip_vendor = next((item for item in cip_observations if item.get("confidence") == "high" and item.get("manufacturer") not in (None, "Unknown / not mapped")), None)
        # Modbus identity objects are self-reported strings, never cryptographic identity.
        reported_vendor, reported_source = canonical_vendor(
            next((str(item["vendor_name"]) for item in modbus_claims if item.get("vendor_name")), None),
            source="modbus-self-reported",
        )
        reported_model = next((str(item["model_name"]) for item in modbus_claims if item.get("model_name")), "")
        if explicit_vendor is not None:
            selected_vendor, selected_source = explicit_vendor, source
        elif cip_vendor is not None:
            selected_vendor, selected_source = str(cip_vendor["manufacturer"]), str(cip_vendor["source"])
        elif reported_vendor is not None:
            selected_vendor, selected_source = reported_vendor, reported_source
        else:
            selected_vendor, selected_source = None, source
        if not family and reported_model:
            for family_name, pattern in MODEL_FAMILY_PATTERNS:
                if pattern.search(reported_model):
                    family = family_name
                    break

        profile: dict[str, Any] = {
            "manufacturer": selected_vendor,
            "manufacturer_source": selected_source,
            "owner_supplied_vendor_raw": metadata.get("vendor"),
            "modbus_vendor_claims_are_self_reported": True,
            "model_family_hint": family,
            "cip_identity_observations": cip_observations,
            "modbus_self_reported_identity": modbus_claims,
            "confidence_note": "Owner inventory is authoritative context. Modbus identification strings are self-reported and low confidence. CIP vendor mapping is asserted only for explicitly mapped IDs. Protocol ports alone do not establish manufacturer identity.",
        }
        if selected_vendor or family or cip_observations or modbus_claims:
            try:
                from plcsec.vendor_database import list_vendors
                database_profile = next((item for item in list_vendors() if item.get("name") == selected_vendor), None)
            except Exception:
                database_profile = None
            if database_profile:
                profile["database_profile_id"] = database_profile.get("id")
                profile["protocol_hints"] = database_profile.get("protocol_hints", [])
                profile["model_families"] = database_profile.get("model_families", [])
                profile["database_identity_confidence"] = database_profile.get("identity_confidence")
            asset.setdefault("inventory_metadata", {})["plcsec_manufacturer_profile"] = profile
    return report
