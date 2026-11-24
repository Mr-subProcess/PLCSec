from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FRAMEWORK_REFERENCES = {
    "nist": "NIST SP 800-82 Rev. 3 — Guide to Operational Technology (OT) Security",
    "iec": "IEC 62443 series — informative mapping to foundational-requirement themes; consult licensed, applicable editions",
}

# Informative theme-level crosswalk only. No certification or control-effectiveness claim.
RULES: tuple[dict[str, Any], ...] = (
    {
        "key": "asset_inventory",
        "tags_any": ["asset-inventory", "unregistered-observation", "service-drift", "visibility-gap"],
        "iec_62443_themes": ["FR 1 — Identification and authentication control", "FR 3 — System integrity", "FR 7 — Resource availability"],
        "nist_800_82_themes": ["OT asset inventory and system documentation", "Configuration and change management", "Continuous monitoring"],
        "review_question": "Is this endpoint approved, owned, documented, and included in the current OT asset inventory?",
    },
    {
        "key": "restricted_data_flow",
        "tags_any": ["zone-conduit", "cross-zone-flow", "management-plane", "cleartext-ot", "legacy-protocol"],
        "iec_62443_themes": ["FR 5 — Restricted data flow"],
        "nist_800_82_themes": ["Network segmentation and boundary protection", "OT/IT separation", "Secure remote access paths"],
        "review_question": "Is this communication path explicitly approved by the zone/conduit design and protected by suitable boundary controls?",
    },
    {
        "key": "use_control_and_change_governance",
        "tags_any": ["write-capable-traffic", "process-change-path", "engineering-access"],
        "iec_62443_themes": ["FR 2 — Use control", "FR 6 — Timely response to events"],
        "nist_800_82_themes": ["Account management and least privilege", "Change control", "Audit and accountability"],
        "review_question": "Was this engineering or write-capable activity performed by an authorized role under an approved change record?",
    },
    {
        "key": "communication_integrity_and_confidentiality",
        "tags_any": ["tls", "certificate", "opcua-security", "cleartext-ot"],
        "iec_62443_themes": ["FR 3 — System integrity", "FR 4 — Data confidentiality"],
        "nist_800_82_themes": ["Communication protection", "Cryptographic protection where supported", "Certificate lifecycle management"],
        "review_question": "Does the deployed protocol configuration provide the required authentication, integrity, and confidentiality for this zone?",
    },
    {
        "key": "resource_and_recovery_resilience",
        "tags_any": ["availability", "tcp-reassembly", "resource-limit", "truncated"],
        "iec_62443_themes": ["FR 7 — Resource availability"],
        "nist_800_82_themes": ["Resilience and recovery planning", "Resource management", "Monitoring coverage"],
        "review_question": "Could this observation affect visibility, resilience, or recovery, and are independent monitoring and recovery controls available?",
    },
)


def crosswalk_report(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings", [])
    mapped: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        tags = set(finding.get("tags") or [])
        matches = []
        for rule in RULES:
            if tags.intersection(rule["tags_any"]):
                matches.append({
                    "category": rule["key"],
                    "iec_62443_themes": rule["iec_62443_themes"],
                    "nist_800_82_themes": rule["nist_800_82_themes"],
                    "review_question": rule["review_question"],
                })
        if matches:
            mapped.append({
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "mappings": matches,
                "interpretation": "Informative evidence crosswalk; requires human assessment and additional evidence.",
            })
    return {
        "schema": "plcsec.compliance-crosswalk.v1",
        "is_certification": False,
        "source_report_schema": report.get("schema_version"),
        "source_tool_version": report.get("tool_version"),
        "framework_references": FRAMEWORK_REFERENCES,
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "mapped_finding_count": len(mapped),
        "mappings": mapped,
        "limitations": [
            "This is not a compliance assessment, certification, audit opinion, or control effectiveness score.",
            "IEC 62443 references are theme-level only; consult licensed, applicable editions and assess the full system scope.",
            "NIST SP 800-82 themes provide guidance and do not establish compliance by themselves.",
            "A passive capture is incomplete evidence and does not prove absence of activity or control failure.",
        ],
    }


def crosswalk_file(input_path: str | Path, output_path: str | Path) -> dict[str, Any]:
    source = Path(input_path)
    target = Path(output_path)
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("findings", []), list):
        raise ValueError("Input must be a PLCSEC JSON assessment report")
    result = crosswalk_report(data)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result
