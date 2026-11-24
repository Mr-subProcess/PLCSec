from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 64 * 1024 * 1024


def _header_escape(value: object, limit: int = 512) -> str:
    return str(value)[:limit].replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _ext_escape(value: object) -> str:
    return (str(value)[:8192].replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r", " ").replace("\n", " "))


def _severity(value: object) -> int:
    return {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}.get(str(value).lower(), 3)


def finding_to_cef(finding: dict[str, Any], *, device_version: str = "0.6.0") -> str:
    severity = _severity(finding.get("severity", "info"))
    finding_id = _header_escape(finding.get("finding_id", "PLCSEC-FINDING"), 128)
    name = _header_escape(finding.get("title", "PLCSEC finding"), 512)
    evidence = finding.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}
    fields: list[tuple[str, object]] = [
        ("externalId", finding.get("finding_id", "")),
        ("msg", finding.get("description", "")),
        ("cn1", finding.get("priority_score", 0)),
        ("cn1Label", "PLCSEC priority score"),
        ("cs1", finding.get("confidence", "unknown")),
        ("cs1Label", "PLCSEC confidence"),
        ("cs2", finding.get("source", "plcsec")),
        ("cs2Label", "PLCSEC source"),
    ]
    for source_key, cef_key in (("ip", "dhost"), ("src_ip", "src"), ("dst_ip", "dst"), ("src_port", "spt"), ("dst_port", "dpt")):
        value = evidence.get(source_key)
        if isinstance(value, (str, int)) and value != "":
            fields.append((cef_key, value))
    extension = " ".join(f"{key}={_ext_escape(value)}" for key, value in fields)
    return f"CEF:0|PLCSEC|Industrial Security Framework|{_header_escape(device_version, 64)}|{finding_id}|{name}|{severity}|{extension}"


def export_cef_report(input_path: str | Path, output_path: str | Path) -> dict[str, Any]:
    source = Path(input_path)
    if not source.is_file() or source.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Input report is missing or exceeds the 64 MiB limit")
    report = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("Input PLCSEC report must be a JSON object")
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("Report findings must be an array")
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [finding_to_cef(item, device_version=str(report.get("tool_version", "0.6.0")))
             for item in findings if isinstance(item, dict)]
    target.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return {"output": str(target), "event_count": len(lines), "format": "CEF:0"}
