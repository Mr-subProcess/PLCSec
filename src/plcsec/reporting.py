from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

from plcsec.models import AssessmentReport


def _csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formula prefixes in untrusted CSV text cells."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def _write_safe_row(writer: csv.DictWriter, row: dict[str, Any]) -> None:
    writer.writerow({key: _csv_safe(value) for key, value in row.items()})


def write_json(report: AssessmentReport, path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return output


def write_csv(report: AssessmentReport, output_base: str | Path) -> list[Path]:
    base = Path(output_base)
    if base.suffix:
        base = base.with_suffix("")
    base.parent.mkdir(parents=True, exist_ok=True)
    data = report.to_dict()
    asset_path = base.with_name(base.name + "_assets.csv")
    with asset_path.open("w", newline="", encoding="utf-8") as stream:
        fields = ["ip", "inventory_asset_id", "hostname", "vendor", "model", "firmware", "role", "owner", "criticality", "zone", "mac_addresses", "packets_seen", "first_seen", "last_seen", "labels", "vendor_hints", "services"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for asset in data["assets"]:
            _write_safe_row(writer, {
                "ip": asset["ip"],
                "inventory_asset_id": asset.get("inventory_metadata", {}).get("asset_id", ""),
                "hostname": asset.get("inventory_metadata", {}).get("hostname", ""),
                "vendor": asset.get("inventory_metadata", {}).get("vendor", ""),
                "model": asset.get("inventory_metadata", {}).get("model", ""),
                "firmware": asset.get("inventory_metadata", {}).get("firmware", ""),
                "role": asset.get("inventory_metadata", {}).get("role", ""),
                "owner": asset.get("inventory_metadata", {}).get("owner", ""),
                "criticality": asset.get("inventory_metadata", {}).get("criticality", ""),
                "zone": asset.get("inventory_metadata", {}).get("zone", ""),
                "mac_addresses": ";".join(asset["mac_addresses"]),
                "packets_seen": asset["packets_seen"],
                "first_seen": asset["first_seen"] or "",
                "last_seen": asset["last_seen"] or "",
                "labels": ";".join(asset.get("labels", [])),
                "vendor_hints": ";".join(asset.get("vendor_hints", [])),
                "services": ";".join(f"{s['protocol']}:{s['port']}" for s in asset["observed_services"]),
            })
    flow_path = base.with_name(base.name + "_flows.csv")
    with flow_path.open("w", newline="", encoding="utf-8") as stream:
        fields = ["src_ip", "src_port", "dst_ip", "dst_port", "transport", "packets", "bytes_observed", "first_seen", "last_seen"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for flow in data.get("flows", []):
            _write_safe_row(writer, {key: flow.get(key, "") for key in fields})
    finding_path = base.with_name(base.name + "_findings.csv")
    with finding_path.open("w", newline="", encoding="utf-8") as stream:
        fields = ["finding_id", "severity", "priority_score", "title", "description", "confidence", "source", "recommendation", "tags", "evidence_json"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for finding in data["findings"]:
            _write_safe_row(writer, {
                "finding_id": finding["finding_id"],
                "severity": finding["severity"],
                "priority_score": finding.get("priority_score", 0),
                "title": finding["title"],
                "description": finding["description"],
                "confidence": finding["confidence"],
                "source": finding["source"],
                "recommendation": finding["recommendation"],
                "tags": ";".join(finding.get("tags", [])),
                "evidence_json": json.dumps(finding["evidence"], ensure_ascii=False, sort_keys=True),
            })
    return [asset_path, flow_path, finding_path]


def write_html(report: AssessmentReport, path: str | Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    data = report.to_dict()
    findings_rows = []
    for finding in sorted(data["findings"], key=lambda row: (row.get("priority_score", 0), row["severity"]), reverse=True):
        findings_rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding['severity']).upper())}</td>"
            f"<td>{int(finding.get('priority_score', 0))}</td>"
            f"<td>{html.escape(str(finding['title']))}</td>"
            f"<td>{html.escape(str(finding['description']))}</td>"
            f"<td><pre>{html.escape(json.dumps(finding['evidence'], indent=2, ensure_ascii=False))}</pre></td>"
            "</tr>"
        )
    assets_rows = []
    for asset in data["assets"]:
        service_text = ", ".join(f"{s['protocol']}:{s['port']} ({s['packets']} pkts)" for s in asset["observed_services"])
        assets_rows.append(
            "<tr>"
            f"<td>{html.escape(asset['ip'])}</td>"
            f"<td>{html.escape(', '.join(asset['mac_addresses']))}</td>"
            f"<td>{html.escape(str(asset.get('inventory_metadata', {}).get('asset_id', '')))} / {html.escape(str(asset.get('inventory_metadata', {}).get('vendor', '')))} {html.escape(str(asset.get('inventory_metadata', {}).get('model', '')))} / {html.escape(str(asset.get('inventory_metadata', {}).get('criticality', '')))}</td>"
            f"<td>{html.escape(service_text)}</td>"
            f"<td>{asset['packets_seen']}</td>"
            "</tr>"
        )
    summary = {
        "schema_version": data.get("schema_version"),
        "assessment_type": data["assessment_type"],
        "started_at": data["started_at"],
        "completed_at": data["completed_at"],
        "scope": data["scope"],
        "metadata": data["metadata"],
    }
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PLCSEC Assessment Report</title>
<style>
:root{{--bg:#f3f6f8;--panel:#fff;--ink:#17212b;--muted:#536273;--line:#dce2e8;--accent:#174a6e}}
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--ink);margin:0;padding:2rem;line-height:1.5}}
main{{max-width:1400px;margin:auto}}header,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.2rem;margin-bottom:1rem}}
h1{{margin:.1rem 0;color:var(--accent)}}h2{{font-size:1.15rem;margin-top:0}}.muted{{color:var(--muted)}}
table{{border-collapse:collapse;width:100%;font-size:.92rem}}th,td{{border-bottom:1px solid var(--line);padding:.65rem;text-align:left;vertical-align:top}}th{{background:#eef3f7}}pre{{white-space:pre-wrap;max-width:520px;overflow-wrap:anywhere;margin:0}}
code{{background:#eef3f7;padding:.1rem .25rem;border-radius:4px}}.notice{{border-left:4px solid #c27b24;padding:.7rem 1rem;background:#fff8eb}}
</style></head><body><main>
<header><h1>PLCSEC Assessment Report</h1><div class="muted">Version {html.escape(data['tool_version'])} · {html.escape(data['assessment_type'])}</div></header>
<section class="panel"><h2>Assessment metadata</h2><pre>{html.escape(json.dumps(summary, indent=2, ensure_ascii=False))}</pre></section>
<section class="panel"><h2>Observed assets ({len(data['assets'])})</h2><table><thead><tr><th>IP</th><th>MAC addresses</th><th>Inventory context</th><th>Observed services</th><th>Packets</th></tr></thead><tbody>{''.join(assets_rows) or '<tr><td colspan="5">No IP assets observed.</td></tr>'}</tbody></table></section>
<section class="panel"><h2>Observed flows ({len(data.get('flows', []))})</h2><pre>{html.escape(json.dumps(data.get('flows', [])[:250], indent=2, ensure_ascii=False))}</pre></section>
<section class="panel"><h2>Prioritized findings ({len(data['findings'])})</h2><table><thead><tr><th>Severity</th><th>Priority</th><th>Finding</th><th>Description</th><th>Evidence</th></tr></thead><tbody>{''.join(findings_rows) or '<tr><td colspan="5">No findings generated.</td></tr>'}</tbody></table></section>
<section class="panel"><h2>Protocol events ({len(data.get('events', []))})</h2><pre>{html.escape(json.dumps(data.get('events', [])[:250], indent=2, ensure_ascii=False))}</pre></section>
<section class="panel notice"><strong>Interpretation:</strong> Passive observations are evidence of traffic captured at one vantage point, not proof of exploitability, misconfiguration, or reachability from another network. Validate findings with the asset owner and process engineering team before taking action.</section>
<footer class="muted">Generated by PLCSEC. Treat this report as sensitive operational information.</footer>
</main></body></html>"""
    output.write_text(document, encoding="utf-8")
    return output


def write_report(report: AssessmentReport, output_base: str | Path, report_format: str) -> list[Path]:
    base = Path(output_base)
    if base.suffix:
        base = base.with_suffix("")
    paths: list[Path] = []
    if report_format in ("json", "both", "all"):
        paths.append(write_json(report, base.with_suffix(".json")))
    if report_format in ("html", "both", "all"):
        paths.append(write_html(report, base.with_suffix(".html")))
    if report_format in ("csv", "all"):
        paths.extend(write_csv(report, base))
    return paths
