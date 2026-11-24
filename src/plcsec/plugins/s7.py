from __future__ import annotations

from importlib import import_module
from typing import Any

from plcsec.models import Asset, AssessmentReport, Finding, ServiceObservation, Severity, to_jsonable


def audit_s7_identity(
    target: str,
    rack: int = 0,
    slot: int = 1,
    port: int = 102,
) -> AssessmentReport:
    """Read S7 CPU/order-code identity only. No process memory or control services."""
    try:
        snap7 = import_module("snap7")
    except ImportError as exc:
        raise RuntimeError("S7 identification requires python-snap7. Install with: pip install 'plcsec[s7]'") from exc

    if not 0 <= rack <= 7 or not 0 <= slot <= 31:
        raise ValueError("Rack must be 0..7 and slot must be 0..31")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    report = AssessmentReport.create(
        "active-read-only-s7-identification",
        {"target": target, "port": port, "rack": rack, "slot": slot, "operations": ["get_cpu_info", "get_order_code"]},
    )
    client = snap7.Client(auto_reconnect=False, max_retries=0)
    try:
        client.connect(target, rack, slot, tcp_port=port)
        cpu_info: Any = client.get_cpu_info()
        order_code: Any = client.get_order_code()
        report.assets.append(Asset(
            ip=target,
            observed_services=[ServiceObservation(protocol="S7comm (ISO-on-TCP)", port=port, notes=["Active identity check completed; packet count not measured."])],
        ))
        evidence = {
            "cpu_info": to_jsonable(cpu_info),
            "order_code_and_firmware": to_jsonable(order_code),
        }
        report.findings.append(Finding(
            finding_id="S7-IDENTITY-READ",
            title="Siemens S7 identity query completed",
            severity=Severity.INFO,
            description="CPU identification and order-code information were read. No PLC memory areas were read or changed.",
            evidence=evidence,
            recommendation="Compare the identity and firmware revision against the vendor lifecycle and approved asset inventory.",
            confidence="high",
            source="active-read-only-python-snap7",
        ))
        report.metadata["writes_sent"] = 0
        report.metadata["memory_area_reads"] = 0
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
    report.finish()
    return report
