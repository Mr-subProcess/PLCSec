from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from plcsec import __version__
from plcsec.baseline import build_baseline, compare_to_baseline, load_baseline, write_baseline
from plcsec.policy import AuthorizationError, require_authorized_target
from plcsec.reporting import write_report

MODULES = [
    ("pcap.passive", "Bounded TCP reassembly and multi-protocol passive analysis", "available"),
    ("protocol.modbus.tcp", "Modbus/TCP MBAP and function-code parsing", "available"),
    ("protocol.s7comm.tpkt", "S7comm over TPKT/COTP framing and metadata parsing", "available"),
    ("protocol.ethernet_ip.cip", "EtherNet/IP encapsulation, CPF, ListIdentity, and bounded CIP services", "available"),
    ("protocol.opcua.uacp", "OPC UA TCP message framing, OPN metadata and certificate export", "available"),
    ("security.opcua.x509", "Offline OPC UA application-certificate path review against supplied trust anchors", "available: cryptography"),
    ("report.ed25519", "Detached Ed25519 signatures for JSON/HTML evidence reports", "available: cryptography"),
    ("baseline.approval", "Signed human approval attestations bound to passive baseline hashes", "available: cryptography"),
    ("firmware.container-metadata", "Bounded ZIP/CPIO/ELF/SquashFS/ext/FDT/U-Boot metadata inspection without extraction", "available"),
    ("protocol.tls.dtls", "TLS/DTLS record and visible ClientHello/ServerHello metadata", "available"),
    ("protocol.iec104.apci", "IEC 60870-5-104 APDU framing and ASDU header metadata", "available"),
    ("protocol.dnp3.link", "DNP3 data-link framing, header CRC and per-block CRC validation", "available"),
    ("protocol.bacnet.bvlc", "BACnet/IP BVLC and basic NPDU metadata", "available"),
    ("baseline.asset-drift", "Passive asset/service/MAC baseline comparison", "available"),
    ("inventory.reconciliation", "Owner-provided asset inventory enrichment and drift review", "available"),
    ("report.csv", "Asset and prioritized-finding CSV exports", "available"),
    ("audit.modbus.device-id", "One-request Modbus Read Device Identification", "available"),
    ("audit.s7.identity", "Read-only Siemens S7 CPU/order-code identity", "optional: python-snap7"),
    ("compliance.nist-800-82", "Evidence mapping to NIST OT security guidance", "partial mapping"),
    ("compliance.iec-62443", "IEC 62443 control-theme references, not certification", "informative mapping"),
    ("firmware.offline", "Bounded firmware hashing, entropy, strings and format hints; no execution", "available"),
    ("baseline.ed25519", "Detached Ed25519 signatures for passive baselines", "optional: cryptography"),
    ("manufacturer.profiles", "Conservative vendor/model enrichment from explicit metadata and known CIP IDs", "available"),
    ("export.stix21", "STIX 2.1 observations and finding notes for CTI/SIEM exchange", "available"),
    ("export.cef", "ArcSight Common Event Format finding export", "available"),
    ("audit.hash-chain", "SQLite tamper-evident hash-chained assessment evidence log", "available"),
    ("protocol.dnp3.crc", "DNP3 link header and 16-octet data-block CRC validation", "available"),
    ("compliance.crosswalk", "Evidence-to-framework theme crosswalk for NIST SP 800-82 and IEC 62443", "informative mapping"),
    ("advisories.exact", "Offline exact-match advisory correlation against operator-supplied vendor/product/firmware feeds", "available"),
]


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="plcsec",
        description="PLCSEC: safety-first industrial controller inventory and passive security analysis.",
        epilog="Passive analysis is the default. Active identity checks require explicit authorization and a target allowlist.",
    )
    parser.add_argument("--version", action="version", version=f"PLCSEC {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    modules = subparsers.add_parser("modules", help="List framework modules")
    modules.add_argument("action", choices=["list"])
    modules.add_argument("--format", choices=["text", "json"], default="text")

    pcap = subparsers.add_parser("pcap", help="Offline, passive capture analysis")
    pcap_sub = pcap.add_subparsers(dest="pcap_action", required=True)
    analyze = pcap_sub.add_parser("analyze", help="Analyze a PCAP/PCAPNG file")
    _add_capture_options(analyze)

    baseline = pcap_sub.add_parser("baseline", help="Create or compare passive site baselines")
    baseline_sub = baseline.add_subparsers(dest="baseline_action", required=True)
    create = baseline_sub.add_parser("create", help="Create a passive baseline from a capture")
    _add_capture_options(create, include_format=False, include_output=False)
    create.add_argument("--site-id", required=True)
    create.add_argument("--baseline-out", required=True, type=Path)

    compare = baseline_sub.add_parser("compare", help="Compare a capture with a saved baseline")
    _add_capture_options(compare)
    compare.add_argument("--baseline", required=True, type=Path)
    compare.add_argument("--signature", type=Path, help="Optional detached Ed25519 signature sidecar")
    compare.add_argument("--public-key", type=Path, help="Public key used to verify the baseline signature")
    compare.add_argument("--require-signature", action="store_true", help="Fail unless a valid signature is provided")

    site_profile = subparsers.add_parser("site-profile", help="Validate an offline OT zone/conduit profile")
    site_profile.add_argument("action", choices=["validate"])
    site_profile.add_argument("--input", required=True, type=Path)

    inventory = subparsers.add_parser("inventory", help="Validate an owner-provided asset inventory")
    inventory.add_argument("action", choices=["validate"])
    inventory.add_argument("--input", required=True, type=Path)

    baseline_tools = subparsers.add_parser("baseline", help="Manage and verify signed passive baselines")
    baseline_tools_sub = baseline_tools.add_subparsers(dest="baseline_tool_action", required=True)
    keygen = baseline_tools_sub.add_parser("keygen", help="Generate an Ed25519 signing key pair")
    keygen.add_argument("--private-key", required=True, type=Path)
    keygen.add_argument("--public-key", required=True, type=Path)
    keygen.add_argument("--force", action="store_true")
    sign = baseline_tools_sub.add_parser("sign", help="Sign a baseline using an Ed25519 private key")
    sign.add_argument("--input", required=True, type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--signature", required=True, type=Path)
    verify = baseline_tools_sub.add_parser("verify", help="Verify a detached baseline signature")
    verify.add_argument("--input", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    verify.add_argument("--signature", required=True, type=Path)
    approve = baseline_tools_sub.add_parser("approve", help="Create a signed human approval record bound to a baseline hash")
    approve.add_argument("--input", required=True, type=Path)
    approve.add_argument("--approved-by", required=True)
    approve.add_argument("--reason", required=True)
    approve.add_argument("--private-key", required=True, type=Path)
    approve.add_argument("--out", required=True, type=Path)
    approve.add_argument("--signature", required=True, type=Path)
    verify_approval = baseline_tools_sub.add_parser("verify-approval", help="Verify a signed baseline approval")
    verify_approval.add_argument("--input", required=True, type=Path)
    verify_approval.add_argument("--approval", required=True, type=Path)
    verify_approval.add_argument("--signature", required=True, type=Path)
    verify_approval.add_argument("--public-key", required=True, type=Path)

    firmware = subparsers.add_parser("firmware", help="Offline analysis of inert firmware images")
    firmware_sub = firmware.add_subparsers(dest="firmware_action", required=True)
    firmware_analyze = firmware_sub.add_parser("analyze", help="Hash and inspect a firmware file without executing it")
    firmware_analyze.add_argument("--input", required=True, type=Path)
    firmware_analyze.add_argument("--out", required=True, type=Path)
    firmware_analyze.add_argument("--max-mb", type=int, default=2048)

    opcua = subparsers.add_parser("opcua", help="Offline OPC UA certificate review and extraction")
    opcua_sub = opcua.add_subparsers(dest="opcua_action", required=True)
    cert_audit = opcua_sub.add_parser("cert-audit", help="Validate one OPC UA application certificate against supplied local trust anchors")
    cert_audit.add_argument("--leaf", required=True, type=Path)
    cert_audit.add_argument("--intermediate", action="append", type=Path, default=[])
    cert_audit.add_argument("--trust-anchor", action="append", type=Path, default=[])
    cert_audit.add_argument("--expected-application-uri")
    cert_audit.add_argument("--expected-dns-name")
    cert_audit.add_argument("--out", required=True, type=Path)
    cert_export = opcua_sub.add_parser("cert-export", help="Export public OPC UA certificates retained in a JSON PCAP report")
    cert_export.add_argument("--report", required=True, type=Path)
    cert_export.add_argument("--out-dir", required=True, type=Path)
    cert_export.add_argument("--max-certificates", type=int, default=128)

    report_tools = subparsers.add_parser("report", help="Sign and verify generated evidence reports")
    report_sub = report_tools.add_subparsers(dest="report_action", required=True)
    report_sign = report_sub.add_parser("sign", help="Create a detached Ed25519 report signature")
    report_sign.add_argument("--input", required=True, type=Path)
    report_sign.add_argument("--private-key", required=True, type=Path)
    report_sign.add_argument("--signature", required=True, type=Path)
    report_verify = report_sub.add_parser("verify", help="Verify a detached report signature")
    report_verify.add_argument("--input", required=True, type=Path)
    report_verify.add_argument("--public-key", required=True, type=Path)
    report_verify.add_argument("--signature", required=True, type=Path)
    report_verify.add_argument("--expected-type", default="assessment-report")

    compliance = subparsers.add_parser("compliance", help="Informative evidence crosswalks; not certification")
    compliance_sub = compliance.add_subparsers(dest="compliance_action", required=True)
    crosswalk = compliance_sub.add_parser("crosswalk", help="Map report findings to framework review themes")
    crosswalk.add_argument("--input", required=True, type=Path)
    crosswalk.add_argument("--out", required=True, type=Path)

    export = subparsers.add_parser("export", help="Export assessment data to security tooling formats")
    export_sub = export.add_subparsers(dest="export_action", required=True)
    export_stix = export_sub.add_parser("stix", help="Export a PLCSEC JSON report as a STIX 2.1 bundle")
    export_stix.add_argument("--input", required=True, type=Path)
    export_stix.add_argument("--out", required=True, type=Path)
    export_cef = export_sub.add_parser("cef", help="Export report findings as ArcSight CEF")
    export_cef.add_argument("--input", required=True, type=Path)
    export_cef.add_argument("--out", required=True, type=Path)

    audit_log = subparsers.add_parser("audit-log", help="Manage the local tamper-evident evidence log")
    audit_log_sub = audit_log.add_subparsers(dest="audit_log_action", required=True)
    audit_log_init = audit_log_sub.add_parser("init", help="Initialize a local audit evidence database")
    audit_log_init.add_argument("--db", required=True, type=Path)
    audit_log_record = audit_log_sub.add_parser("record-report", help="Record an assessment report hash and summary")
    audit_log_record.add_argument("--db", required=True, type=Path)
    audit_log_record.add_argument("--input", required=True, type=Path)
    audit_log_record.add_argument("--actor", required=True)
    audit_log_verify = audit_log_sub.add_parser("verify", help="Verify the local audit hash chain")
    audit_log_verify.add_argument("--db", required=True, type=Path)
    audit_log_export = audit_log_sub.add_parser("export", help="Export a verified audit log as JSON Lines")
    audit_log_export.add_argument("--db", required=True, type=Path)
    audit_log_export.add_argument("--out", required=True, type=Path)
    audit_log_checkpoint = audit_log_sub.add_parser("checkpoint-sign", help="Create and Ed25519-sign an external chain-head checkpoint")
    audit_log_checkpoint.add_argument("--db", required=True, type=Path)
    audit_log_checkpoint.add_argument("--out", required=True, type=Path)
    audit_log_checkpoint.add_argument("--private-key", required=True, type=Path)
    audit_log_checkpoint.add_argument("--signature", required=True, type=Path)
    audit_log_checkpoint_verify = audit_log_sub.add_parser("checkpoint-verify", help="Verify signed checkpoint and current audit database head")
    audit_log_checkpoint_verify.add_argument("--db", required=True, type=Path)
    audit_log_checkpoint_verify.add_argument("--checkpoint", required=True, type=Path)
    audit_log_checkpoint_verify.add_argument("--public-key", required=True, type=Path)
    audit_log_checkpoint_verify.add_argument("--signature", required=True, type=Path)

    advisories = subparsers.add_parser("advisories", help="Validate and match operator-supplied offline product advisories")
    advisories_sub = advisories.add_subparsers(dest="advisories_action", required=True)
    advisories_validate = advisories_sub.add_parser("validate", help="Validate an offline advisory database")
    advisories_validate.add_argument("--input", required=True, type=Path)
    advisories_match = advisories_sub.add_parser("match", help="Match exact vendor/product/firmware strings against an asset inventory")
    advisories_match.add_argument("--inventory", required=True, type=Path)
    advisories_match.add_argument("--database", required=True, type=Path)
    advisories_match.add_argument("--out", required=True, type=Path)

    vendors = subparsers.add_parser("vendors", help="Enrich reports with conservative manufacturer profiles")
    vendors_sub = vendors.add_subparsers(dest="vendors_action", required=True)
    vendor_enrich = vendors_sub.add_parser("enrich", help="Apply owner metadata and known CIP vendor ID mappings")
    vendor_enrich.add_argument("--input", required=True, type=Path)
    vendor_enrich.add_argument("--out", required=True, type=Path)
    vendor_database = vendors_sub.add_parser("database", help="List the conservative built-in manufacturer profile database")
    vendor_database.add_argument("--format", choices=["json", "text"], default="text")
    vendor_database.add_argument("--out", type=Path, help="Optional JSON export path")

    audit = subparsers.add_parser("audit", help="Authorized, narrowly scoped read-only identity checks")
    audit_sub = audit.add_subparsers(dest="audit_action", required=True)
    modbus = audit_sub.add_parser("modbus-id", help="One Modbus Read Device Identification query")
    _add_active_common(modbus)
    modbus.add_argument("--port", type=int, default=502)
    modbus.add_argument("--unit-id", type=int, default=1)
    modbus.add_argument("--timeout", type=float, default=2.0)
    modbus.add_argument("--out", type=Path, required=True)
    modbus.add_argument("--format", choices=["json", "html", "csv", "both", "all"], default="both")

    s7 = audit_sub.add_parser("s7-id", help="Siemens S7 CPU/order-code identity query only")
    _add_active_common(s7)
    s7.add_argument("--port", type=int, default=102)
    s7.add_argument("--rack", type=int, default=0)
    s7.add_argument("--slot", type=int, default=1)
    s7.add_argument("--out", type=Path, required=True)
    s7.add_argument("--format", choices=["json", "html", "csv", "both", "all"], default="both")
    return parser


def _add_capture_options(parser, include_format: bool = True, include_output: bool = True) -> None:
    parser.add_argument("--input", required=True, type=Path)
    if include_output:
        parser.add_argument("--out", required=True, type=Path, help="Output base path without extension")
    parser.add_argument("--max-packets", type=int, default=5_000_000)
    parser.add_argument("--max-stream-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--max-flows", type=int, default=100_000)
    parser.add_argument("--max-assets", type=int, default=100_000)
    parser.add_argument("--max-services", type=int, default=100_000)
    parser.add_argument("--max-segments", type=int, default=250_000)
    parser.add_argument("--max-total-stream-mb", type=int, default=256)
    parser.add_argument("--site-profile", type=Path, help="Optional offline zone/conduit profile JSON")
    parser.add_argument("--inventory", type=Path, help="Optional owner-provided asset inventory JSON")
    parser.add_argument("--include-opcua-certs", action="store_true", help="Retain public OPC UA certificate DER in JSON events; reports may expose certificate metadata")
    if include_format:
        parser.add_argument("--format", choices=["json", "html", "csv", "both", "all"], default="all")


def _add_active_common(parser) -> None:
    parser.add_argument("--target", required=True, help="Single PLC IP address; hostnames/subnets are rejected")
    parser.add_argument("--allowlist", required=True, type=Path, help="Approved IP/CIDR allowlist")
    parser.add_argument("--authorized", action="store_true", help="Confirm written authorization and site approval")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "export":
            import json
            if args.export_action == "stix":
                from plcsec.stix_export import export_stix_report
                result = export_stix_report(args.input, args.out)
            else:
                from plcsec.cef_export import export_cef_report
                result = export_cef_report(args.input, args.out)
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "audit-log":
            import json
            from plcsec.audit_store import (
                export_jsonl, initialize_audit_store, record_report, sign_checkpoint,
                verify_audit_store, verify_checkpoint,
            )
            if args.audit_log_action == "init":
                result = initialize_audit_store(args.db)
            elif args.audit_log_action == "record-report":
                result = record_report(args.db, args.input, actor=args.actor)
            elif args.audit_log_action == "verify":
                result = verify_audit_store(args.db)
            elif args.audit_log_action == "export":
                result = export_jsonl(args.db, args.out)
            elif args.audit_log_action == "checkpoint-sign":
                result = sign_checkpoint(args.db, args.out, args.private_key, args.signature)
            else:
                result = verify_checkpoint(args.db, args.checkpoint, args.public_key, args.signature)
            print(json.dumps(result, indent=2))
            return 0 if result.get("valid", True) else 1
        if args.command == "modules":
            _print_modules(args.format)
            return 0
        if args.command == "site-profile" and args.action == "validate":
            from plcsec.site_profile import validate_site_profile
            import json
            result = validate_site_profile(args.input)
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "inventory" and args.action == "validate":
            from plcsec.inventory import validate_inventory
            import json
            result = validate_inventory(args.input)
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "baseline":
            import json
            from plcsec.signing import generate_ed25519_keypair, sign_baseline, verify_baseline
            if args.baseline_tool_action == "keygen":
                result = generate_ed25519_keypair(args.private_key, args.public_key, force=args.force)
            elif args.baseline_tool_action == "sign":
                result = sign_baseline(args.input, args.private_key, args.signature)
            elif args.baseline_tool_action == "verify":
                result = verify_baseline(args.input, args.public_key, args.signature)
            elif args.baseline_tool_action == "approve":
                from plcsec.approvals import create_baseline_approval
                result = create_baseline_approval(args.input, approved_by=args.approved_by, reason=args.reason, private_key_path=args.private_key, output_path=args.out, signature_path=args.signature)
            else:
                from plcsec.approvals import verify_baseline_approval
                result = verify_baseline_approval(args.input, args.approval, args.signature, args.public_key)
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "opcua":
            import json
            from plcsec.opcua_cert import audit_opcua_certificate_chain, export_opcua_certificates_from_report
            if args.opcua_action == "cert-audit":
                result = audit_opcua_certificate_chain(args.leaf, intermediates=args.intermediate, trust_anchors=args.trust_anchor, expected_application_uri=args.expected_application_uri, expected_dns_name=args.expected_dns_name)
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                print(json.dumps({"output": str(args.out), "trusted": result["trust"]["trusted"], "status": result["trust"]["status"], "findings": len(result["findings"]), "revocation_checked": False}, indent=2))
                return 0 if result["trust"]["trusted"] else 1
            if args.max_certificates < 1 or args.max_certificates > 1024:
                raise ValueError("max-certificates must be between 1 and 1024")
            exported = export_opcua_certificates_from_report(args.report, args.out_dir, max_certificates=args.max_certificates)
            print(json.dumps({"exported": exported, "count": len(exported)}, indent=2))
            return 0
        if args.command == "report":
            import json
            from plcsec.artifact_signing import sign_artifact, verify_artifact
            if args.report_action == "sign":
                result = sign_artifact(args.input, args.private_key, args.signature, artifact_type="assessment-report")
            else:
                result = verify_artifact(args.input, args.public_key, args.signature, expected_type=args.expected_type)
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "firmware" and args.firmware_action == "analyze":
            import json
            from plcsec.firmware import analyze_firmware
            result = analyze_firmware(args.input, max_bytes=args.max_mb * 1024 * 1024)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps({"input": str(args.input), "sha256": result["hashes"]["sha256"], "size_bytes": result["input"]["size_bytes"], "output": str(args.out), "executed": False}, indent=2))
            return 0
        if args.command == "compliance" and args.compliance_action == "crosswalk":
            import json
            from plcsec.compliance import crosswalk_file
            result = crosswalk_file(args.input, args.out)
            print(json.dumps({"output": str(args.out), "findings": result["finding_count"], "mapped_findings": result["mapped_finding_count"], "is_certification": False}, indent=2))
            return 0
        if args.command == "advisories":
            import json
            from plcsec.advisories import match_advisory_files, validate_advisory_database
            if args.advisories_action == "validate":
                result = validate_advisory_database(args.input)
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0
            result = match_advisory_files(args.inventory, args.database)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps({
                "output": str(args.out),
                "site_id": result["site_id"],
                "match_count": result["match_count"],
                "assets_missing_identity": len(result["assets_missing_identity"]),
                "is_vendor_applicability_confirmed": False,
            }, indent=2))
            return 0
        if args.command == "vendors" and args.vendors_action == "database":
            import json
            from plcsec.vendor_database import load_vendor_database
            data = load_vendor_database()
            if args.out:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if args.format == "json":
                print(json.dumps(data, indent=2))
            else:
                print(f"PLCSEC vendor database {data['database_version']}")
                for vendor in data["manufacturers"]:
                    print(f"{vendor['id']:<24} {vendor['name']}  |  {', '.join(vendor['protocol_hints'])}")
                print("Evidence policy: protocol ports alone never identify a manufacturer.")
            return 0
        if args.command == "vendors" and args.vendors_action == "enrich":
            import json
            from plcsec.manufacturers import enrich_report_vendors
            report_data = json.loads(args.input.read_text(encoding="utf-8"))
            result = enrich_report_vendors(report_data)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"[+] Vendor-enriched report written: {args.out}")
            return 0
        if args.command == "pcap" and args.pcap_action == "analyze":
            from plcsec.pcap import analyze_capture

            report = analyze_capture(args.input, max_packets=args.max_packets, max_stream_bytes=args.max_stream_bytes, max_flows=args.max_flows, max_assets=args.max_assets, max_services=args.max_services, max_segments=args.max_segments, max_total_stream_mb=args.max_total_stream_mb, include_opcua_certificates=args.include_opcua_certs)
            if args.site_profile:
                from plcsec.site_profile import apply_site_profile, load_site_profile
                report = apply_site_profile(report, load_site_profile(args.site_profile))
            if args.inventory:
                from plcsec.inventory import apply_inventory, load_inventory
                report = apply_inventory(report, load_inventory(args.inventory))
            paths = write_report(report, args.out, args.format)
            _print_report_summary(report.to_dict())
            for path in paths:
                print(f"[+] Report written: {path}")
            return 0
        if args.command == "pcap" and args.pcap_action == "baseline":
            from plcsec.pcap import analyze_capture

            report = analyze_capture(args.input, max_packets=args.max_packets, max_stream_bytes=args.max_stream_bytes, max_flows=args.max_flows, max_assets=args.max_assets, max_services=args.max_services, max_segments=args.max_segments, max_total_stream_mb=args.max_total_stream_mb, include_opcua_certificates=args.include_opcua_certs)
            if args.site_profile:
                from plcsec.site_profile import apply_site_profile, load_site_profile
                report = apply_site_profile(report, load_site_profile(args.site_profile))
            if args.inventory:
                from plcsec.inventory import apply_inventory, load_inventory
                report = apply_inventory(report, load_inventory(args.inventory))
            if args.baseline_action == "create":
                baseline = build_baseline(report, args.site_id)
                path = write_baseline(baseline, args.baseline_out)
                print(f"[+] Passive baseline written: {path}")
                print(f"[+] Site ID: {args.site_id}; assets: {baseline['asset_count']}")
                return 0
            if bool(args.signature) != bool(args.public_key):
                raise ValueError("--signature and --public-key must be provided together")
            if args.require_signature and not args.signature:
                raise ValueError("This operation requires --signature and --public-key")
            if args.signature and args.public_key:
                from plcsec.signing import verify_baseline
                verification = verify_baseline(args.baseline, args.public_key, args.signature)
                print(f"[+] Baseline signature valid: Ed25519 ({verification['public_key_sha256'][:16]}…)")
            baseline_data = load_baseline(args.baseline)
            report = compare_to_baseline(report, baseline_data)
            paths = write_report(report, args.out, args.format)
            _print_report_summary(report.to_dict())
            for path in paths:
                print(f"[+] Report written: {path}")
            return 0
        if args.command == "audit":
            require_authorized_target(args.target, args.allowlist, args.authorized)
            if args.audit_action == "modbus-id":
                from plcsec.plugins.modbus_tcp import audit_device_identification

                report = audit_device_identification(args.target, args.port, args.unit_id, args.timeout)
            elif args.audit_action == "s7-id":
                from plcsec.plugins.s7 import audit_s7_identity

                report = audit_s7_identity(args.target, args.rack, args.slot, args.port)
            else:
                parser.error("Unknown audit action")
                return 2
            paths = write_report(report, args.out, args.format)
            _print_report_summary(report.to_dict())
            for path in paths:
                print(f"[+] Report written: {path}")
            return 0
    except (AuthorizationError, ValueError, FileNotFoundError, RuntimeError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # Network libraries raise vendor-specific exceptions.
        print(f"[!] Assessment failed safely: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    parser.print_help()
    return 0


def _print_modules(output_format: str) -> None:
    if output_format == "json":
        import json
        print(json.dumps([{"name": n, "description": d, "status": s} for n, d, s in MODULES], indent=2))
        return
    print(f"PLCSEC {__version__} modules")
    print("-" * 96)
    for name, description, status in MODULES:
        print(f"{name:<34} [{status}]\n  {description}")


def _print_report_summary(data: dict[str, object]) -> None:
    assets = data.get("assets", [])
    findings = data.get("findings", [])
    events = data.get("events", [])
    print(f"[+] Assessment: {data['assessment_type']}")
    print(f"[+] Assets: {len(assets) if isinstance(assets, list) else 0}")
    print(f"[+] Findings: {len(findings) if isinstance(findings, list) else 0}")
    print(f"[+] Protocol events: {len(events) if isinstance(events, list) else 0}")
    metadata = data.get("metadata", {})
    if isinstance(metadata, dict):
        limit_flags = [
            key for key, value in metadata.items()
            if (key.endswith("_limit_reached") or key.endswith("_truncated")) and value is True
        ]
        if limit_flags:
            print("[!] Analysis limits affected completeness: " + ", ".join(sorted(limit_flags)))


if __name__ == "__main__":
    raise SystemExit(main())
