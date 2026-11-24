# PLCSEC

**Industrial Controller Security Framework — passive-first OT inventory, protocol intelligence and evidence review.**

PLCSEC is a modular Python framework for defensive assessment of operational technology (OT) environments. It analyzes authorized PCAP/PCAPNG captures, reconciles observed endpoints with owner-maintained inventories, reviews zone/conduit profiles, compares passive baselines, inspects firmware container metadata without extraction, reviews OPC UA application certificates offline, and signs evidence artifacts with Ed25519.

> **Operational safety is a design constraint.** Offline capture analysis is the default. Live checks remain narrowly scoped, read-only identity requests to a single explicitly authorized IP address in an allowlist. PLCSEC does not write process data, change controller mode, force I/O, transfer programs, flash firmware, brute-force credentials, scan ranges, fuzz live devices or perform denial-of-service actions.

## Release status

- **Version:** `0.6.0`
- **Maturity:** alpha / research preview; not safety-certified and not a validated production OT product.
- **Python:** 3.11–3.13.
- **Primary workflow:** offline PCAP/PCAPNG analysis.
- **Optional dependencies:** Scapy (PCAP reader), python-snap7 (narrow S7 identity adapter), cryptography (Ed25519 and X.509 certificate review).
- **Report schema:** `plcsec.report.v2`.

## Capabilities

### Passive protocol intelligence

- Bounded directional TCP reassembly with out-of-order handling, duplicate suppression, sequence-gap and conflicting-overlap reporting.
- Asset, MAC, service, flow, packet and byte observations.
- Modbus/TCP, Siemens S7comm over TPKT/COTP, EtherNet/IP/CIP, OPC UA UACP, TLS/DTLS, IEC 60870-5-104, DNP3 data-link and BACnet/IP BVLC metadata parsing.
- DNP3 CRC-16/DNP validation for link headers and each 16-octet user-data block; CRC errors are surfaced as low-severity observations, not authentication failures.
- Expanded IEC 60870-5-104 ASDU header metadata: COT, originator, VSQ object count/sequence flag, first IOA and selected command select/qualifier fields.
- S7 Setup Communication PDU/job limits and common S7ANY variable reference metadata (area, DB, byte/bit address and transport size); **data values are not extracted**.
- CIP explicit-message selected logical path metadata (class, instance and attribute); not a complete CIP object model.
- OPC UA OPN SecurityPolicy observation and optional public sender-certificate retention.
- Explicit parser resource limits; malformed/incomplete/unknown frames are not converted into guessed identity.

See [protocol coverage](docs/PROTOCOL_COVERAGE.md) for exact parser boundaries.

### Asset inventory and vendor profiles

- Owner-provided asset inventory validation and reconciliation.
- OT zones and directed conduits from local JSON site profiles.
- Conservative baseline drift: new/absent IPs, new observed services and MAC changes.
- Packaged manufacturer aliases, model-family hints and protocol-family hints.
- CIP Vendor ID 1 is explicitly mapped to Rockwell Automation; other IDs remain unknown unless reviewed and added.
- Modbus identity strings are self-reported claims and low confidence. Protocol ports alone never identify a manufacturer.

```bash
plcsec inventory validate --input ./examples/asset_inventory.example.json
plcsec site-profile validate --input ./examples/site_profile.example.json
plcsec vendors database
plcsec vendors enrich --input ./reports/plant-a.json --out ./reports/plant-a-vendors.json
```

### Offline vendor advisory correlation (0.6.0)

PLCSEC can validate a locally maintained advisory feed and compare it with the owner-provided asset inventory. Matching is exact after case-folding and whitespace normalization across vendor, product/model and firmware strings. There is no fuzzy matching, wildcard matching or semantic-version range inference. A match is a candidate for manual review, not a confirmed vulnerability or proof of vendor applicability. PLCSEC does not download feeds automatically.

```bash
plcsec advisories validate --input ./examples/advisories.example.json
plcsec advisories match \
  --inventory ./examples/asset_inventory.example.json \
  --database ./examples/advisories.example.json \
  --out ./reports/advisory-candidates.json
```

The bundled advisory example is synthetic and uses the reserved `.invalid` domain; replace it only with an operator-reviewed vendor feed. See [offline advisory correlation](docs/ADVISORIES.md) and the packaged `plcsec.advisories.v1` JSON Schema.

### Firmware metadata triage

```bash
plcsec firmware analyze --input ./vendor-approved-image.bin --out ./reports/firmware.json --max-mb 2048
```

The analyzer hashes inert bytes and provides bounded format, entropy and strings/version hints. In 0.5.0 and later releases it can also inspect selected ZIP central-directory, CPIO newc, ELF, SquashFS, ext superblock, FDT and U-Boot legacy image metadata. It does not extract archive members, decompress data, mount filesystems, execute binaries, emulate firmware or modify the input. ZIP central-directory inspection is skipped for archives above 64 MiB. CRC success is an integrity observation, not authenticity. See [firmware container inspection](docs/FIRMWARE_CONTAINERS.md).

### OPC UA certificate review

Certificate DER retention from PCAP is **opt-in** because certificate metadata can disclose operational details:

```bash
plcsec pcap analyze --input ./capture.pcapng --out ./reports/ua --format json --include-opcua-certs
plcsec opcua cert-export --report ./reports/ua.json --out-dir ./reports/ua-certs
plcsec opcua cert-audit \
  --leaf ./reports/ua-certs/application.der \
  --intermediate ./trust/intermediates.pem \
  --trust-anchor ./trust/site-root-ca.pem \
  --expected-application-uri urn:example:plc:server \
  --expected-dns-name plc-01.example.internal \
  --out ./reports/opcua-certificate-audit.json
```

The offline certificate path review uses only operator-supplied trust anchors. It checks supported certificate signatures, validity periods, selected CA/KeyUsage constraints and optional URI/DNS SAN matches. It does not perform OCSP/CRL revocation checks, full RFC 5280 name/policy constraint processing, RSA-PSS certificate-signature verification or automatic trust-store discovery. A `trusted` result only means the constrained path reached a supplied trust anchor and passed implemented checks. See [OPC UA certificate review](docs/OPCUA_CERTIFICATE_REVIEW.md).

### SIEM and CTI exports

Export a PLCSEC JSON assessment report to STIX 2.1. Asset and flow telemetry is represented as observed-data; PLCSEC findings are represented as Notes, not Vulnerability or Indicator objects, so an observation is not misrepresented as a confirmed vulnerability or threat attribution.

```bash
plcsec export stix --input ./reports/plant-a.json --out ./reports/plant-a.stix.json
plcsec export cef --input ./reports/plant-a.json --out ./reports/plant-a.cef
```

Maintain a local evidence ledger and periodically sign a checkpoint with an Ed25519 key kept outside the audit host:

```bash
plcsec audit-log init --db ./evidence/audit.sqlite
plcsec audit-log record-report --db ./evidence/audit.sqlite --input ./reports/plant-a.json --actor "OT Security Analyst"
plcsec audit-log checkpoint-sign --db ./evidence/audit.sqlite --out ./evidence/audit-checkpoint.json --private-key ./secrets/audit-private.pem --signature ./evidence/audit-checkpoint.sig.json
plcsec audit-log checkpoint-verify --db ./evidence/audit.sqlite --checkpoint ./evidence/audit-checkpoint.json --public-key ./trust/audit-public.pem --signature ./evidence/audit-checkpoint.sig.json
```

A signed checkpoint can be stored in a separately administered location. Verification remains valid as the local chain grows, provided the earlier prefix is unchanged. The STIX exporter validates object IDs and internal references before writing. CEF is suitable for ingestion pipelines that accept ArcSight Common Event Format. Review and sanitize operational identifiers before sharing reports outside the organization.

### Tamper-evident local audit log

PLCSEC can maintain a local SQLite hash-chained log. `record-report` stores the report SHA-256 and aggregate counts rather than copying the report's asset details into the log.

```bash
plcsec audit-log init --db ./evidence/plcsec-audit.sqlite
plcsec audit-log record-report --db ./evidence/plcsec-audit.sqlite --input ./reports/plant-a.json --actor "OT Security Analyst"
plcsec audit-log verify --db ./evidence/plcsec-audit.sqlite
plcsec audit-log export --db ./evidence/plcsec-audit.sqlite --out ./evidence/audit.jsonl
```

The hash chain is tamper-evident, not tamper-proof: an administrator who can rewrite the entire database can recompute an unkeyed chain. A detached Ed25519 checkpoint, stored outside the host, detects rewrites of the checkpointed prefix. Protect backups and signing keys, and restrict database write access.

### Signed baselines, approvals and reports

Ed25519 signatures bind exact file bytes, artifact type and public-key fingerprint. Keep private keys out of source control.

```bash
plcsec baseline keygen --private-key ./secrets/approver-private.pem --public-key ./trust/approver-public.pem
plcsec baseline sign --input ./baselines/line-a.json --private-key ./secrets/approver-private.pem --signature ./baselines/line-a.sig.json
plcsec baseline verify --input ./baselines/line-a.json --public-key ./trust/approver-public.pem --signature ./baselines/line-a.sig.json

plcsec baseline approve \
  --input ./baselines/line-a.json \
  --approved-by "OT Change Board" \
  --reason "Reviewed against approved maintenance-window capture" \
  --private-key ./secrets/approver-private.pem \
  --out ./baselines/line-a.approval.json \
  --signature ./baselines/line-a.approval.sig.json

plcsec baseline verify-approval \
  --input ./baselines/line-a.json \
  --approval ./baselines/line-a.approval.json \
  --signature ./baselines/line-a.approval.sig.json \
  --public-key ./trust/approver-public.pem

plcsec report sign --input ./reports/line-a.json --private-key ./secrets/reporter-private.pem --signature ./reports/line-a.sig.json
plcsec report verify --input ./reports/line-a.json --public-key ./trust/reporter-public.pem --signature ./reports/line-a.sig.json
```

The `approved_by` label is an attestation field; PLCSEC does not verify employment, role or organizational authority. Public-key trust and approval governance must be managed out-of-band. See [signed evidence](docs/SIGNED_EVIDENCE.md).

### Compliance evidence crosswalk

```bash
plcsec compliance crosswalk --input ./reports/line-a.json --out ./reports/line-a-crosswalk.json
```

The output maps selected evidence tags to broad NIST SP 800-82 and IEC 62443 review themes. This is not an audit, certification, Security Level assessment or control-effectiveness score.

### Live identity checks

The only active checks remain single-target, allowlist-gated, read-only identity operations for Modbus Device Identification and Siemens S7 CPU/order-code identity. They can still affect fragile devices; obtain written authorization and test in an isolated lab or approved maintenance window. No write/control API is included.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[all,dev]'
```

For passive PCAP analysis only: `python -m pip install -e '.[pcap]'`.

For Ed25519 and OPC UA X.509 operations: `python -m pip install -e '.[crypto]'`.

Verify:

```bash
plcsec --version
plcsec --help
plcsec modules list
make check
```

Kali Linux instructions are in [RUN_KALI.md](RUN_KALI.md).

## Synthetic offline lab fixture

To exercise the PCAP reader without using real plant traffic, install the optional Scapy dependency and generate a small capture containing synthetic Modbus/TCP, S7comm, OPC UA and EtherNet/IP frames. The example uses documentation-only IP address ranges and transmits no packets:

```bash
python -m pip install -e '.[pcap]'
python examples/generate_synthetic_lab_pcap.py --out ./captures/synthetic-ot-lab.pcap
plcsec pcap analyze --input ./captures/synthetic-ot-lab.pcap --out ./reports/synthetic-lab --format all
```

This fixture is for parser smoke testing only; it is not a vendor conformance capture and contains no genuine PLC identity.

## Data handling and resource limits

- Firmware input: 2 GiB maximum by default; container metadata limits are separately documented.
- ZIP metadata inspection: skipped when archive file exceeds 64 MiB; members are not decompressed or extracted.
- CPIO member payloads are skipped by offset; no member content is extracted.
- OPC UA public certificate DER is omitted from reports unless `--include-opcua-certs` is explicitly selected.
- Signed artifact input: 128 MiB maximum.
- PCAP processing uses bounded configurable resource ceilings. Check truncation flags before interpreting absence of events.
- Treat PCAP/PCAPNG, certificate exports, firmware images, asset inventories, private keys and reports as sensitive operational data. Do not attach real plant data to public issues.

## Development and verification

```bash
python -m pip install -e '.[all,dev]'
make check
make lint
make typecheck
python -m build
```

Synthetic fixtures and fake packet readers are used in unit tests. The optional Scapy PCAP-reader test runs when Scapy is installed. No tests contact physical PLCs. See [verification status](docs/VERIFICATION_STATUS.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Protocol coverage](docs/PROTOCOL_COVERAGE.md)
- [TCP reassembly](docs/REASSEMBLY.md)
- [Firmware container inspection](docs/FIRMWARE_CONTAINERS.md)
- [OPC UA certificate review](docs/OPCUA_CERTIFICATE_REVIEW.md)
- [Signed evidence](docs/SIGNED_EVIDENCE.md)
- [Manufacturer database](docs/VENDOR_DATABASE.md)
- [Baselines](docs/BASELINES.md)
- [Inventory](docs/INVENTORY.md)
- [Site profiles](docs/SITE_PROFILES.md)
- [Compliance crosswalk](docs/COMPLIANCE_MAPPING.md)
- [Safety](docs/SAFETY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Module authoring](docs/MODULE_AUTHORING.md)
- [References](docs/REFERENCES.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Roadmap](docs/ROADMAP.md)

## License

PLCSEC is distributed under the [MIT License](LICENSE). This license applies to PLCSEC project code only. Third-party tools, vendor SDKs, firmware images, captures and standards remain under their respective terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
