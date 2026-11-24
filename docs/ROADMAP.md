# Roadmap

## 0.1.0–0.4.0 — Foundations (completed)

- Modular CLI, bounded passive inventory, baseline drift, site profiles and evidence reports.
- Modbus/TCP, S7comm, EtherNet/IP/CIP, OPC UA, TLS/DTLS, IEC-104, DNP3 and BACnet/IP framing/metadata parsers.
- Directional TCP reassembly, owner-maintained inventory, signed passive baselines and initial inert firmware triage.

## 0.5.0 — Evidence and firmware analysis (current alpha)

- Expanded S7comm Setup Communication and common S7ANY reference metadata; no process-value extraction.
- CIP logical path class/instance/attribute metadata.
- OPC UA opt-in certificate export and constrained offline certificate path review.
- Metadata-only ZIP, CPIO newc, ELF, SquashFS, ext, FDT and U-Boot legacy image inspection.
- Ed25519 signed report artifacts and signed human baseline-approval attestations.
- Packaged conservative vendor profile database and provenance-aware enrichment.

## 0.6.0 — Evidence and protocol hardening (implemented; external validation pending)

- DNP3 link-header and data-block CRC validation; partial IEC-104 ASDU command metadata.
- STIX 2.1 and CEF exports plus SQLite hash-chained evidence log and externally signed checkpoints.
- Offline operator-curated advisory feed matching against exact vendor/product/firmware identity strings.

## 0.7.x — Parser assurance and laboratory validation

- Differential test corpus against independent dissectors for the documented protocol subsets.
- More S7comm and CIP parser coverage, with sanitized captures from identified lab hardware.
- DNP3 CRC/transport/application parsing and IEC-104 ASDU coverage.
- OPC UA trust-list governance, CRL/OCSP validation design and broader X.509 profile tests.
- Vendor/model/firmware compatibility matrix with exact official-document references.
- Isolated laboratory integration tests for Siemens, Rockwell, Schneider Electric and Mitsubishi devices.

## 0.7.x — Operations and evidence lifecycle

- Signed report bundles with reproducibility metadata and policy versioning.
- Baseline exception expiry, approver-role mapping and audit trail integration.
- Read-only syslog/JSONL export and SIEM-friendly normalization, disabled by default.
- Bounded optional firmware metadata adapters for additional container families; still no execution or automatic extraction.
- Performance profiling for large captures and long-lived industrial sessions.

## 1.0 — Stability gate

- Parser fuzzing in isolated test harnesses and corpus-based regression suite.
- Multi-version CI, lint, type checks, reproducible wheel/sdist and signed releases.
- Lab validation across documented PLC models and firmware revisions.
- Independent review of active-check safety controls, protocol traces and certificate validation.
- Formal threat-model review and external security review.
- No production-ready claim until reliability, safety and compatibility evidence exists.

## Explicit non-goals

- PLC logic modification, control writes, I/O forcing, RUN/STOP, firmware replacement, credential attacks, exploitation or denial-of-service.
- Automated vulnerability verdicts from banners, ports, entropy or strings alone.
- Compliance, functional-safety or product-security certification.
