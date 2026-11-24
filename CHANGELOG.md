# Changelog

## 0.6.0 — SIEM exports, tamper-evident evidence and deeper passive decoding

- Added STIX 2.1 export: IP assets and network flows become `observed-data`; assessment findings become `note` objects, not inferred vulnerabilities or indicators.
- Added CEF export with header/extension escaping for findings.
- Added a local SQLite SHA-256 hash-chained assessment audit log, streaming verification and JSONL export. Report recording stores a report digest and aggregate counts rather than operational asset details.
- Added DNP3 CRC-16/DNP validation for link headers and per-block CRCs, including the standard `123456789` check vector; CRC failures are reported as low-severity observations.
- Expanded IEC 60870-5-104 ASDU header decoding for VSQ, COT, originator, common address, first IOA and selected command select/qualifier fields.
- Added regression tests for malformed CRCs, multi-block DNP3 frames, IEC-104 command metadata, STIX references, CEF escaping, audit-chain tampering and CLI export/audit flows.
- Added explicit limitations for STIX finding semantics and local hash-chain assurance.
- Added bounded offline advisory-feed validation and exact normalized vendor/product/firmware correlation against owner-maintained asset inventories; candidate matches are never represented as confirmed vendor applicability.
- Added a packaged advisory JSON Schema, CLI validation/matching commands and regression tests for exact matching, non-matching versions, missing identity, invalid records, duplicate identifiers, strict field types, HTTPS source requirements and bounded reads.

## 0.5.0 — 2026-11-23

- Added bounded offline OPC UA X.509 certificate path review against explicitly supplied trust anchors, plus opt-in certificate export from JSON capture reports.
- Added detached Ed25519 signatures for assessment artifacts and signed baseline approval attestations bound to baseline SHA-256.
- Added metadata-only firmware container inspection for ZIP, CPIO newc, ELF, SquashFS, ext superblocks, FDT and U-Boot legacy headers. No extraction, decompression, mounting or execution is performed.
- Extended passive S7comm parsing for Setup Communication limits and common S7ANY variable reference metadata; values are not extracted.
- Extended CIP parsing for selected logical path class/instance/attribute metadata.
- Added packaged conservative manufacturer profile database and explicit vendor evidence-confidence policy.
- Added regression tests for certificate chains, signatures/approvals, firmware containers, S7 variable references, CIP paths and CLI workflows.
- Clarified protocol coverage and validation limitations.
- Added bounded stable-file readers for baseline, certificate, key and signed-artifact inputs; detected growth, replacement and metadata changes fail closed.
- Added a regression case proving that an expired intermediate certificate prevents a trusted OPC UA path result.
- Made detached artifact-signature sidecar writes atomic and bounded sidecar/key reads.

# Changelog

## 0.4.0 — Firmware triage, signed baselines and enriched OT evidence

- Added bounded, inert offline firmware analysis with SHA-256/SHA-1/MD5, format hints, entropy windows, bounded ASCII/UTF-16LE strings and version/vendor hints. No execution, unpacking, decompression, mounting or network access.
- Added Ed25519 detached signatures for passive baseline files, key generation, signature verification and an optional `--require-signature` gate for baseline comparison.
- Added OPC UA OPN asymmetric security-header parsing for SecurityPolicy URI and optional sender-certificate fingerprint/X.509 metadata.
- Added passive Modbus Device Identification response parsing and low-confidence self-reported vendor/model observations.
- Added conservative manufacturer profile enrichment. CIP Vendor ID 1 maps to Rockwell Automation; other CIP vendor IDs remain unmapped until reviewed. Siemens, Schneider Electric, Mitsubishi Electric and other family hints use owner-supplied inventory metadata.
- Added an informative IEC 62443 / NIST SP 800-82 evidence crosswalk. It explicitly does not claim certification or control effectiveness.
- Added CLI commands for firmware analysis, baseline keygen/sign/verify, manufacturer enrichment and compliance crosswalk.
- Added regression tests for signing/tampering, firmware hashing/format hints, OPC UA OPN security headers, Modbus identity extraction and CLI flows.
- Added a file-stability guard to reject firmware images that change or grow while being analyzed.

## 0.3.0 — Inventory reconciliation and bounded-output hardening

- Added owner-provided asset inventory schema, validation, enrichment and drift review.
- Added zone/conduit profiles, baseline comparison, report exports and bounded TCP reassembly.
- Added passive parsers for Modbus/TCP, S7comm, EtherNet/IP/CIP, OPC UA UACP, TLS/DTLS, IEC-104, DNP3 and BACnet/IP.
- Added explicit PCAP/resource limits and report truncation metadata.

## 0.2.0 — Passive protocol intelligence and site context

- Added directional TCP reassembly, protocol stream parsing, baseline creation/comparison and OT zone/conduit review.

## 0.1.0 — Initial research preview

- Added modular CLI, passive inventory, narrow read-only Modbus/S7 identity adapters, reports and initial tests.
