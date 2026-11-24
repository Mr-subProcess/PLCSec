# PLCSEC 0.6.0 Release Summary

PLCSEC 0.6.0 adds passive protocol and evidence improvements for defensive OT assessment.

## Highlights

- DNP3 CRC-16/DNP validation for link headers and per-block data CRCs.
- Expanded IEC 60870-5-104 ASDU header and selected command metadata.
- STIX 2.1 and CEF exports for SIEM/CTI workflows.
- SQLite SHA-256 hash-chained audit evidence with JSONL export and externally signed Ed25519 checkpoints.
- Offline operator-supplied advisory-feed validation and exact normalized vendor/product/firmware matching against owner-maintained asset inventory.
- Strict advisory field/type validation, HTTPS source URL requirement, duplicate-ID rejection, bounded stable reads and a packaged JSON Schema.
- Synthetic advisory fixture and CLI validation/matching workflows.

## Verification

- `make check`: 164 passed, 1 skipped (165 collected).
- The single skip is the optional Scapy real-PCAP/PCAPNG reader integration test; Scapy is not installed in this local build environment.
- Coverage run: 83% statement coverage (4,034 statements; 703 missed).
- Python compile checks passed.
- CLI advisory validation and exact-match smoke tests passed against synthetic example data.
- Wheel installed into a clean target directory; CLI version and packaged JSON Schema/vendor database resources were checked.
- Source distribution includes advisory documentation, example feed and tests.
- No independent OASIS STIX validator, Ruff/mypy, Python 3.11/3.12 local matrix or real PLC lab was run.

## Status

Alpha research release. Not a certified OT security product and not validated for production deployment. Active identity checks remain narrow, read-only, single-target and allowlist-gated. Advisory matches are candidates for owner/vendor review, not confirmed vulnerability applicability.
