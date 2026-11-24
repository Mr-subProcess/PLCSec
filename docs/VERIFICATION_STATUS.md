# Verification status — PLCSEC 0.6.0

## Local test run

- Environment: Python 3.13.5.
- Command: `make check`.
- Result: 164 passed, 1 skipped (165 collected).
- Skip: the optional Scapy real-PCAP/PCAPNG reader integration test; Scapy is not installed in this build environment. Fake-reader integration and parser tests ran.
- Coverage command: `PYTHONPATH=src python -m pytest --cov=plcsec --cov-report=term-missing -q`.
- Coverage result: 83% statement coverage (4,034 statements; 703 missed), including the final advisory validation and CLI tests.
- Python compile check: included in `make check` and passed.

## 0.6.0-specific coverage

- DNP3 CRC-16/DNP check vector (`123456789` => `0xEA82`), header CRC, per-block CRC, corruption reporting and PCAP finding integration.
- IEC 60870-5-104 VSQ, COT, originator, first IOA and selected command-select/qualifier metadata.
- STIX 2.1 bundle envelope, object IDs, reference integrity and note-vs-vulnerability semantics. No independent OASIS validator was run in this environment.
- CEF header/extension escaping and report conversion.
- SQLite audit hash-chain append/verify, report digest minimization, tamper detection, signed checkpoint verification and detection of a rewritten/recomputed local chain.
- CLI export and audit-log workflows.
- Offline advisory-feed validation, stable bounded input reads, exact normalized vendor/product/firmware match, no-match behavior, missing identity handling, invalid record rejection and CLI workflows.

## Not run / not claimed

- Scapy real PCAP/PCAPNG reader integration, unless the optional dependency was installed and the test did not skip.
- Python 3.11 and 3.12 matrix on the local workstation.
- Ruff and mypy unless those tools were installed and executed.
- External STIX validator interoperability; built-in structural/reference validation is not a complete OASIS conformance validator.
- Wireshark/tshark differential protocol validation or vendor conformance suites.
- Real PLC lab interoperability or impact testing.
- Independent vendor confirmation of advisory applicability or a maintained live vulnerability-feed database.
- IEC 62443 certification, NIST assessment, safety certification or production readiness.

## Interpretation

Passing tests validates only the tested code paths and synthetic fixtures. Advisory matching is exact string correlation against operator-supplied data; it is not a vulnerability verdict. DNP3 CRC is not authentication. IEC-104 parsing remains partial. STIX Notes preserve observation semantics and are not vulnerability assertions. A signed external audit checkpoint can detect later database rewrites that do not match the checkpoint; the local SHA-256 chain alone is not immutable.
