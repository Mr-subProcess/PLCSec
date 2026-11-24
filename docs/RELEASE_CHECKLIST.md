# Release checklist

A version is not a production release merely because its package builds or unit tests pass.

## Source and package integrity

- [ ] Version matches in `VERSION`, `pyproject.toml`, `src/plcsec/__init__.py`, README, citation metadata and changelog.
- [ ] No private PCAP/PCAPNG, plant address plan, credentials, serial numbers, firmware image, private inventory, private key or approved target allowlist is included.
- [ ] Third-party notices, vendor references and license metadata are reviewed.
- [ ] Source archive and wheel build successfully.
- [ ] SHA-256 manifests verify after download.
- [ ] Packaged vendor JSON and JSON Schemas are present in wheel and sdist.

## Software quality

- [ ] CI passes on Python 3.11, 3.12 and 3.13.
- [ ] Optional PCAP integration test runs with Scapy installed.
- [ ] Ruff and mypy results are reviewed and recorded.
- [ ] Parser regression corpus, malformed-input and resource-limit tests pass.
- [ ] Report output is reviewed for sensitive data and CSV formula handling.
- [ ] Firmware metadata readers are tested against malformed and boundary inputs; no extraction or execution path is added.
- [ ] Ed25519 baseline, report signature and approval binding/tamper tests pass.
- [ ] OPC UA certificate path tests cover trusted, untrusted, expired, malformed and missing-anchor cases; limitations remain documented.
- [ ] Dependency advisories are reviewed.

## Protocol and vendor interoperability

- [ ] Protocol parsers are checked against independent dissectors or trusted conformance corpora.
- [ ] Siemens and Modbus active identity adapters are validated against exact lab models and firmware.
- [ ] Other parser claims remain limited to `docs/PROTOCOL_COVERAGE.md`.
- [ ] Modbus identity values are marked self-reported; unknown CIP Vendor IDs remain unmapped.
- [ ] Vendor/model and protocol hints are backed by references or explicitly marked owner-supplied/heuristic.

## OT safety and field readiness

- [ ] Passive mode is verified to make no network connections.
- [ ] Active commands are reviewed from packet traces and require approved single-target scope.
- [ ] Active checks are exercised only in an isolated lab or approved maintenance window.
- [ ] Asset owners and process-safety stakeholders review operational risk.
- [ ] No production deployment or safety certification is claimed without independent assessment.

## Release publication

- [ ] `CHANGELOG.md` and `RELEASE_SUMMARY.md` are current.
- [ ] GitHub Actions is green and logs are reviewed.
- [ ] Release archive hashes are published.
- [ ] Release is tagged `vX.Y.Z` only after applicable blocking checks are satisfied.

## 0.6.0 integration checks

- [ ] Validate generated STIX 2.1 bundles with an independent STIX validator before external distribution.
- [ ] Test CEF escaping against the receiving SIEM connector and encoding requirements.
- [ ] Confirm DNP3 CRC behavior against approved protocol vectors and, where possible, an independent implementation.
- [ ] Confirm IEC-104 ASDU metadata using vendor/companion-standard fixtures; do not interpret a select bit as proof of process execution.
- [ ] Sign an audit-log checkpoint with a key outside the monitored host and archive it separately.
- [ ] Verify that local audit database, checkpoints, public plant inventories and reports are not accidentally committed to Git.


## 0.6.0-specific checks

- [ ] Validate the advisory JSON Schema and confirm feed provenance before importing real vendor advisories.
- [ ] Confirm exact-match results manually against product hardware revision and official vendor advisory scope.
- [ ] Verify candidate matches are never presented as confirmed vulnerabilities or confirmed vendor applicability.
- [ ] Verify audit database and signed checkpoints are backed up separately, with private keys stored outside the monitored host.
- [ ] Validate STIX output with an independent OASIS-compatible validator before external SIEM/CTI distribution.
