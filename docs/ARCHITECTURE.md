# Architecture

## Design principles

- Passive observation first; network transmission only in two narrow, explicit identity commands.
- Fail-closed active scope validation.
- Bounded parsing and explicit truncation/ambiguity reporting.
- Evidence, confidence, provenance and limitations accompany findings.
- Protocol parsers remain separate from capture acquisition, report rendering and CLI policy.
- Raw industrial application payloads and public certificates are excluded from reports by default.
- Offline firmware inspection never extracts, decompresses, mounts or executes input data.

## Components

1. `plcsec.cli`: command parsing, orchestration and safety policy gates.
2. `plcsec.policy`: exact single-IP allowlist validation for active identity checks.
3. `plcsec.pcap`: offline Scapy packet reader, endpoint/service/flow inventory, bounded TCP stream assembly, protocol dispatch and finding generation.
4. `plcsec.reassembly`: directional TCP byte-stream assembly with gaps and conflicting-overlap metadata.
5. `plcsec.parsers`: pure bounded byte parsers for Modbus, S7, EtherNet/IP/CIP, OPC UA, TLS/DTLS, IEC-104, DNP3 and BACnet/IP.
6. `plcsec.opcua_cert`: constrained offline X.509 path review using operator-supplied certificates and trust anchors.
7. `plcsec.site_profile`, `plcsec.inventory`, `plcsec.baseline`: offline network-zone policy, owner-maintained assets, baseline serialization and drift comparison.
8. `plcsec.signing`, `plcsec.artifact_signing`, `plcsec.approvals`: detached Ed25519 signatures and signed approval attestations.
9. `plcsec.firmware`, `plcsec.firmware_containers`: inert byte hashing, bounded header/container metadata and heuristic indicators.
10. `plcsec.manufacturers`, `plcsec.vendor_database`: conservative profile enrichment with evidence confidence and provenance notes.
11. `plcsec.models` and `plcsec.reporting`: versioned report data model and JSON/HTML/CSV output.

## Data flow

`PCAP/PCAPNG -> Scapy offline reader -> bounded packet/flow inventory -> TCP reassembly -> protocol parsers -> observations/findings -> optional baseline/inventory/site context -> JSON/HTML/CSV`

The capture analysis path does not open sockets or transmit packets. Certificate DER retention is opt-in and only available in JSON protocol events.

## Active path

`CLI -> explicit --authorized -> exact IP allowlist match -> single adapter -> one constrained identity operation -> report`

Out-of-scope targets are rejected before the network adapter is imported. No subnet scan, retry loop or protocol write API is exposed.

## Firmware inspection path

`immutable firmware input -> bounded hash/string/entropy scan -> selected metadata-only container readers -> findings and explicit safety flags`

The path does not extract archive entries, decompress members, mount filesystems, execute code, emulate a device or access the network.

## Signed evidence path

`artifact bytes -> SHA-256 + artifact-type domain separation + public-key fingerprint -> Ed25519 detached signature`

A baseline approval JSON document binds a human-entered approver label and reason to an exact baseline SHA-256 and site ID. Signature verification authenticates the signing key, not the person's institutional authority. Trust provisioning is out-of-band.

## Report schema

`plcsec.report.v2` includes tool metadata, scope, assets, flows, findings, events and capture metadata. Report format is versioned because downstream consumers should not assume fields remain unchanged across major releases.

## Extension guidance

A new passive parser must accept bytes and explicit length bounds; return structured metadata rather than payload dumps; distinguish malformed, incomplete and unknown messages; include positive, negative, truncated, boundary and malformed-input tests; and document exact parser scope. An active adapter requires a separate safety review and must remain read-only, single-target, explicitly authorized, allowlist-gated, bounded and lab-tested.


## Input and artifact integrity guards

- `safeio.py` reads bounded regular-file inputs and compares descriptor/path identity and metadata before and after reading. This detects common replacement/truncation/growth races; it is not a defense against a malicious kernel or a filesystem that forges metadata.
- Artifact and baseline signatures use Ed25519 over domain-separated hashes and bind the artifact type and public-key fingerprint. Detached signatures do not establish signer identity; public-key trust must be provisioned out of band.
- Firmware and certificate inputs are bounded and are not executed or transmitted.
