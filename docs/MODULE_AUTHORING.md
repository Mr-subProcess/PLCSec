# Authoring a protocol module

A module should be small, explicit about its protocol and safety class, independently testable, and bounded against untrusted input. Version 0.4.0 separates passive protocol parsers, inventory/site context, inert firmware analysis, signed-baseline operations and narrowly scoped active identity adapters.

## Passive parser requirements

- Accept bytes or normalized packet fields; do not open sockets.
- Validate all declared lengths before slicing or allocating.
- Bound the number of parsed records and evidence stored in a report.
- Treat malformed, fragmented, or unknown input as unknown rather than guessing.
- Include synthetic tests for valid, truncated, malformed, and boundary-length messages.
- Record source and confidence for every finding.

## Active adapter requirements

- Must require an explicit `--authorized` confirmation and an IP/CIDR allowlist match.
- Must operate on one IP target only.
- Must have bounded timeouts, bounded response size, bounded request count, and no automatic discovery loop.
- Must be read-only at the protocol level.
- Must not send writes, program-control commands, file transfer, firmware operations, force operations, or fuzzing payloads.
- Must include a test proving the exact request function/subfunction and request count.
- Must cite a vendor or protocol specification and document residual operational risk.

## Report requirements

Use the shared `AssessmentReport` and `Finding` models. A finding must distinguish an observation from a confirmed weakness. Avoid declaring CVEs or compliance failures based only on a product string or port number.
