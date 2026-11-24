# Security Policy

## Scope

PLCSEC is a defensive assessment utility. Security reports should focus on PLCSEC itself, its parsers, firmware triage, Ed25519 baseline signing, report generation, dependencies, and unintended active-protocol behavior.

## Reporting a vulnerability

Do not open a public issue containing credentials, production IP addresses, PCAP files, PLC configurations, firmware images, or other sensitive OT information.

Until a dedicated private disclosure address is configured, contact the maintainers through a private GitHub Security Advisory for this repository. Include the affected version, reproducible steps, expected behavior, actual behavior, and a sanitized proof of concept.

## Operational safety

Never validate a suspected defect against a production PLC. Reproduce it using synthetic packets, a simulator, or an isolated laboratory controller. Do not include payloads that change PLC state, force I/O, stop CPUs, or disrupt a process. Firmware images and PCAP files may contain secrets or sensitive operational metadata; share only minimized, sanitized reproductions. Never submit private signing keys.

## Evidence store assurance

The local audit log uses a SHA-256 hash chain to make unauthorized edits detectable during verification. It is not immutable and does not provide non-repudiation against an administrator who can rewrite the entire SQLite database and recompute the chain. Deployments requiring stronger assurance should sign periodic chain-head checkpoints with an externally protected key and archive them in independently controlled storage.

## Protocol evidence interpretation

DNP3 CRC-16/DNP failures are treated as low-severity integrity observations. CRC is not cryptographic authentication. IEC 60870-5-104 command metadata is a passive observation and does not prove process execution or device state. STIX output preserves findings as Notes unless a separate validated source justifies a stronger object type.
