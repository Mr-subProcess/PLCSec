# Security Integrations

## STIX 2.1

`plcsec export stix` creates a STIX 2.1 bundle. IP assets and observed network flows are represented as `observed-data`. PLCSEC findings are represented as STIX `note` objects, not `vulnerability` or `indicator` objects. This avoids converting a passive observation into a stronger claim that the available evidence does not establish.

## CEF

`plcsec export cef` writes one CEF event per PLCSEC finding. Header pipe characters and extension delimiters are escaped. Operators should treat output as sensitive and review forwarding, retention and data residency policies before SIEM ingestion.

## Local evidence ledger

`plcsec audit-log` records report digests and aggregate counts in a SQLite event chain. Every event hash covers the sequence, timestamp, actor, type, canonical payload and previous hash. The verifier detects edits and ordering changes within the existing database. The scheme is not a trusted timestamp service, immutable WORM storage or non-repudiation mechanism. A privileged user can rewrite all rows and recompute the chain. Periodically sign the chain head using a key outside the host and archive the checkpoint in a separately administered system.
