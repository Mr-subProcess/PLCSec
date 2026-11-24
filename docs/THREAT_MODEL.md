# Threat model

## Protected interests

- Controller and field-device availability.
- Process integrity and operator visibility.
- Safety functions and personnel safety.
- Accuracy and confidentiality of asset inventory, captures and reports.

## Trust boundaries

- **Capture input:** PCAP/PCAPNG is untrusted and may be malformed, truncated or adversarially crafted.
- **Protocol parser:** parsers must not assume lengths, counts, offsets or strings are valid.
- **Active network boundary:** exact single-target allowlist and explicit authorization must be checked before a client is created.
- **Site context:** baselines and zone/conduit profiles may be stale or incomplete.
- **Report boundary:** output may contain sensitive topology and device identifiers.
- **Dependency boundary:** Scapy and python-snap7 are optional third-party packages.

## Threats and mitigations

| Threat | Mitigation / residual risk |
|---|---|
| Malformed or oversized capture input | Bounded parser lengths and explicit packet/flow/stream ceilings; continue to use OS-level sandboxing for untrusted input. |
| TCP overlap or missing segments | Record conflicts and gaps; never invent missing bytes; endpoint-specific reassembly may differ. |
| False PLC identity from a common port | Findings are phrased as observations; port is not treated as identity proof. |
| Accidental active test against wrong device | `--authorized`, a single IP literal and matching allowlist; written site approval remains operator responsibility. |
| Active query destabilizes a fragile PLC | Minimize requests; no retries; only identity requests; still requires lab/vendor/process-safety review. |
| Stale or poisoned baseline | Capture hash, owner-managed versioning and conservative interpretation. |
| Incorrect or stale owner inventory | Strict schema/IP validation; comparison findings remain owner-review observations, not authoritative verdicts. |
| Incomplete zone/conduit policy | Findings require network-owner validation; not a live firewall verdict. |
| Report injection | HTML output escapes data. Reports still must be stored and shared securely. |
| Dependency compromise | Optional dependencies, declared version ranges, CI, dependency review and release checks. |

## Out of scope

Exploitation, credential attacks, PLC logic manipulation, safety bypass, firmware modification, automated vulnerability verdicts, and compliance certification are out of scope.
