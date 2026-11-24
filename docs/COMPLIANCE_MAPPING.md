# Security framework mapping — guidance only

PLCSEC 0.4 adds an evidence crosswalk command:

```bash
plcsec compliance crosswalk \
  --input ./reports/line-a.json \
  --out ./reports/line-a-compliance-crosswalk.json
```

The crosswalk associates selected finding tags with broad IEC 62443 foundational-requirement themes and NIST SP 800-82 Rev. 3 OT-security topics. It is intended to help an assessor ask the next question; it is not a checklist of all requirements.

| Evidence category | IEC 62443 theme | NIST SP 800-82 review theme |
|---|---|---|
| Asset inventory and baseline drift | FR 1, FR 3, FR 7 themes | OT asset inventory, configuration/change management, monitoring |
| Zones, conduits and observed cross-zone flows | FR 5 theme | Segmentation, boundary protection and OT/IT separation |
| Write-capable traffic | FR 2 and FR 6 themes | Least privilege, change control and accountability |
| OPC UA / TLS security observations | FR 3 and FR 4 themes | Communication and cryptographic protection; certificate lifecycle |
| Reassembly and resource-limit observations | FR 7 theme | Resilience, resource management and monitoring coverage |

## Limitations

- PLCSEC does not certify IEC 62443, assess a complete system, determine a Security Level, or score control effectiveness.
- IEC references are theme-level. Obtain the applicable licensed standard, edition and scope before formal assessment.
- NIST SP 800-82 Rev. 3 is the published final guide referenced by this release. Check the NIST publication page for later drafts or final revisions before formal work.
- A PCAP is a vantage-point- and time-bounded sample. Missing traffic is not proof that a control is absent or an asset is offline.
- Tags are heuristic evidence selectors. Review each mapped finding and its underlying evidence.
