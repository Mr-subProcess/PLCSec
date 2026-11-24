# Report interpretation — schema v2

PLCSEC emits JSON, self-contained HTML and CSV output. Report records use the `plcsec.report.v2` schema. Consumers should check `schema_version` before parsing and should tolerate added metadata fields.

## Findings

Each finding contains:

- `finding_id`: stable identifier for automation.
- `title` and `description`: concise statement of an observation.
- `severity`: informational triage level, not a CVSS score.
- `priority_score`: local review-order hint, not a calibrated risk score.
- `evidence`: bounded packet or identity metadata supporting the observation.
- `recommendation`: defensive next step.
- `confidence`: confidence in the observation, not confidence of exploitability.
- `source`: parser or adapter that produced the evidence.
- `tags` and `references`: classification and source material.

## Output formats

`--format json` emits one JSON file; `html` emits a self-contained HTML file; `csv` emits assets, flows and findings CSV files; `both` emits JSON and HTML; `all` emits JSON, HTML and the three CSV files. CSV text fields are prefixed with an apostrophe when they begin with a spreadsheet formula marker (`=`, `+`, `-`, `@`, tab or carriage return). This helps reduce spreadsheet formula injection when opening untrusted values in common spreadsheet applications.

## Interpretation

Passive findings are observations. A Modbus write function in a capture may be normal HMI traffic. It is not automatically malicious. Port 502 does not prove the endpoint is a PLC. Version strings do not by themselves prove that firmware is vulnerable or unsupported. A device missing from a capture may simply be idle or outside the capture vantage point. An observed service absent from an owner inventory requires operational validation.

Reports can reveal network architecture, owner names, product identifiers, serial numbers and firmware context. Treat them as sensitive OT information. Redact addresses, MACs, hostnames, product identifiers and process metadata before publishing samples.
