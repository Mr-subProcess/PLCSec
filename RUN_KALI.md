# Kali Linux quick start

PLCSEC supports Python 3.11–3.13. Use a virtual environment; do not install project dependencies into Kali's system Python.

## Install

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e '.[all,dev]'
```

## Verify

```bash
plcsec --version
plcsec modules list
make check
```

## Passive capture analysis

```bash
plcsec pcap analyze --input ./captures/approved-line-a.pcapng --out ./reports/line-a --format all
```

To retain public OPC UA sender certificate DER in the JSON report, opt in explicitly:

```bash
plcsec pcap analyze --input ./captures/approved-line-a.pcapng --out ./reports/line-a --format json --include-opcua-certs
plcsec opcua cert-export --report ./reports/line-a.json --out-dir ./reports/line-a-certs
```

## Offline advisory correlation

```bash
plcsec advisories validate --input ./examples/advisories.example.json
plcsec advisories match \
  --inventory ./examples/asset_inventory.example.json \
  --database ./examples/advisories.example.json \
  --out ./reports/advisory-candidates.json
```

The example advisory and inventory are synthetic. Matching requires exact normalized vendor, product/model and firmware strings. Review every candidate with the vendor; the result is not a confirmed vulnerability applicability decision. See `docs/ADVISORIES.md` before importing site or vendor data.

## Firmware metadata triage

```bash
plcsec firmware analyze --input ./firmware/vendor-approved-image.bin --out ./reports/firmware.json --max-mb 2048
```

Selected firmware container metadata is inspected without extraction, decompression, mounting, emulation or execution.

## OPC UA certificate review

```bash
plcsec opcua cert-audit \
  --leaf ./certs/application.der \
  --intermediate ./trust/intermediates.pem \
  --trust-anchor ./trust/site-root-ca.pem \
  --expected-application-uri urn:example:plc:server \
  --out ./reports/opcua-certificate-audit.json
```

This is a constrained offline path review, not full RFC 5280 validation; no revocation check is performed.

## Signed evidence and baseline approval

```bash
plcsec baseline keygen --private-key ./secrets/approval-private.pem --public-key ./trust/approval-public.pem
plcsec baseline approve \
  --input ./baselines/line-a.json --approved-by "OT Change Board" \
  --reason "Reviewed for lab use" --private-key ./secrets/approval-private.pem \
  --out ./baselines/line-a.approval.json --signature ./baselines/line-a.approval.sig.json
plcsec baseline verify-approval \
  --input ./baselines/line-a.json --approval ./baselines/line-a.approval.json \
  --signature ./baselines/line-a.approval.sig.json --public-key ./trust/approval-public.pem
plcsec report sign --input ./reports/line-a.json --private-key ./secrets/approval-private.pem --signature ./reports/line-a.sig.json
plcsec report verify --input ./reports/line-a.json --public-key ./trust/approval-public.pem --signature ./reports/line-a.sig.json
```

Keep private keys outside Git and use an approved key manager/HSM for high-assurance workflows. The `approved_by` value is declarative; PLCSEC does not verify organizational authority.

## Vendor and compliance workflows

```bash
plcsec vendors database
plcsec vendors enrich --input ./reports/line-a.json --out ./reports/line-a-vendors.json
plcsec compliance crosswalk --input ./reports/line-a.json --out ./reports/line-a-crosswalk.json
```

Vendor hints are evidence-ranked. Protocol ports alone do not identify a manufacturer.

## Optional active identity checks — authorized lab only

Only two narrow single-target checks are included: Modbus Device Identification and Siemens S7 CPU/order-code identity. They require written approval, one target IP, and an allowlist. They can still affect fragile controllers. No PLC write/control APIs are exposed.

```bash
plcsec audit modbus-id --target 192.0.2.10 --allowlist ./authorized_targets.txt --authorized --out ./reports/modbus-identity
plcsec audit s7-id --target 192.0.2.10 --allowlist ./authorized_targets.txt --authorized --rack 0 --slot 1 --out ./reports/s7-identity
```

`192.0.2.10` is documentation-only and must be replaced with the single address of an approved lab controller.

## SIEM exports and local evidence ledger (0.6.0)

```bash
plcsec export stix --input ./reports/plant-a.json --out ./reports/plant-a.stix.json
plcsec export cef --input ./reports/plant-a.json --out ./reports/plant-a.cef

plcsec audit-log init --db ./evidence/audit.sqlite
plcsec audit-log record-report --db ./evidence/audit.sqlite --input ./reports/plant-a.json --actor "OT Security Analyst"
plcsec audit-log verify --db ./evidence/audit.sqlite
plcsec audit-log export --db ./evidence/audit.sqlite --out ./evidence/audit.jsonl
```

The SQLite log is tamper-evident, not tamper-proof. Protect the database and backups, and externally sign/archive head-hash checkpoints for stronger assurance.

## Synthetic report export smoke test

```bash
plcsec export stix --input ./examples/assessment.example.json --out ./reports/synthetic.stix.json
plcsec export cef --input ./examples/assessment.example.json --out ./reports/synthetic.cef
plcsec audit-log init --db ./reports/synthetic-audit.sqlite
plcsec audit-log record-report --db ./reports/synthetic-audit.sqlite --input ./examples/assessment.example.json --actor "local-test"
plcsec audit-log verify --db ./reports/synthetic-audit.sqlite
```

The included report is synthetic documentation data using RFC 5737 IP addresses. Do not mistake it for a real capture.
