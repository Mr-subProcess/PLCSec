# Offline advisory correlation

PLCSEC 0.6.0 can validate a locally supplied advisory database and correlate it with an owner-maintained asset inventory. The matcher is deliberately conservative: it requires an exact, whitespace-normalized, case-insensitive match on vendor, product/model, and firmware string.

It does **not** infer semantic-version ranges, wildcard matches, affected hardware revisions, exploitability, exposure, or vendor applicability. A match is a candidate for human review, not a vulnerability verdict. PLCSEC does not fetch advisory feeds automatically; the operator must maintain provenance and review the source before importing data.

## Validate a feed

```bash
plcsec advisories validate --input ./examples/advisories.example.json
```

The included example is synthetic and uses the reserved `.invalid` domain. It is not a real vendor advisory.

## Match an inventory

```bash
plcsec advisories match \
  --inventory ./examples/asset_inventory.example.json \
  --database ./examples/advisories.example.json \
  --out ./reports/advisory-candidates.json
```

The output includes the inventory asset ID, observed identity strings, advisory identifier, source URL, exact-match policy and a mandatory `is_vendor_applicability_confirmed: false` marker.

## Feed requirements

- Schema: `plcsec.advisories.v1`.
- `source_name` identifies the operator-curated feed or source set.
- Every record requires a unique `advisory_id`, title, vendor, product/model, exact affected firmware strings, severity and HTTPS source URL.
- Optional CVE identifiers must match `CVE-YYYY-NNNN...` syntax.
- Published dates, when supplied, use `YYYY-MM-DD`.
- File size is limited to 16 MiB and the number of entries to 20,000.
- Files are read with the stable-input guard; detected replacement or mutation fails closed.

## Operational guidance

Keep original vendor advisories and their retrieval dates in the organization's evidence repository. Confirm hardware revision, firmware provenance, configuration prerequisites and affected product scope with the vendor. Do not automatically create remediation tickets or change control-system state based solely on a candidate string match.
