# Owner-provided asset inventory

The inventory is an operator-maintained context file used to enrich passive observations. It is intentionally separate from a learned PCAP baseline: a baseline records what was observed, while an inventory records what the site owner expects to exist.

## Schema

The JSON document is described by the packaged JSON Schema at `src/plcsec/schemas/plcsec.asset-inventory.v1.schema.json` and uses `plcsec.asset-inventory.v1` and contains a `site_id` plus a non-empty `assets` array. Each asset has a unique `asset_id`, unique IP address and optional metadata:

- `hostname`, `vendor`, `model`, `firmware`
- `role`, `owner`, `criticality`, `zone`
- `expected_services`: protocol name, port and optional purpose
- `notes`

Criticality values are `low`, `medium`, `high`, `critical` and `safety`. Inventories are limited to 10 MiB to reduce accidental ingestion of unbounded files. Passwords, API tokens, private keys and other secrets must never be stored in this file.

## Validate

```bash
plcsec inventory validate --input examples/asset_inventory.example.json
```

The example uses documentation-only IP ranges. Copy it to a private site file and replace all entries with owner-approved values. Do not publish operational IP maps, owner names or detailed firmware inventories in a public repository.

## Compare against a capture

```bash
plcsec pcap analyze \
  --input approved-capture.pcapng \
  --inventory /secure/site/asset-inventory.json \
  --out reports/asset-inventory-review \
  --format all
```

The reconciliation can report:

- Observed IPs without an inventory entry.
- Inventory assets not observed in the capture window.
- Services observed but absent from the expected-service list.
- Expected services not observed in the capture window.

## Interpretation

These are visibility and change-review signals. A passive capture is not a complete traffic census. An asset may be idle, outside the capture vantage point, hidden behind NAT or a gateway, or active only during a different operating phase. A common port or protocol does not conclusively identify a PLC. Review every discrepancy with the asset and process owners before changing records or network rules.
