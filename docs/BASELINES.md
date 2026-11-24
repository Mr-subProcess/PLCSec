# Passive baselines and drift review

A baseline records what PLCSEC observed in one capture window. It is not an authoritative asset database, a CMDB export, an approved design, or a statement that an asset was online for the entire period.

## Create a baseline

```bash
plcsec pcap baseline create \
  --input approved-baseline.pcapng \
  --site-id plant-a \
  --baseline-out baselines/plant-a.json
```

The baseline contains:

- Site ID supplied by the operator.
- Baseline creation timestamp.
- SHA-256 of the capture file.
- IP asset keys.
- Observed MAC addresses.
- Observed protocol/service and port pairs.

## Compare a later capture

```bash
plcsec pcap baseline compare \
  --input current-window.pcapng \
  --baseline baselines/plant-a.json \
  --out reports/plant-a-drift \
  --format all
```

Potential observations include newly seen IPs, newly observed service/port combinations, MAC association changes, and baseline assets not seen in the current capture.

## Interpretation

- A new IP can be a device, a temporary engineering laptop, NAT, a gateway, or a capture-scope change.
- A new service observation does not prove that a service is reachable from every zone or exposed externally.
- A changed MAC can result from redundancy, virtualization, NIC replacement, proxy ARP, NAT, or capture topology.
- An absent asset may simply have been idle or outside the current capture vantage point.

Baselines can themselves be poisoned if built from an untrusted capture. Use a known capture point, documented observation window, approval record and protected baseline storage. Do not silently overwrite an approved baseline; version it and preserve its hash.
