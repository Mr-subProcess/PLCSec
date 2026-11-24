# Site profiles: zones and conduits

PLCSEC can compare observed IP flows with an operator-provided JSON profile. The profile is a review aid for network architecture; it is not a live firewall policy importer or a proof of unauthorized communication.

## Example

See [`examples/site_profile.example.json`](../examples/site_profile.example.json).

A profile contains:

- A stable `site_id`.
- Named zones with non-overlapping IPv4/IPv6 CIDRs.
- Directed approved conduits with source zone, destination zone, transport and destination port.
- An optional purpose string for human context.

Validate the profile:

```bash
plcsec site-profile validate --input examples/site_profile.example.json
```

Apply it to a capture:

```bash
plcsec pcap analyze \
  --input approved-capture.pcapng \
  --site-profile examples/site_profile.example.json \
  --out reports/zone-review \
  --format all
```

## Interpretation

A cross-zone flow without a matching directed conduit rule is flagged for review. A profile can be incomplete; asymmetric routes, proxies, NAT, dynamic ports, non-standard service ports, and capture placement can affect direction or destination-port interpretation. The finding is not proof of an incident or firewall failure.

Profiles often disclose site architecture. Keep operational profiles private and do not place production IP maps or zone names in a public repository.

## JSON Schema

The profile document schema is shipped at `src/plcsec/schemas/plcsec.site-profile.v1.schema.json`. Schema validation checks document structure; PLCSEC additionally performs semantic validation of CIDR overlap, zone references, duplicate conduits and resource limits.
