# Manufacturer profile database

PLCSEC ships a conservative JSON manufacturer profile database at `src/plcsec/data/vendor_profiles.json` and exposes it with:

```bash
plcsec vendors database
plcsec vendors database --format json --out ./reports/vendor-profiles.json
```

The profiles contain aliases, broad model-family hints and protocol-family hints. They are not a complete or authoritative product catalog. Vendor identification is evidence-ranked:

1. Owner-supplied inventory is authoritative context but not independent verification.
2. Explicitly reviewed protocol identifiers are used only where the mapping is documented (currently CIP Vendor ID 1 in the built-in mapping).
3. Modbus Device Identification strings are self-reported and low confidence.
4. A TCP port or protocol name alone never identifies a manufacturer.

Model family names are hints. Firmware compatibility, security support status and exact hardware revisions require vendor release notes or owner-provided authoritative documents.
