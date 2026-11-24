# Signed evidence and baseline approvals

PLCSEC uses detached Ed25519 signatures with domain separation. Signatures bind the exact file bytes, artifact type and signer public-key fingerprint. Any change to the signed file invalidates the signature.

## Signed assessment reports

```bash
plcsec report sign --input ./reports/plant-a.json --private-key ./secrets/reporter-private.pem --signature ./reports/plant-a.sig.json
plcsec report verify --input ./reports/plant-a.json --public-key ./trust/reporter-public.pem --signature ./reports/plant-a.sig.json
```

The tool signs the file as-is; canonicalization is not applied. If a report is regenerated or reformatted, sign the new exact output again.

## Baseline approval attestations

```bash
plcsec baseline approve \
  --input ./baselines/plant-a.json \
  --approved-by "OT Change Board" \
  --reason "Reviewed against approved maintenance-window capture" \
  --private-key ./secrets/approver-private.pem \
  --out ./baselines/plant-a.approval.json \
  --signature ./baselines/plant-a.approval.sig.json

plcsec baseline verify-approval \
  --input ./baselines/plant-a.json \
  --approval ./baselines/plant-a.approval.json \
  --signature ./baselines/plant-a.approval.sig.json \
  --public-key ./trust/approver-public.pem
```

The approval record is bound to the exact baseline SHA-256 and site ID. `approved_by` is a declarative label; PLCSEC does not establish the person's employment, role or organizational authority. Public-key trust and approval governance must be managed out-of-band. Keep private keys outside the repository and use an HSM or approved key manager where appropriate.
