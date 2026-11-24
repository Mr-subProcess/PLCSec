# Ed25519-signed passive baselines

PLCSEC can create detached Ed25519 signatures for baseline JSON files. The baseline content is hashed with SHA-256; the signature binds the payload digest and the normalized public-key fingerprint under a PLCSEC-specific context string.

## Generate a signing key pair

```bash
plcsec baseline keygen \
  --private-key ./secrets/plcsec-baseline-private.pem \
  --public-key ./trust/plcsec-baseline-public.pem
```

The generated private-key file is set to owner-read/write (0600) on POSIX systems. It is unencrypted PEM for automation convenience; protect it with an operating-system secret store, encrypted volume, HSM or an approved key-management system. Never commit the private key to source control or distribute it with reports. For high-assurance sites, sign through an HSM-backed workflow rather than this local-file keygen flow.

## Sign and verify

```bash
plcsec baseline sign \
  --input ./baselines/line-a.json \
  --private-key ./secrets/plcsec-baseline-private.pem \
  --signature ./baselines/line-a.sig.json

plcsec baseline verify \
  --input ./baselines/line-a.json \
  --public-key ./trust/plcsec-baseline-public.pem \
  --signature ./baselines/line-a.sig.json
```

A valid signature proves that the baseline bytes match a signature made by the corresponding private key. It does not prove that the baseline was accurate, complete, approved or safe when created. Public-key authenticity must be established out-of-band (for example, via a trusted configuration-management system or fingerprint exchange).

## Require verification before comparison

`pcap baseline compare` accepts `--signature` and `--public-key` together. Add `--require-signature` to make missing signature material a hard error:

```bash
plcsec pcap baseline compare \
  --input ./captures/current.pcapng \
  --baseline ./baselines/line-a.json \
  --signature ./baselines/line-a.sig.json \
  --public-key ./trust/plcsec-baseline-public.pem \
  --require-signature \
  --out ./reports/line-a-drift
```

The private key is never needed for verification.
