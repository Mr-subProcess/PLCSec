# OPC UA application certificate review

PLCSEC 0.5.0 provides a constrained, offline certificate path review. It never contacts a PLC, OCSP responder, CRL endpoint or external trust service.

## Opt-in certificate retention from PCAP

Public sender-certificate DER is omitted from reports by default. Enable it only when report handling is approved:

```bash
plcsec pcap analyze --input ./capture.pcapng --out ./reports/ua --format json --include-opcua-certs
plcsec opcua cert-export --report ./reports/ua.json --out-dir ./reports/ua-certs
```

Exported certificates are public-key certificates, but their subjects, names, endpoints and fingerprints may still disclose operational information. Treat exported certificates and reports as sensitive site data.

## Offline path review

```bash
plcsec opcua cert-audit \
  --leaf ./certs/application.der \
  --intermediate ./certs/intermediate-chain.pem \
  --trust-anchor ./trust/site-root-ca.pem \
  --expected-application-uri urn:example:plc:server \
  --expected-dns-name plc-01.example.internal \
  --out ./reports/opcua-cert-audit.json
```

Multiple `--intermediate` and `--trust-anchor` paths can be supplied. A PEM file may contain multiple certificate blocks. The leaf input must contain exactly one certificate.

## What is checked

- Leaf/intermediate/trust-anchor validity periods at the local system time.
- Certificate signatures for RSA PKCS#1 v1.5, ECDSA, DSA, Ed25519 and Ed448 where supported by the installed `cryptography` package.
- Issuer/subject path continuity to one of the explicitly supplied trust anchors.
- BasicConstraints CA status and KeyUsage `keyCertSign` for supplied intermediates.
- Optional application URI and DNS SAN matching on the leaf.
- Leaf SHA-256, serial, subject, issuer, SAN URI/DNS and expiry metadata.

## Explicit limitations

This is not a full RFC 5280 implementation. It does not perform OCSP/CRL revocation checking, full name-constraints or policy-constraints evaluation, cross-sign path backtracking, RSA-PSS certificate-signature verification, or automatic trust-store discovery. A trusted result means only that the constrained path reached a user-supplied trust anchor and passed the implemented checks. It does not prove that the trust anchor is organizationally approved, the endpoint is correctly configured, or the full OPC UA application identity is valid.
