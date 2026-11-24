# Publishing PLCSEC 0.6.0 on GitHub

1. Create a new repository named `plcsec` or `plcsec-industrial-security`.
2. Extract the source archive into a clean directory and review `LICENSE`, `SECURITY.md`, `THIRD_PARTY_NOTICES.md`, `CITATION.cff`, `docs/SAFETY.md`, `docs/OPCUA_CERTIFICATE_REVIEW.md` and `docs/FIRMWARE_CONTAINERS.md`.
3. Confirm that no real PCAP/PCAPNG, plant IP plan, credentials, serial number list, firmware image, private inventory, private certificate/key or allowlist is included.
4. In a clean Python 3.11–3.13 environment install `.[all,dev]`; run `make check`, `make lint`, `make typecheck` and `python -m build`.
5. Verify that the optional Scapy real-PCAP test ran rather than skipped. Run an independent STIX 2.1 validator on the example export, review CEF output with the target connector, and check lint/type-check/build output and dependency advisories.
6. Push the repository and allow GitHub Actions to complete. Do not publish a release until CI is green and `docs/RELEASE_CHECKLIST.md`, `docs/SECURITY_INTEGRATIONS.md`, `docs/DNP3_CRC.md` and `docs/ADVISORIES.md` have been reviewed.
7. Create tag `v0.6.0` only after all applicable checks pass. Record the CI run URL and artifact checksums in the GitHub release description.

Example:

```bash
git init
git add .
git status --short
git commit -m "Release PLCSEC 0.6.0"
git branch -M main
git remote add origin https://github.com/OWNER/plcsec.git
git push -u origin main
```

Replace `OWNER` with the actual account or organization. Public repositories must not contain site-specific data. This release remains alpha even if CI succeeds; CI does not replace vendor interoperability, protocol conformance, OT safety or independent security review.
