# Contributing

Thanks for helping improve PLCSEC. Contributions should preserve the project's safety-first and read-only design.

## Before opening a pull request

1. Open an issue describing the protocol, device family, and defensive use case.
2. Do not include real site addresses, credentials, proprietary configuration files, or unredacted captures.
3. Add synthetic tests for normal, malformed, truncated, and boundary-case inputs.
4. Document protocol assumptions and cite vendor or standards documentation.
5. Update `docs/PROTOCOL_COVERAGE.md` and the changelog when coverage changes.

## Required checks

```bash
python -m pip install -e '.[all,dev]'
make check
```

## Safety requirements

- No PLC write, force, stop/start, program download/upload, firmware update, or destructive commands.
- No password guessing, brute force, denial of service, exploit delivery, or unbounded discovery.
- Any new active adapter must be opt-in, single-target, allowlist-gated, rate-limited, and read-only.
- Active protocol changes require a protocol-level safety rationale and tests proving that no write/control function is emitted.
- Passive parsers must handle malformed and truncated input without crashing or excessive memory use.

Contributors must not represent passive indicators as confirmed vulnerabilities or claim standards compliance without a documented assessment method.
