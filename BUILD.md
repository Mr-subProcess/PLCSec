# Build and verification

## Local developer environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[all,dev]'
```

## Required checks

```bash
python -m compileall -q src tests plcsec_util.py
PYTHONPATH=src python -m pytest --cov=plcsec --cov-report=term-missing
```

Or run the standard local target:

```bash
make check  # sets PYTHONPATH=src for a source-tree checkout
```

## Optional static analysis

```bash
make lint       # Ruff
make typecheck  # mypy
```

Static analysis is available to contributors, but it is not currently a release gate. Do not describe a release as lint-clean or type-checked unless those commands have actually completed successfully.

## Wheel and source distribution

```bash
python -m pip install build
python -m build
```

## Capture integration check

Install Scapy via `.[pcap]` or `.[all]` and run the full test suite. If Scapy is not installed, one real-PCAP-reader integration test is skipped; fake-reader analyzer tests still run. The skip must be reported, not represented as a full PCAP backend pass.

## External validation still required

- Successful GitHub Actions matrix on Python 3.11, 3.12 and 3.13.
- Ruff and mypy review.
- Protocol corpus and differential parser tests.
- Real PCAP/PCAPNG captures from an isolated lab, with sensitive metadata redacted.
- Vendor model and firmware compatibility tests.
- OT safety review before any active operation.
- Independent security review before operational deployment.
