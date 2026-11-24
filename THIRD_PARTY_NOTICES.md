# Third-party notices

PLCSEC does not bundle third-party libraries. Optional runtime and development integrations are installed separately:

- **Scapy** (`scapy`, optional `pcap` extra): packet capture parsing. See https://scapy.net/ and the license distributed by the Scapy project.
- **python-snap7** (`python-snap7`, optional `s7` extra): narrow read-only Siemens S7 identity adapter. See https://python-snap7.readthedocs.io/ and the license distributed by that project.
- **cryptography** (`cryptography`, optional `crypto` extra): Ed25519 baseline signing and optional X.509 certificate metadata parsing. See https://cryptography.io/ and its Apache-2.0 OR BSD-3-Clause license notices.
- **pytest**, **pytest-cov**, **ruff**, **mypy**, and **build** (development extras): test, coverage, lint, type-check and build tooling. Each project retains its own license.

No vendor firmware, vendor SDK, PLC project file, or proprietary device documentation is included. Users are responsible for observing third-party license, vendor terms, applicable standards licenses, and local rules when installing and using optional dependencies.
