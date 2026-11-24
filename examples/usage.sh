#!/usr/bin/env bash
set -euo pipefail

# Passive capture analysis (no packets sent to PLCs).
plcsec pcap analyze \
  --input /path/to/site-capture.pcapng \
  --out ./reports/site-baseline \
  --format both

# Active examples are commented intentionally. Do not uncomment until written
# approval, site risk review, and target allowlisting are complete.
# plcsec audit modbus-id --target 192.0.2.10 --allowlist authorized_targets.txt \
#   --authorized --out ./reports/modbus-id --format both
# plcsec audit s7-id --target 192.0.2.10 --allowlist authorized_targets.txt \
#   --authorized --rack 0 --slot 1 --out ./reports/s7-id --format both
