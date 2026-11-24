#!/usr/bin/env python3
"""Convenience launcher for source checkouts; installed users can run `plcsec`."""
from plcsec.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
