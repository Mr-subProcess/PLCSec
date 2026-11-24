from __future__ import annotations

from pathlib import Path

import pytest

from plcsec.safeio import UnstableInputError, read_stable_bytes


def test_read_stable_bytes_returns_exact_content(tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(b"PLCSEC\x00fixture")
    assert read_stable_bytes(source, max_bytes=64, label="fixture") == b"PLCSEC\x00fixture"


def test_read_stable_bytes_enforces_limit(tmp_path: Path) -> None:
    source = tmp_path / "large.bin"
    source.write_bytes(b"x" * 17)
    with pytest.raises(ValueError, match="configured limit"):
        read_stable_bytes(source, max_bytes=16, label="fixture")


def test_read_stable_bytes_requires_regular_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_stable_bytes(tmp_path, max_bytes=16, label="fixture")
