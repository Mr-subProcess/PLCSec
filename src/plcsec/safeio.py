from __future__ import annotations

import os
from pathlib import Path


class UnstableInputError(ValueError):
    """Raised when an input changes while PLCSEC is reading it."""


def read_stable_bytes(path: str | Path, *, max_bytes: int, label: str = "Input") -> bytes:
    """Read a bounded regular file and reject detected replacement or mutation.

    This is a consistency guard, not a defense against a hostile kernel or a
    filesystem that can forge metadata. Callers must still treat files as untrusted.
    """
    source = Path(path)
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    if not source.is_file():
        raise FileNotFoundError(source)
    try:
        with source.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if before.st_size > max_bytes:
                raise ValueError(f"{label} exceeds configured limit of {max_bytes} bytes")
            if not os.path.isfile(source):
                raise UnstableInputError(f"{label} is not a regular file")
            data = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
        path_after = source.stat()
    except OSError as exc:
        raise UnstableInputError(f"{label} could not be read consistently") from exc

    identity_fields = ("st_dev", "st_ino")
    change_fields = ("st_size", "st_mtime_ns", "st_ctime_ns")
    if len(data) > max_bytes:
        raise UnstableInputError(f"{label} grew beyond the configured limit while being read")
    if any(getattr(before, field) != getattr(after, field) for field in identity_fields + change_fields):
        raise UnstableInputError(f"{label} changed while being read")
    if any(getattr(after, field) != getattr(path_after, field) for field in identity_fields + change_fields):
        raise UnstableInputError(f"{label} path was replaced while being read")
    if len(data) != after.st_size:
        raise UnstableInputError(f"{label} size changed or read was incomplete")
    return data
