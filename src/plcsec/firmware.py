from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

MAX_FIRMWARE_BYTES = 2 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
MAX_STRINGS = 20_000
MAX_STRING_LENGTH = 512

MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "ELF executable/object"),
    (b"\x27\x05\x19\x56", "U-Boot legacy image"),
    (b"hsqs", "SquashFS filesystem"),
    (b"sqsh", "SquashFS filesystem (alternate byte order)"),
    (b"CrAU", "Android OTA payload"),
    (b"PK\x03\x04", "ZIP archive/container"),
    (b"\x1f\x8b", "GZIP compressed data"),
    (b"\xfd7zXZ\x00", "XZ compressed data"),
    (b"\x5d\x00\x00", "LZMA stream (possible)"),
    (b"\x04\x22\x4d\x18", "LZ4 frame"),
    (b"\x28\xb5\x2f\xfd", "Zstandard frame"),
    (b"\xd0\x0d\xfe\xed", "Flattened Device Tree"),
    (b"\x45\x3d\xcd\x28", "CRAMFS filesystem"),
    (b"\x85\x19", "JFFS2 filesystem (possible)"),
    (b"UBI#", "UBI volume container"),
    (b"\x3a\xff\x26\xed", "Android sparse image"),
    (b"\xe2\xe1\xf5\xe0", "EROFS filesystem"),
    (b"070701", "CPIO newc archive"),
    (b"070702", "CPIO crc archive"),
)

VENDOR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Siemens", re.compile(r"\b(SIMATIC|SIEMENS|S7[- ]?(?:1200|1500|300|400|ET\s*200))\b", re.I)),
    ("Rockwell Automation", re.compile(r"\b(ROCKWELL|ALLEN[- ]BRADLEY|CONTROLLOGIX|COMPACTLOGIX|MICROLOGIX|MICRO800)\b", re.I)),
    ("Schneider Electric", re.compile(r"\b(SCHNEIDER|MODICON|UNITY PRO|CONTROL EXPERT|M580|M340)\b", re.I)),
    ("Mitsubishi Electric", re.compile(r"\b(MITSUBISHI|MELSEC|FX[35]?U?|IQ[- ]?R|IQ[- ]?F)\b", re.I)),
    ("ABB", re.compile(r"\b(ABB|AC500|800XA)\b", re.I)),
    ("Beckhoff", re.compile(r"\b(BECKHOFF|TWINCAT|CX[0-9]{3,4})\b", re.I)),
    ("B&R", re.compile(r"\b(B&R|BERNECKER|AUTOMATION STUDIO)\b", re.I)),
    ("Omron", re.compile(r"\b(OMRON|NJ[0-9]{3}|NX[0-9]{3})\b", re.I)),
    ("WAGO", re.compile(r"\b(WAGO|PFC[0-9]{3})\b", re.I)),
    ("Yokogawa", re.compile(r"\b(YOKOGAWA|FA-M3|CENTUM)\b", re.I)),
)

VERSION_PATTERN = re.compile(
    r"(?i)\b(?:firmware|firmware\s+version|fw|version|ver)\s*[:=_ -]?\s*"
    r"(v?\d{1,4}(?:\.\d{1,4}){1,4}(?:[-+._][A-Za-z0-9.-]+)?)\b"
)


def _iter_ascii_strings(data: bytes, min_length: int = 6) -> Iterator[str]:
    for match in re.finditer(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}", data):
        yield match.group(0).decode("ascii", errors="replace")[:MAX_STRING_LENGTH]


def _iter_utf16le_strings(data: bytes, min_length: int = 6) -> Iterator[str]:
    # Bounded, even-aligned UTF-16LE printable runs; avoid whole-file decoding.
    printable = bytearray()
    for offset in range(0, len(data) - 1, 2):
        codepoint = int.from_bytes(data[offset : offset + 2], "little")
        if codepoint in (9, 10, 13) or 0x20 <= codepoint <= 0x7E or 0xA0 <= codepoint <= 0xFF:
            printable.extend(data[offset : offset + 2])
        else:
            if len(printable) >= min_length * 2:
                try:
                    yield printable.decode("utf-16le", errors="replace")[:MAX_STRING_LENGTH]
                except UnicodeDecodeError:
                    pass
            printable.clear()
    if len(printable) >= min_length * 2:
        yield printable.decode("utf-16le", errors="replace")[:MAX_STRING_LENGTH]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _magic_at_start(data: bytes) -> list[str]:
    found = [label for magic, label in MAGIC_SIGNATURES if data.startswith(magic)]
    if len(data) >= 2 and data[:2] == b"MZ":
        found.append("DOS/Windows PE container (MZ header; PE offset not validated)")
    return found or ["Unknown / vendor-specific container"]


def analyze_firmware(path: str | Path, *, max_bytes: int = MAX_FIRMWARE_BYTES) -> dict[str, Any]:
    """Analyze a firmware image as inert bytes. Never executes or unpacks it."""
    image = Path(path)
    if not image.is_file():
        raise FileNotFoundError(image)
    if max_bytes < 1 or max_bytes > MAX_FIRMWARE_BYTES:
        raise ValueError(f"max_bytes must be between 1 and {MAX_FIRMWARE_BYTES}")
    stat_before = image.stat()
    size = stat_before.st_size
    if size <= 0:
        raise ValueError("Firmware input is empty")
    if size > max_bytes or max_bytes > MAX_FIRMWARE_BYTES:
        raise ValueError(f"Firmware size exceeds configured limit ({max_bytes} bytes)")

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1(usedforsecurity=False)
    md5 = hashlib.md5(usedforsecurity=False)
    first = b""
    total_entropy_weighted = 0.0
    entropy_bytes = 0
    entropy_windows: list[dict[str, float | int]] = []
    vendor_hits: set[str] = set()
    versions: set[str] = set()
    strings_seen = 0
    strings_truncated = False
    chunk_index = 0
    bytes_read = 0

    with image.open("rb") as handle:
        opened_before = os.fstat(handle.fileno())
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            if not first:
                first = chunk[:4096]
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise ValueError("Firmware input grew beyond the configured size limit during analysis")
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            entropy = shannon_entropy(chunk)
            total_entropy_weighted += entropy * len(chunk)
            entropy_bytes += len(chunk)
            if chunk_index < 256:
                entropy_windows.append({"offset": chunk_index * CHUNK_SIZE, "length": len(chunk), "entropy": round(entropy, 4)})
            if not strings_truncated:
                for text in _iter_ascii_strings(chunk):
                    if strings_seen >= MAX_STRINGS:
                        strings_truncated = True
                        break
                    strings_seen += 1
                    for vendor, pattern in VENDOR_PATTERNS:
                        if pattern.search(text):
                            vendor_hits.add(vendor)
                    for match in VERSION_PATTERN.finditer(text):
                        versions.add(match.group(1))
            # UTF-16LE signatures are typically localized; inspect only first 16 MiB to bound CPU.
            if not strings_truncated and chunk_index < 16:
                for text in _iter_utf16le_strings(chunk):
                    if strings_seen >= MAX_STRINGS:
                        strings_truncated = True
                        break
                    strings_seen += 1
                    for vendor, pattern in VENDOR_PATTERNS:
                        if pattern.search(text):
                            vendor_hits.add(vendor)
                    for match in VERSION_PATTERN.finditer(text):
                        versions.add(match.group(1))
            chunk_index += 1

        opened_after = os.fstat(handle.fileno())
    stat_after = image.stat()
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if bytes_read != size or any(getattr(opened_before, field) != getattr(opened_after, field) for field in stable_fields) or any(getattr(opened_after, field) != getattr(stat_after, field) for field in stable_fields):
        raise ValueError("Firmware input changed while being analyzed; retry using a stable, immutable copy")

    entropy_avg = total_entropy_weighted / max(entropy_bytes, 1)
    format_hints = _magic_at_start(first)
    from plcsec.firmware_containers import inspect_firmware_container
    container_inspection = inspect_firmware_container(image)
    stat_after_container = image.stat()
    if any(getattr(stat_after, field) != getattr(stat_after_container, field) for field in stable_fields):
        raise ValueError("Firmware input changed during container metadata inspection")
    suspicious_entropy = entropy_avg >= 7.2
    findings: list[dict[str, Any]] = []
    if suspicious_entropy:
        findings.append({
            "id": "FW-HIGH-ENTROPY",
            "severity": "info",
            "title": "High average firmware entropy",
            "description": "The image has high average byte entropy. Compression, encryption, packed data, or a mixed binary format may explain it; this is not evidence of malware.",
            "recommendation": "Compare against a vendor-provided reference image and inspect container metadata with an approved offline toolchain.",
        })
    container_warnings = container_inspection.get("details", {}).get("warnings", [])
    if isinstance(container_warnings, list):
        for warning in container_warnings[:100]:
            warning_text = str(warning)
            if "Unsafe archive path" in warning_text or "Unsafe CPIO path" in warning_text:
                findings.append({
                    "id": "FW-CONTAINER-UNSAFE-PATH",
                    "severity": "medium",
                    "title": "Unsafe path metadata in firmware container",
                    "description": warning_text,
                    "recommendation": "Do not extract the image on a privileged host. Preserve the image and inspect it in an isolated, disposable analysis environment.",
                })
            elif "Symbolic-link entry" in warning_text:
                findings.append({
                    "id": "FW-CONTAINER-SYMLINK",
                    "severity": "low",
                    "title": "Symbolic-link metadata in firmware container",
                    "description": warning_text,
                    "recommendation": "Review link targets before any extraction; PLCSEC does not extract archive members.",
                })
            elif "Extreme compression ratio" in warning_text or "exceeds review threshold" in warning_text:
                findings.append({
                    "id": "FW-CONTAINER-RESOURCE-REVIEW",
                    "severity": "info",
                    "title": "Firmware container resource-review indicator",
                    "description": warning_text,
                    "recommendation": "Use strict resource limits and a disposable analysis environment if deeper inspection is required.",
                })
    if not vendor_hits:
        findings.append({
            "id": "FW-VENDOR-UNIDENTIFIED",
            "severity": "info",
            "title": "Vendor not identified from bounded strings",
            "description": "No supported vendor marker was found in extracted strings. Proprietary or stripped images commonly have no readable vendor strings.",
            "recommendation": "Obtain model, order code, and firmware version from the asset owner or vendor release manifest.",
        })
    return {
        "schema": "plcsec.firmware-analysis.v1",
        "input": {"name": image.name, "size_bytes": size},
        "hashes": {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest(), "md5": md5.hexdigest()},
        "format_hints": format_hints,
        "container_inspection": container_inspection,
        "entropy": {"average_shannon": round(entropy_avg, 4), "windows": entropy_windows, "interpretation": "Heuristic only; high entropy does not prove encryption or malicious content."},
        "metadata_hints": {
            "vendor_candidates": sorted(vendor_hits),
            "version_strings": sorted(versions),
            "strings_examined": strings_seen,
            "raw_strings_retained": False,
            "strings_limit": MAX_STRINGS,
            "strings_processing_truncated": strings_truncated,
        },
        "findings": findings,
        "analysis_safety": {
            "executed": False,
            "decompressed": False,
            "archive_members_extracted": False,
            "filesystem_mounted": False,
            "network_access": False,
            "note": "Firmware was treated as inert input bytes. This analyzer does not execute, unpack, emulate, or modify the image.",
        },
    }
