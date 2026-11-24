from __future__ import annotations

import json
from pathlib import Path

import pytest

from plcsec.firmware import analyze_firmware, shannon_entropy


def test_entropy_bounds() -> None:
    assert shannon_entropy(b"A" * 100) == 0.0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_analyze_firmware_is_inert_and_finds_header_strings(tmp_path: Path) -> None:
    source = tmp_path / "plc-fw.bin"
    source.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"SIEMENS SIMATIC S7-1500 Firmware Version V2.9.1\x00PASSWORD=supersecret123\x00")
    result = analyze_firmware(source)
    assert result["input"]["size_bytes"] == source.stat().st_size
    assert "ELF executable/object" in result["format_hints"]
    assert "Siemens" in result["metadata_hints"]["vendor_candidates"]
    assert "V2.9.1" in result["metadata_hints"]["version_strings"]
    assert result["analysis_safety"]["executed"] is False
    assert result["analysis_safety"]["decompressed"] is False
    assert result["metadata_hints"]["raw_strings_retained"] is False
    assert "sample_strings" not in result["metadata_hints"]
    assert "supersecret123" not in json.dumps(result)
    assert len(result["hashes"]["sha256"]) == 64


def test_rejects_empty_and_over_limit_files(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        analyze_firmware(empty)
    blob = tmp_path / "large.bin"
    blob.write_bytes(b"12345")
    with pytest.raises(ValueError, match="exceeds"):
        analyze_firmware(blob, max_bytes=4)


def test_output_schema_is_json_serializable(tmp_path: Path) -> None:
    source = tmp_path / "fw.bin"
    source.write_bytes(b"firmware" * 500)
    result = analyze_firmware(source)
    json.dumps(result)


def test_device_tree_magic_is_identified(tmp_path: Path) -> None:
    source = tmp_path / "board.dtb"
    source.write_bytes(b"\xd0\x0d\xfe\xed" + b"\x00" * 128)
    result = analyze_firmware(source)
    assert "Flattened Device Tree" in result["format_hints"]


def test_rejects_firmware_modified_during_analysis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "changing-fw.bin"
    source.write_bytes(b"original firmware bytes" * 32)
    original_stat = Path.stat
    stat_calls = 0

    def mutate_before_final_stat(path: Path, *args: object, **kwargs: object):
        nonlocal stat_calls
        if path == source:
            stat_calls += 1
            # is_file() performs the first stat; analyze_firmware() records the
            # starting state on the second and checks it again after reading.
            if stat_calls == 3:
                source.write_bytes(b"changed firmware bytes" * 64)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr("plcsec.firmware.Path.stat", mutate_before_final_stat)
    with pytest.raises(ValueError, match="changed while being analyzed"):
        analyze_firmware(source)
