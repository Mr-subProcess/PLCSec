from __future__ import annotations

import json
import struct
import zipfile
import zlib
from pathlib import Path

from plcsec.firmware import analyze_firmware
from plcsec.firmware_containers import inspect_firmware_container


def _cpio_entry(name: str, payload: bytes, mode: int = 0o100644) -> bytes:
    fields = [1, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name.encode()) + 1, 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    name_data = name.encode() + b"\x00"
    data_start = (110 + len(name_data) + 3) & ~3
    prefix = header + name_data + b"\x00" * (data_start - 110 - len(name_data))
    body = prefix + payload
    return body + b"\x00" * ((4 - len(body) % 4) % 4)


def test_zip_container_metadata_flags_path_traversal_without_extracting(tmp_path: Path) -> None:
    image = tmp_path / "firmware.zip"
    with zipfile.ZipFile(image, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../outside.txt", "not extracted")
        archive.writestr("etc/config.ini", "mode=read-only")
    result = inspect_firmware_container(image)
    assert result["container_type"] == "zip"
    assert result["details"]["members_decompressed"] is False
    assert any("Unsafe archive path" in item for item in result["details"]["warnings"])
    assert all("../outside" in item["name"] or item["name"] == "etc/config.ini" for item in result["details"]["reported_entries"])


def test_cpio_metadata_detects_unsafe_path_without_reading_payload(tmp_path: Path) -> None:
    image = tmp_path / "rootfs.cpio"
    image.write_bytes(_cpio_entry("../escape", b"DATA") + _cpio_entry("TRAILER!!!", b""))
    result = inspect_firmware_container(image)
    assert result["container_type"] == "cpio-newc"
    assert result["details"]["member_contents_read"] is False
    assert any("Unsafe CPIO path" in item for item in result["details"]["warnings"])


def test_elf_header_metadata_is_reported(tmp_path: Path) -> None:
    image = tmp_path / "controller.elf"
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[16:18] = struct.pack("<H", 2)
    header[18:20] = struct.pack("<H", 183)
    header[24:32] = struct.pack("<Q", 0x80000000)
    image.write_bytes(header)
    result = inspect_firmware_container(image)
    assert result["container_type"] == "elf"
    assert result["details"]["machine_hint"] == "AArch64"
    assert result["details"]["execution_performed"] is False


def test_squashfs_superblock_reports_version_and_block_size(tmp_path: Path) -> None:
    image = tmp_path / "root.squashfs"
    header = bytearray(96)
    header[:4] = b"hsqs"
    header[4:8] = (23).to_bytes(4, "little")
    header[12:16] = (131072).to_bytes(4, "little")
    header[20:22] = (4).to_bytes(2, "little")
    header[28:30] = (4).to_bytes(2, "little")
    header[30:32] = (0).to_bytes(2, "little")
    header[40:48] = (65536).to_bytes(8, "little")
    image.write_bytes(header)
    details = inspect_firmware_container(image)["details"]
    assert details["compression_id"] == 4
    assert details["version"] == "4.0"
    assert details["block_size"] == 131072


def test_uboot_legacy_header_crc_and_data_crc(tmp_path: Path) -> None:
    image = tmp_path / "uimage.bin"
    payload = b"firmware payload"
    header = bytearray(64)
    header[0:4] = b"\x27\x05\x19\x56"
    header[12:16] = len(payload).to_bytes(4, "big")
    header[24:28] = (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "big")
    header[28:32] = bytes([5, 2, 2, 0])
    header[32:46] = b"PLCSEC TEST FW"
    header[4:8] = (zlib.crc32(header) & 0xFFFFFFFF).to_bytes(4, "big")
    image.write_bytes(header + payload)
    details = inspect_firmware_container(image)["details"]
    assert details["header_crc_valid"] is True
    assert details["data_crc_valid"] is True
    assert details["checks_are_integrity_checks_not_authenticity_checks"] is True


def test_firmware_analyzer_includes_container_metadata(tmp_path: Path) -> None:
    image = tmp_path / "root.zip"
    with zipfile.ZipFile(image, "w") as archive:
        archive.writestr("bin/plc", b"abc")
    report = analyze_firmware(image)
    assert report["container_inspection"]["container_type"] == "zip"
    assert report["analysis_safety"]["archive_members_extracted"] is False
    json.dumps(report)
