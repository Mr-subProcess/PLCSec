from __future__ import annotations

import os
import stat
import struct
import zlib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

MAX_CONTAINER_ENTRIES = 20_000
MAX_ZIP_DIRECTORY_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_REPORTED_ENTRIES = 256
MAX_TOTAL_UNCOMPRESSED = 512 * 1024 * 1024
MAX_SINGLE_ENTRY = 256 * 1024 * 1024


def _safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    drive_like = bool(path.parts and path.parts[0].endswith(":"))
    return not path.is_absolute() and not drive_like and ".." not in path.parts and not normalized.startswith("/")


def inspect_firmware_container(path: str | Path, *, max_entries: int = MAX_CONTAINER_ENTRIES) -> dict[str, Any]:
    """Inspect selected firmware container metadata without extracting or executing data.

    ZIP central-directory metadata is read but members are never decompressed. CPIO,
    SquashFS, ext superblock, ELF, FDT and U-Boot headers are parsed in place.
    """
    image = Path(path)
    size = image.stat().st_size
    with image.open("rb") as handle:
        head = handle.read(4096)
    result: dict[str, Any] = {
        "inspector_version": "1",
        "inspection_mode": "metadata-only-no-extraction-no-mount-no-execution",
        "container_type": "unknown",
        "details": {},
        "warnings": [],
    }

    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        result["container_type"] = "zip"
        result["details"] = _inspect_zip(image, max_entries=max_entries)
    elif head[:6] in (b"070701", b"070702"):
        result["container_type"] = "cpio-newc"
        result["details"] = _inspect_cpio(image, max_entries=max_entries)
    elif head.startswith(b"\x7fELF"):
        result["container_type"] = "elf"
        result["details"] = _inspect_elf(head)
    elif head.startswith(b"hsqs") or head.startswith(b"sqsh"):
        result["container_type"] = "squashfs"
        result["details"] = _inspect_squashfs(head)
    elif len(head) >= 1082 and head[1024 + 56 : 1024 + 58] == b"\x53\xef":
        result["container_type"] = "ext-filesystem-superblock"
        result["details"] = _inspect_ext_superblock(head[1024:])
    elif head.startswith(b"\x27\x05\x19\x56"):
        result["container_type"] = "u-boot-legacy-image"
        result["details"] = _inspect_uboot_legacy(image, size)
    elif head.startswith(b"\xd0\x0d\xfe\xed"):
        result["container_type"] = "flattened-device-tree"
        result["details"] = _inspect_fdt(head)
    elif head.startswith(b"UBI#"):
        result["container_type"] = "ubi-erase-counter-header"
        result["details"] = {"magic": "UBI#", "note": "Only the leading magic was recognized; volume-table and erase-counter validation are not implemented."}
    else:
        result["details"] = {"note": "No supported container header recognized at offset zero."}

    if result["details"].get("truncated"):
        result["warnings"].append("Container metadata parsing reached a configured or input boundary.")
    return result


def _inspect_zip(path: Path, *, max_entries: int) -> dict[str, Any]:
    if path.stat().st_size > MAX_ZIP_DIRECTORY_ARCHIVE_BYTES:
        return {"skipped": True, "reason": f"ZIP input exceeds metadata-inspection limit {MAX_ZIP_DIRECTORY_ARCHIVE_BYTES} bytes", "entries": [], "members_decompressed": False, "truncated": True}
    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    total_uncompressed = 0
    count = 0
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            count = len(infos)
            if count > max_entries:
                warnings.append(f"Entry count {count} exceeds limit {max_entries}; metadata listing truncated.")
            for info in infos[:max_entries]:
                total_uncompressed += info.file_size
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                symlink = stat.S_ISLNK(unix_mode)
                ratio = (info.file_size / max(info.compress_size, 1)) if info.file_size else 1.0
                safe_name = _safe_member_name(info.filename)
                if not safe_name:
                    warnings.append(f"Unsafe archive path detected: {info.filename[:160]}")
                if symlink:
                    warnings.append(f"Symbolic-link entry present: {info.filename[:160]}")
                if info.flag_bits & 0x1:
                    warnings.append(f"Encrypted archive member present: {info.filename[:160]}")
                if info.file_size > MAX_SINGLE_ENTRY:
                    warnings.append(f"Large member exceeds review threshold: {info.filename[:160]}")
                if ratio > 1000:
                    warnings.append(f"Extreme compression ratio observed: {info.filename[:160]}")
                if len(entries) < MAX_REPORTED_ENTRIES:
                    entries.append({
                        "name": info.filename[:512],
                        "size_bytes": info.file_size,
                        "compressed_bytes": info.compress_size,
                        "compression_ratio": round(ratio, 2),
                        "crc32": f"{info.CRC:08x}",
                        "encrypted": bool(info.flag_bits & 0x1),
                        "symbolic_link": symlink,
                        "safe_relative_path": safe_name,
                    })
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
                warnings.append("Declared uncompressed size exceeds review threshold; members were not decompressed.")
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        return {"parse_error": type(exc).__name__, "entries": [], "truncated": False}
    return {
        "entry_count": count,
        "reported_entries": entries,
        "reported_entries_truncated": count > len(entries),
        "declared_total_uncompressed_bytes": total_uncompressed,
        "warnings": warnings,
        "members_decompressed": False,
        "truncated": count > max_entries,
    }


def _inspect_cpio(path: Path, *, max_entries: int) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    count = 0
    total_size = 0
    offset = 0
    truncated = False
    with path.open("rb") as handle:
        while count < max_entries:
            handle.seek(offset)
            header = handle.read(110)
            if not header:
                break
            if len(header) < 110 or header[:6] not in (b"070701", b"070702"):
                warnings.append(f"Invalid or truncated newc header at offset {offset}.")
                truncated = True
                break
            try:
                fields = [int(header[i : i + 8], 16) for i in range(6, 110, 8)]
            except ValueError:
                warnings.append(f"Malformed hexadecimal CPIO field at offset {offset}.")
                truncated = True
                break
            ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor, rdevmajor, rdevminor, namesize, check = fields
            if namesize < 1 or namesize > 4096:
                warnings.append(f"Invalid CPIO name length at offset {offset}.")
                truncated = True
                break
            name_start = offset + 110
            handle.seek(name_start)
            raw_name = handle.read(namesize)
            if len(raw_name) != namesize or raw_name[-1:] != b"\x00":
                warnings.append(f"Truncated CPIO name at offset {offset}.")
                truncated = True
                break
            name = raw_name[:-1].decode("utf-8", errors="replace")
            data_start = (name_start + namesize + 3) & ~3
            data_end = data_start + filesize
            if data_end > path.stat().st_size:
                warnings.append(f"CPIO member extends beyond input: {name[:120]}")
                truncated = True
                break
            if name == "TRAILER!!!":
                break
            safe_name = _safe_member_name(name)
            if not safe_name:
                warnings.append(f"Unsafe CPIO path detected: {name[:160]}")
            kind_bits = stat.S_IFMT(mode)
            if kind_bits == stat.S_IFLNK:
                warnings.append(f"Symbolic-link entry present: {name[:160]}")
            total_size += filesize
            if len(entries) < MAX_REPORTED_ENTRIES:
                entries.append({
                    "name": name[:512], "mode": oct(mode), "size_bytes": filesize,
                    "uid": uid, "gid": gid, "mtime": mtime,
                    "file_type": "symlink" if kind_bits == stat.S_IFLNK else "directory" if kind_bits == stat.S_IFDIR else "regular-or-other",
                    "safe_relative_path": safe_name,
                })
            count += 1
            offset = (data_end + 3) & ~3
            if total_size > MAX_TOTAL_UNCOMPRESSED:
                warnings.append("Declared CPIO payload total exceeds review threshold; contents were not read.")
                break
    if count >= max_entries:
        truncated = True
        warnings.append(f"CPIO entry count reached configured limit {max_entries}.")
    return {
        "entry_count": count, "reported_entries": entries,
        "reported_entries_truncated": count > len(entries),
        "declared_total_file_bytes": total_size, "warnings": warnings,
        "member_contents_read": False, "truncated": truncated,
    }


def _inspect_elf(head: bytes) -> dict[str, Any]:
    if len(head) < 20:
        return {"parse_error": "truncated-elf-header"}
    elf_class, data_encoding = head[4], head[5]
    endian = "little" if data_encoding == 1 else "big" if data_encoding == 2 else None
    if elf_class not in (1, 2) or endian is None:
        return {"class": elf_class, "data_encoding": data_encoding, "parse_error": "unsupported-elf-class-or-endian"}
    e_type = int.from_bytes(head[16:18], endian)
    machine = int.from_bytes(head[18:20], endian)
    entry_offset = 24
    entry_size = 4 if elf_class == 1 else 8
    entry = int.from_bytes(head[entry_offset : entry_offset + entry_size], endian) if len(head) >= entry_offset + entry_size else None
    machines = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V", 20: "PowerPC"}
    types = {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}
    return {
        "class_bits": 32 if elf_class == 1 else 64,
        "endianness": endian,
        "object_type": types.get(e_type, f"unknown-{e_type}"),
        "machine_id": machine,
        "machine_hint": machines.get(machine, "unknown"),
        "entry_point": entry,
        "execution_performed": False,
    }


def _inspect_squashfs(head: bytes) -> dict[str, Any]:
    if len(head) < 96:
        return {"parse_error": "truncated-squashfs-superblock"}
    endian = "little" if head[:4] == b"hsqs" else "big"
    try:
        inode_count = int.from_bytes(head[4:8], endian)
        block_size = int.from_bytes(head[12:16], endian)
        compression = int.from_bytes(head[20:22], endian)
        major = int.from_bytes(head[28:30], endian)
        minor = int.from_bytes(head[30:32], endian)
        bytes_used = int.from_bytes(head[40:48], endian)
    except Exception:
        return {"parse_error": "invalid-squashfs-superblock"}
    return {
        "endianness": endian, "inode_count": inode_count, "block_size": block_size,
        "compression_id": compression, "version": f"{major}.{minor}",
        "bytes_used": bytes_used, "filesystem_mounted": False,
    }


def _inspect_ext_superblock(sb: bytes) -> dict[str, Any]:
    if len(sb) < 256:
        return {"parse_error": "truncated-ext-superblock"}
    inodes = int.from_bytes(sb[0:4], "little")
    blocks_low = int.from_bytes(sb[4:8], "little")
    log_block_size = int.from_bytes(sb[24:28], "little")
    block_size = 1024 << log_block_size if log_block_size <= 6 else None
    volume_name = sb[120:136].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    incompat = int.from_bytes(sb[96:100], "little")
    compat = int.from_bytes(sb[92:96], "little")
    return {
        "inode_count": inodes, "blocks_count_low": blocks_low,
        "block_size_bytes": block_size, "volume_name": volume_name,
        "feature_compat": f"0x{compat:08x}", "feature_incompat": f"0x{incompat:08x}",
        "filesystem_mounted": False,
    }


def _inspect_fdt(head: bytes) -> dict[str, Any]:
    if len(head) < 40:
        return {"parse_error": "truncated-fdt-header"}
    values = [int.from_bytes(head[i : i + 4], "big") for i in range(4, 40, 4)]
    return {
        "total_size": values[0], "version": values[4],
        "last_compatible_version": values[5],
        "strings_size": values[7], "structure_size": values[8],
        "header_only": True,
    }


def _inspect_uboot_legacy(path: Path, file_size: int) -> dict[str, Any]:
    with path.open("rb") as handle:
        header = handle.read(64)
    if len(header) < 64:
        return {"parse_error": "truncated-u-boot-header"}
    stored_header_crc = int.from_bytes(header[4:8], "big")
    header_copy = bytearray(header)
    header_copy[4:8] = b"\x00" * 4
    calculated_header_crc = zlib.crc32(header_copy) & 0xFFFFFFFF
    data_size = int.from_bytes(header[12:16], "big")
    stored_data_crc = int.from_bytes(header[24:28], "big")
    data_crc = 0
    bytes_read = 0
    if data_size <= max(file_size - 64, 0):
        with path.open("rb") as handle:
            handle.seek(64)
            remaining = data_size
            while remaining:
                block = handle.read(min(1024 * 1024, remaining))
                if not block:
                    break
                data_crc = zlib.crc32(block, data_crc)
                bytes_read += len(block)
                remaining -= len(block)
    os_code, arch_code, image_type, compression = header[28:32]
    name = header[32:64].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return {
        "image_name": name, "payload_size": data_size,
        "payload_fits_file": data_size <= max(file_size - 64, 0),
        "os_code": os_code, "architecture_code": arch_code,
        "image_type_code": image_type, "compression_code": compression,
        "header_crc32_stored": f"{stored_header_crc:08x}",
        "header_crc32_calculated": f"{calculated_header_crc:08x}",
        "header_crc_valid": stored_header_crc == calculated_header_crc,
        "data_crc32_stored": f"{stored_data_crc:08x}",
        "data_crc32_calculated": f"{(data_crc & 0xFFFFFFFF):08x}" if bytes_read == data_size else None,
        "data_crc_valid": (data_crc & 0xFFFFFFFF) == stored_data_crc if bytes_read == data_size else None,
        "checks_are_integrity_checks_not_authenticity_checks": True,
    }
