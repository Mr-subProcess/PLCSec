# Firmware container metadata inspection

PLCSEC 0.5.0 adds bounded metadata inspection for selected firmware formats:

| Format | Metadata inspected | Content processing |
|---|---|---|
| ZIP | Central-directory names, sizes, CRC fields, compression ratio, encryption flag, symlink metadata and unsafe paths | No member decompression or extraction; ZIP inspection is skipped above 64 MiB archive size |
| CPIO newc | Bounded headers, names, modes, sizes, owner IDs, timestamps, unsafe paths and symlink entries | Member payloads are skipped by file offset, never read as file contents |
| ELF | Class, endianness, object type, machine and entry point | Header only; never loaded or executed |
| SquashFS | Endianness, inode count, block size, compression ID, version and bytes-used | Superblock only; never mounted or decompressed |
| ext filesystem | Inode/block metadata, block size, volume name and feature flags | Superblock only; never mounted |
| Flattened Device Tree | Header size and version fields | Header only; no property tree traversal |
| U-Boot legacy image | Name, declared payload size, OS/architecture/type/compression codes, header/data CRC | CRCs are integrity checks only; no execution or decompression |

All findings are triage indicators. An unsafe path or high compression ratio is not proof of malware. A CRC match does not establish authenticity. The analyzer does not unpack nested archives, so nested filesystem contents remain uninspected.
