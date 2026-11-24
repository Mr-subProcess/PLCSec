# Offline firmware analysis

`plcsec firmware analyze` treats the input image as inert bytes. It does not execute, emulate, unpack, mount, decompress, flash, or transmit the input.

## Example

```bash
plcsec firmware analyze \
  --input ./vendor-approved-firmware.bin \
  --out ./reports/firmware-analysis.json \
  --max-mb 2048
```

## Current checks

- SHA-256, SHA-1 and MD5 hashes. SHA-256 is the integrity identifier; SHA-1 and MD5 are emitted only for compatibility with vendor manifests and legacy inventories.
- A bounded set of file/container magic hints (ELF, PE/MZ, U-Boot legacy image, SquashFS, CRAMFS, JFFS2, UBI, EROFS, FDT, CPIO, ZIP, GZIP, XZ, LZ4 and Zstandard).
- Average Shannon entropy and up to 256 1 MiB window observations.
- Bounded ASCII and UTF-16LE string scanning, vendor-family hints and common version-string hints. Raw strings are not retained in the report to reduce accidental disclosure of embedded credentials, tokens or private configuration.
- A JSON report with explicit analysis-safety flags.

## Interpretation

Magic bytes and printable strings are heuristics. They do not prove the file format, exact product, vulnerability status, authenticity or integrity. High entropy can indicate compression, encryption, packing or ordinary binary data. Vendor markers can be copied or forged. Firmware provenance must be checked against an authenticated vendor release manifest or signed update package.

The analyzer intentionally does not recursively unpack archives or run embedded tools. For deeper analysis, use a dedicated isolated firmware lab and a vendor-supported unpacking workflow. Do not test unknown images on a production controller.

## Container metadata inspection in 0.5.0

The analyzer now inspects selected metadata without extracting archive members or mounting filesystems. Supported header/metadata families include ZIP, CPIO newc, ELF, SquashFS, ext superblocks, FDT and U-Boot legacy images. ZIP members are inspected through central-directory metadata only; CPIO member payloads are skipped by offset. Do not treat CRC success as authenticity: image provenance still requires a trusted vendor signature and release process.
