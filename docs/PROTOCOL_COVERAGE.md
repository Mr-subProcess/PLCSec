# Protocol coverage — PLCSEC 0.6.0

All parsers are passive, bounded metadata decoders. A protocol label or observed packet does not prove that a device is a PLC, that a service is reachable from all network zones, or that the endpoint is vulnerable.

| Protocol | Coverage | Explicit limitations |
|---|---|---|
| Modbus/TCP | MBAP framing, function-code metadata, multi-ADU streams, observed write-capable requests, Read Device Identification response objects | No process register/coil values are extracted. Identity strings are self-reported. |
| Modbus/UDP | Best-effort MBAP observations | Non-standard deployments may differ; not a conformance decoder. |
| Siemens S7comm | TPKT/COTP framing, Setup Communication job/PDU limits, bounded S7ANY variable reference metadata (area, DB, byte/bit address, transport size), observed Write Variable request hint | Not a full S7 protocol decoder; no data values are extracted. Variable reference parsing is limited to the common S7ANY syntax and bounded item count. |
| EtherNet/IP / CIP | Encapsulation, CPF, ListIdentity, selected CIP services, common logical path class/instance/attribute metadata, write-like service observations | Not a complete CIP object model, connected I/O decoder, EDS parser or CIP Security decryptor. Only explicitly reviewed vendor IDs are mapped. |
| OPC UA over TCP | UACP framing, HEL endpoint metadata, OPN SecurityPolicy URI, optional public sender-certificate retention/export | No SecureChannel decryption, GetEndpoints service decoding, or full MessageSecurityMode inference. Certificate validation is a separate offline command and is a constrained path review, not full RFC 5280 validation; no revocation check is performed. |
| TLS / DTLS | Record framing and visible ClientHello/ServerHello hints | No decryption or full X.509 chain validation. |
| IEC 60870-5-104 | APCI framing, sequence numbers, ASDU type, VSQ count/SQ flag, COT/originator/common address, first IOA and selected command qualifier/select metadata | Does not decode every information-object payload, CP56Time2a, all cause semantics or all companion profiles; not a conformance checker. |
| DNP3 | Data-link framing, CRC-16/DNP validation of the 8-octet header and each user-data block of up to 16 octets, link-control metadata and first transport-header bits | No DNP3 transport-fragment reassembly, Secure Authentication verification, or full application object decoding. CRC detects transmission errors; it is not cryptographic authentication. |
| BACnet/IP | BVLC and limited NPDU/APDU metadata | Not a complete BACnet service/object decoder. |

## Manufacturer identification

- CIP Vendor ID 1 is mapped to Rockwell Automation / Allen-Bradley using public ODVA declaration material.
- Other CIP IDs are reported as unknown until explicitly reviewed and added.
- Modbus Device Identification vendor/product/model objects are self-reported and low-confidence.
- Siemens, Schneider, Mitsubishi and other vendor/model hints are based on owner-provided inventory strings; an S7 or Modbus port alone is not a manufacturer identity.

## OPC UA security policy observations

The OPN asymmetric security header can carry a SecurityPolicy URI and sender certificate. `SecurityPolicy#None` and selected deprecated policies receive review findings. The parser does not claim the full endpoint catalogue or all endpoint MessageSecurityModes are known. Check vendor endpoint configuration and applicable OPC Foundation profile requirements.

## Parser safety

- Parsers apply explicit message-size, frame-count and string limits.
- Malformed and incomplete frames are not treated as valid device identity.
- Unknown fields remain unknown; no speculative version or vendor assignment is emitted.
- Encrypted application data is not decrypted.
- The PCAP reader is offline; it does not send packets.

## OPC UA certificate review (0.5.0)

When `--include-opcua-certs` is explicitly supplied to PCAP analysis, public sender-certificate DER is retained in the JSON report. `plcsec opcua cert-export` can export those DER blobs. `plcsec opcua cert-audit` performs an offline, bounded path review against trust anchors supplied by the operator. The validator checks certificate validity periods, supported certificate signatures, CA basic constraints, selected key-usage conditions, optional application-URI/DNS SAN matches and whether the path reaches a supplied trust anchor. It does not fetch CRLs/OCSP, enforce all RFC 5280 name, path-length or policy constraints, handle RSA-PSS certificate signatures or prove that the trust anchor is organizationally approved.

## Firmware container metadata (0.5.0)

The firmware analyzer can inspect ZIP central-directory metadata, CPIO `newc` headers, ELF headers, SquashFS superblocks, ext filesystem superblocks, Flattened Device Tree headers and U-Boot legacy image headers. ZIP/CPIO members are never extracted; compressed members are never decompressed; filesystems are never mounted; executables are never run. Archive path traversal, symlink, encryption and high compression-ratio metadata can generate review indicators. Header CRCs are integrity checks only and do not establish image authenticity.

## Extended metadata (0.5.0)

- S7comm Setup Communication requests expose negotiated job/PDU limits where present. Common S7ANY read/write variable requests expose bounded address metadata only; data values are not extracted.
- CIP explicit-message requests expose selected logical path class/instance/attribute identifiers. This is not a complete CIP object model.
- A packaged manufacturer profile database provides conservative aliases and protocol hints. Protocol ports alone never identify a vendor; only the explicitly reviewed CIP Vendor ID mapping is treated as a protocol-level identity claim.

## SIEM/CTI exports and evidence log (0.6.0)

- STIX 2.1 export emits `observed-data` for IP assets and network flows. PLCSEC findings are emitted as `note` objects. Findings are not transformed into STIX `vulnerability` or `indicator` objects because passive observations do not establish those claims. Object IDs and internal references are checked before output.
- CEF export serializes assessment findings with escaped header and extension values.
- The local SQLite audit store chains events with SHA-256 over canonical event material. Verification detects modification, deletion, insertion and reordering within the stored chain. This is tamper-evident, not tamper-proof: a privileged database owner can rewrite and recompute the chain. Use independently signed checkpoints and remote immutable retention for stronger assurance.

## DNP3 CRC implementation notes

PLCSEC uses CRC-16/DNP with reflected polynomial `0xA6BC`, initial register `0x0000`, final XOR `0xFFFF`, and little-endian transmitted CRC bytes. The check value for ASCII `123456789` is `0xEA82`. Header CRC covers the first eight link-header octets. User-data CRCs follow each block of up to 16 octets. CRC failure is retained as an observation and does not cause the frame to be silently treated as authenticated or valid. The algorithm parameters and check vector are documented in the cited protocol-profile material; this parser is not a substitute for DNP Users Group conformance testing.

## Offline advisory correlation (0.6.0)

- Advisory database matching uses exact normalized vendor, product/model and firmware strings from an operator-supplied feed and asset inventory.
- No online feed retrieval, fuzzy matching, wildcard matching, semantic-version inference, hardware-revision inference or automatic vulnerability verdict is performed.
- A match is labelled as a candidate and always carries `is_vendor_applicability_confirmed: false`.
- The bundled example feed is synthetic and is not a source of current vulnerability information.
