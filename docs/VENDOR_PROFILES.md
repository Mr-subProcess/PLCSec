# Manufacturer and model profiles

PLCSEC separates **observed protocol identity**, **self-reported identity**, and **owner-supplied inventory context**. It does not infer a manufacturer from a TCP port alone.

## Current profile sources

| Source | Use | Confidence / limitation |
|---|---|---|
| Owner-provided inventory `vendor` / `model` | Canonicalize supported aliases and identify known product-family hints | Inventory is operator-supplied; confirm it against nameplate/vendor records |
| EtherNet/IP CIP `ListIdentity` | Map CIP Vendor ID 1 to Rockwell Automation / Allen-Bradley | High confidence for the registered vendor identifier, not proof that the device is an authentic Rockwell product |
| Modbus Device Identification objects | Read vendor/product/model strings already present in a capture | Low confidence; device-reported values are self-asserted and can be absent or spoofed |
| S7comm traffic | Label the observed protocol endpoint as S7comm | Does not prove the PLC manufacturer without a device identity record |

The built-in CIP vendor map is deliberately conservative. PLCSEC currently hard-codes only Vendor ID 1 (Rockwell Automation / Allen-Bradley), corroborated by ODVA declarations. Unknown IDs remain unknown rather than being guessed. The user may extend the mapping with a reviewed local profile file in a future release.

## Supported owner-inventory aliases

Siemens, Rockwell Automation, Schneider Electric, Mitsubishi Electric, ABB, Beckhoff, Omron, WAGO, Yokogawa and Emerson have basic alias and model-family matching. Matching is descriptive metadata enrichment, not model validation or vulnerability detection.

## Privacy

Real asset inventories often contain internal IP plans, serial numbers, owner contacts, firmware information and network roles. Keep production inventory files and resulting reports private. Do not upload them to a public issue or repository without authorization and redaction.
