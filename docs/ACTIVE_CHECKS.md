# Active checks in 0.4.0

Active checks are opt-in and require both `--authorized` and a matching `--allowlist` file. The allowlist must contain an IP address or CIDR that covers the exact target. A hostname is not accepted. The CLI does not provide a subnet scanner.

## Modbus/TCP Read Device Identification

The Modbus adapter sends exactly one application request:

- Function code: `0x2B` — Encapsulated Interface Transport.
- MEI type: `0x0E` — Read Device Identification.
- Read Device ID code: `0x01` — Basic device identification.
- Starting object ID: `0x00` — VendorName.
- Unit ID: operator-specified, 1–247 (broadcast is rejected).

The implementation waits for the MBAP header, validates transaction/protocol/unit identifiers and the length field, then parses the bounded response. It does not retry, enumerate object IDs, read coils/registers, write data, or issue control functions.

A controller, gateway, or vendor implementation may handle this identity function differently. The result may be unsupported or incomplete; failure is not proof of a vulnerability.

## Siemens S7 identity

When `python-snap7` is installed, the adapter:

1. Creates a client with automatic reconnect disabled and retries set to zero.
2. Connects to the one allowlisted IP and operator-supplied rack/slot.
3. Calls `get_cpu_info()` and `get_order_code()` only.
4. Disconnects in a `finally` block.

It does not call DB/marker/input/output/timer/counter reads, block-list, upload/download, write, control, RUN/STOP, or firmware APIs. Rack/slot selection is device-family dependent and must come from approved engineering documentation.

## Residual risk

Even an identity query establishes a session and sends network traffic. A device may have firmware bugs, resource constraints, or a gateway that behaves unexpectedly. Written site approval, lab validation, and operational risk review remain mandatory.
