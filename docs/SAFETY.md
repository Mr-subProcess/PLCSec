# Operational safety and acceptable use

PLCSEC is designed for OT environments where availability, reliability, process integrity and personnel safety can be affected by even ordinary network traffic.

## Default mode

Passive PCAP/PCAPNG analysis is the primary workflow. It reads an existing file and does not transmit packets. Use approved SPAN/TAP captures or site-provided exports; do not install an unapproved capture point on a live control network.

## Active identity commands

Only two active checks are exposed:

- One Modbus Read Device Identification request.
- Siemens S7 CPU identity and module order-code metadata.

Both require `--authorized` and an explicit single-target IP/CIDR allowlist. A single IP literal is accepted per command; no subnet scan is present.

Even read-only requests establish sessions and can consume device resources. Before any active check:

1. Obtain written approval from the asset owner and OT/process-safety authority.
2. Confirm exact model, firmware, port, Unit ID or rack/slot using approved inventory.
3. Check the vendor's guidance for the exact device/firmware.
4. Test the same request against a lab/simulator or spare device.
5. Complete the site's change/risk process and maintenance-window requirements.
6. Ensure operators and monitoring staff know the test is occurring.

## Hard non-goals

PLCSEC intentionally does not implement:

- PLC writes, coil/register writes, tag writes or process changes.
- I/O force/unforce, CPU RUN/STOP, reset or mode changes.
- Program block upload/download, firmware update, bootloader or configuration writes.
- Credential guessing, brute force, exploit delivery, fuzzing against live devices, denial of service, or safety bypass.
- Automated subnet scanning or broad port scanning.

## Capture and report safety

PCAP files are untrusted input. Parser limits cap packets, flows, segments and retained stream bytes. Keep software updated and analyze untrusted large captures in a restricted environment. Reports may expose IP plans, MAC addresses, serial numbers, product names, SNI values and control-system communication patterns. Protect them as sensitive site data and redact before external sharing.

## Standards context

NIST SP 800-82 Rev. 3 is the published final OT security guide referenced by this release. NIST has also listed an initial public draft of Rev. 4; consult NIST for its current status and do not treat a draft as a final requirement. See [REFERENCES.md](REFERENCES.md).
