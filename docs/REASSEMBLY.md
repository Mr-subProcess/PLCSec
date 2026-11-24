# Passive TCP reassembly model

PLCSEC includes a bounded directional reassembler for offline capture analysis.

## Behavior

- Groups payload segments by the observed four-tuple (source IP/port, destination IP/port). Opposite directions are separate streams.
- Uses TCP sequence numbers and accounts for the SYN sequence-space byte when the SYN flag is visible.
- Sorts payload segments by sequence offset and merges contiguous or overlapping data.
- Suppresses exact retransmissions.
- Keeps the first-seen bytes when conflicting overlaps occur and records the conflict count; it does not emulate the operating system's endpoint-specific overlap policy.
- Emits separated chunks when sequence gaps exist. It never invents missing bytes.
- Applies per-flow byte and segment ceilings. The capture reader also limits aggregate retained stream payload, total packet count and directional flow count.

## Important limitations

This is a passive forensic aid, not a complete TCP stack. It does not implement TCP handshake state validation, ACK/window processing, retransmission timers, IP fragment reassembly, TCP Fast Open semantics, endpoint-specific overlap policy, or application-aware gap recovery. A capture can begin mid-stream or omit packets. Parser findings from gap-affected streams require manual confirmation.

## Resource configuration

See `plcsec pcap analyze --help` for:

- `--max-packets`
- `--max-stream-bytes`
- `--max-flows`
- `--max-segments`
- `--max-total-stream-mb`

Lower ceilings should be used when reviewing large or untrusted PCAP files. If limits are reached, report metadata marks the relevant truncation condition.

## Handling ambiguous overlap

For different bytes occupying the same TCP sequence range, PLCSEC retains the first-seen sequence bytes and emits an overlap-conflict observation. This is intentionally conservative: depending on the target TCP implementation, a receiver could reassemble the same packets differently. Analysts should compare capture location, duplicate capture paths, NIC offload effects, and endpoint behavior before interpreting the application parser's result.
