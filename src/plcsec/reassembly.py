from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable


_MOD32 = 1 << 32
_HALF32 = 1 << 31


@dataclass(frozen=True, slots=True)
class TCPSegment:
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    payload: bytes
    timestamp: float
    syn: bool = False


@dataclass(slots=True)
class ReassembledStream:
    src: str
    dst: str
    sport: int
    dport: int
    data: bytes
    first_timestamp: float
    last_timestamp: float
    segment_count: int
    retransmissions: int = 0
    overlap_conflicts: int = 0
    sequence_gaps_before: int = 0
    truncated: bool = False


@dataclass(slots=True)
class ReassemblyStats:
    directional_flows: int = 0
    streams_emitted: int = 0
    segments_seen: int = 0
    empty_segments_ignored: int = 0
    retransmissions: int = 0
    overlap_conflicts: int = 0
    sequence_gaps: int = 0
    truncated_flows: int = 0


def _signed_delta(value: int, base: int) -> int:
    delta = (value - base) % _MOD32
    return delta - _MOD32 if delta >= _HALF32 else delta


def reassemble_tcp_segments(
    segments: Iterable[TCPSegment],
    *,
    max_bytes_per_flow: int = 4 * 1024 * 1024,
    max_segments_per_flow: int = 100_000,
) -> tuple[list[ReassembledStream], ReassemblyStats]:
    """Bounded, passive TCP payload reassembly for offline captures.

    It merges in-order and out-of-order payload segments, suppresses exact
    retransmissions, and keeps disjoint byte ranges as separate streams. It
    does not infer missing data or attempt to emulate an endpoint TCP stack.
    Ambiguous overlaps are recorded because endpoint overlap policies differ.
    """
    buckets: dict[tuple[str, int, str, int], list[TCPSegment]] = defaultdict(list)
    for seg in segments:
        if not seg.payload:
            continue
        key = (seg.src, seg.sport, seg.dst, seg.dport)
        buckets[key].append(seg)

    stats = ReassemblyStats(directional_flows=len(buckets), segments_seen=sum(len(v) for v in buckets.values()))
    result: list[ReassembledStream] = []

    for (src, sport, dst, dport), flow_segments in buckets.items():
        if len(flow_segments) > max_segments_per_flow:
            flow_segments = sorted(flow_segments, key=lambda item: item.timestamp)[:max_segments_per_flow]
            flow_truncated = True
        else:
            flow_truncated = False

        base_seq = flow_segments[0].seq + (1 if flow_segments[0].syn else 0)
        normalized: list[tuple[int, TCPSegment, bytes]] = []
        total_input = 0
        for seg in flow_segments:
            start_seq = (seg.seq + (1 if seg.syn else 0)) % _MOD32
            offset = _signed_delta(start_seq, base_seq)
            data = seg.payload
            if total_input + len(data) > max_bytes_per_flow:
                allowed = max(0, max_bytes_per_flow - total_input)
                data = data[:allowed]
                flow_truncated = True
            if data:
                normalized.append((offset, seg, data))
                total_input += len(data)
            if total_input >= max_bytes_per_flow:
                flow_truncated = True
                break

        normalized.sort(key=lambda item: (item[0], item[1].timestamp))
        chunks: list[dict[str, object]] = []
        for offset, seg, data in normalized:
            end = offset + len(data)
            if not chunks or offset > int(chunks[-1]["end"]):
                if chunks and offset - int(chunks[-1]["end"]) > 0:
                    stats.sequence_gaps += 1
                chunks.append({
                    "start": offset,
                    "end": end,
                    "data": bytearray(data),
                    "first": seg.timestamp,
                    "last": seg.timestamp,
                    "count": 1,
                    "retrans": 0,
                    "conflicts": 0,
                    "gap_before": 1 if len(chunks) else 0,
                })
                continue

            chunk = chunks[-1]
            current_end = int(chunk["end"])
            current_start = int(chunk["start"])
            current_data = chunk["data"]
            assert isinstance(current_data, bytearray)
            if offset < current_start:
                # Sorting normally makes this unreachable, but keep defensive handling.
                prefix = data[: current_start - offset]
                current_data[:0] = prefix
                chunk["start"] = offset
                current_start = offset
            overlap = max(0, current_end - offset)
            if overlap >= len(data):
                if overlap and bytes(current_data[offset - current_start : offset - current_start + len(data)]) != data:
                    chunk["conflicts"] = int(chunk["conflicts"]) + 1
                    stats.overlap_conflicts += 1
                else:
                    chunk["retrans"] = int(chunk["retrans"]) + 1
                    stats.retransmissions += 1
            else:
                if overlap:
                    existing = bytes(current_data[offset - current_start :])
                    incoming = data[:overlap]
                    if existing[: len(incoming)] != incoming:
                        chunk["conflicts"] = int(chunk["conflicts"]) + 1
                        stats.overlap_conflicts += 1
                current_data.extend(data[overlap:])
                chunk["end"] = offset + len(data)
            chunk["last"] = max(float(chunk["last"]), seg.timestamp)
            chunk["first"] = min(float(chunk["first"]), seg.timestamp)
            chunk["count"] = int(chunk["count"]) + 1

        for chunk in chunks:
            stream = ReassembledStream(
                src=src,
                dst=dst,
                sport=sport,
                dport=dport,
                data=bytes(chunk["data"]),  # type: ignore[arg-type]
                first_timestamp=float(chunk["first"]),
                last_timestamp=float(chunk["last"]),
                segment_count=int(chunk["count"]),
                retransmissions=int(chunk["retrans"]),
                overlap_conflicts=int(chunk["conflicts"]),
                sequence_gaps_before=int(chunk["gap_before"]),
                truncated=flow_truncated,
            )
            result.append(stream)
            stats.streams_emitted += 1
        if flow_truncated:
            stats.truncated_flows += 1

    result.sort(key=lambda item: (item.first_timestamp, item.src, item.sport, item.dst, item.dport))
    return result, stats
