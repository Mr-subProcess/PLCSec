from plcsec.reassembly import TCPSegment, reassemble_tcp_segments


def _seg(seq: int, payload: bytes, ts: float) -> TCPSegment:
    return TCPSegment("192.0.2.10", "192.0.2.20", 40000, 502, seq, payload, ts)


def test_reassembles_out_of_order_segments() -> None:
    streams, stats = reassemble_tcp_segments([_seg(100, b"ABC", 1), _seg(106, b"GHI", 3), _seg(103, b"DEF", 2)])
    assert len(streams) == 1
    assert streams[0].data == b"ABCDEFGHI"
    assert stats.sequence_gaps == 0


def test_deduplicates_exact_retransmission() -> None:
    streams, stats = reassemble_tcp_segments([_seg(100, b"ABCDE", 1), _seg(100, b"ABCDE", 2)])
    assert streams[0].data == b"ABCDE"
    assert stats.retransmissions == 1


def test_reports_conflicting_overlap() -> None:
    streams, stats = reassemble_tcp_segments([_seg(100, b"ABCDE", 1), _seg(102, b"XXFG", 2)])
    assert streams[0].data == b"ABCDEG"
    assert stats.overlap_conflicts == 1


def test_keeps_sequence_gaps_as_separate_streams() -> None:
    streams, stats = reassemble_tcp_segments([_seg(100, b"ABC", 1), _seg(110, b"XYZ", 2)])
    assert len(streams) == 2
    assert stats.sequence_gaps == 1
    assert streams[1].sequence_gaps_before == 1


def test_enforces_per_flow_byte_limit() -> None:
    streams, stats = reassemble_tcp_segments([_seg(100, b"A" * 100, 1)], max_bytes_per_flow=32)
    assert len(streams[0].data) == 32
    assert streams[0].truncated
    assert stats.truncated_flows == 1
