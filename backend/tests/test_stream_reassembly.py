from app.core.stream_reassembly import reassemble


def packet(seq, payload, frame):
    return dict(src='a', dst='b', sport=40000, dport=25, seq=seq, payload=payload, flags=16, frame=frame, ts=frame)


def test_reorder_overlap_gap():
    streams = reassemble([packet(105, b'world', 1), packet(100, b'hello', 2), packet(103, b'loworld', 3), packet(115, b'gap', 4)])
    stream = streams[0]
    assert b''.join(p['payload'] for p in stream['directions']['client']) == b'helloworldgap'
    assert any('gap' in w for w in stream['warnings'])
    assert any('overlap' in w for w in stream['warnings'])
