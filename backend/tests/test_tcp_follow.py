import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.database import Base
from backend.app.models import Capture, InspectionPacket, PacketBytes, TcpStream
from backend.app.tcp_follow import follow_stream


@pytest.fixture
def stored():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        capture = Capture(filename='test', imported_at='now', packet_count=0, flow_count=0)
        db.add(capture); db.flush()
        stream = TcpStream(capture_id=capture.id, source='a', destination='b', source_port=1, destination_port=2, first_seen=0, last_seen=1)
        db.add(stream); db.flush()
        yield db, stream
    engine.dispose()


def add(stored, seq, body=b'', direction='forward', flags=24, raw=True, declared=None):
    db, stream = stored
    row = InspectionPacket(capture_id=stream.capture_id, stream_id=stream.id, number=len(db.new)+db.query(InspectionPacket).count()+1, timestamp=0, source='a' if direction == 'forward' else 'b', destination='b' if direction == 'forward' else 'a', source_port=1 if direction == 'forward' else 2, destination_port=2 if direction == 'forward' else 1, protocol='TCP', transport='TCP', ip_version=4, length=len(body)+2, captured_length=len(body)+2, linktype=1, summary='', direction=direction, tcp_seq=seq, tcp_ack=0, tcp_flags=flags, payload_offset=2, payload_length=len(body) if declared is None else declared, raw_status='available' if raw else 'quota')
    db.add(row); db.flush()
    if raw:
        db.add(PacketBytes(packet_id=row.id, data=b'HH'+body)); db.flush()
    return row.id


def test_reorders_deduplicates_and_marks_gaps_and_directions(stored):
    add(stored, 100, flags=2)
    world = add(stored, 106, b'world')
    hello = add(stored, 101, b'hello')
    add(stored, 101, b'hello')
    add(stored, 114, b'!')
    add(stored, 500, b'reply', 'backward')
    result = follow_stream(*stored)
    forward, backward = result['directions']
    assert forward['text'] == 'helloworld[gap 3 bytes]!'
    assert forward['hex'] == b'helloworld!'.hex()
    assert forward['gaps'] == [{'offset': 10, 'length': 3}]
    assert forward['retransmissions'] == 1
    assert forward['segments'][:2] == [{'packet_id': hello, 'offset': 0, 'length': 5}, {'packet_id': world, 'offset': 5, 'length': 5}]
    assert backward['text'] == 'reply'
    assert result['packet_count'] == 6


def test_wrap_and_first_captured_overlap_wins(stored):
    add(stored, 0xfffffffd, flags=2)
    add(stored, 0, b'cdef')
    add(stored, 0xfffffffe, b'abXX')
    forward = follow_stream(*stored)['directions'][0]
    assert forward['text'] == 'abcdef'
    assert forward['retransmissions'] == 1
    assert any('conflicting overlap' in w.lower() for w in follow_stream(*stored)['warnings'])


def test_missing_raw_and_sequence_are_explicit(stored):
    add(stored, 1, b'missing', raw=False)
    add(stored, None, b'unknown')
    result = follow_stream(*stored)
    assert result['directions'][0]['truncated']
    assert result['directions'][0]['text'] == ''
    assert result['directions'][1]['name'] == 'backward'
    assert any('raw' in w.lower() for w in result['warnings'])
    assert any('sequence' in w.lower() for w in result['warnings'])


def test_per_packet_output_and_huge_gap_are_bounded(stored):
    add(stored, 1, flags=2)
    for i in range(10):
        add(stored, 2+i*10000, b'x'*10000)
    add(stored, 2+1000000000, b'end')
    result = follow_stream(*stored)
    forward = result['directions'][0]
    assert len(bytes.fromhex(forward['hex'])) == 65536
    assert forward['truncated']
    assert len(forward['text']) < 70000
    assert any('8192' in w for w in result['warnings'])
    assert any('65536' in w for w in result['warnings'])


def test_scan_limit_and_tls_warning(stored):
    add(stored, 1, b'\x16\x03\x03\x00\x03abc')
    for i in range(1000):
        add(stored, i+100, flags=16)
    result = follow_stream(*stored)
    assert result['packet_count'] == 1001
    assert result['directions'][0]['truncated']
    assert any('1000' in w for w in result['warnings'])
    assert any('TLS' in w for w in result['warnings'])


def test_missing_syn_and_billion_byte_hole_use_no_padding(stored):
    add(stored, 106, b'world')
    add(stored, 101, b'hello')
    add(stored, 1000000111, b'!')
    forward, backward = follow_stream(*stored)['directions']
    assert forward['text'] == 'helloworld[gap 1000000000 bytes]!'
    assert forward['hex'] == b'helloworld!'.hex()
    assert forward['gaps'] == [{'offset': 10, 'length': 1000000000}]
    assert backward['text'] == ''
