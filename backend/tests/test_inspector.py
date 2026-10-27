import json
import time

import pytest
from scapy.all import ARP, DNS, DNSQR, Ether, IP, IPv6, TCP, UDP, Raw, wrpcap
from sqlalchemy import select

from backend.app.packet_filters import compile_filter, FilterError


def capture_rows():
    rows = [
        Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=1234, dport=80, seq=100, flags='S'),
        Ether()/IP(src='10.0.0.2', dst='10.0.0.1')/TCP(sport=80, dport=1234, seq=500, ack=101, flags='SA'),
        Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=1234, dport=80, seq=101, ack=501, flags='PA')/Raw(load=b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'),
        Ether()/IPv6(src='2001:db8::1', dst='2001:db8::2')/UDP(sport=1234, dport=53)/DNS(qd=DNSQR(qname='example.test')),
        Ether()/ARP(psrc='10.0.0.1', pdst='10.0.0.2'),
    ]
    for index, raw in enumerate(rows):
        raw.time = 1700000000 + index
    return rows


def import_capture(client, tmp_path, monkeypatch, rows=None):
    from backend.app import advanced
    api, _ = client
    monkeypatch.setattr(advanced, 'UPLOAD_DIR', tmp_path / 'uploads')
    api.put('/api/settings', json={'demo_mode': False, 'refresh_seconds': 30})
    path = tmp_path / 'inspect.pcap'
    wrpcap(str(path), rows or capture_rows())
    response = api.post('/api/captures', files={'file': ('inspect.pcap', path.read_bytes())})
    assert response.status_code == 201, response.text
    return response.json()['id']


def test_inspector_lists_dissects_and_filters_imported_packets(client, tmp_path, monkeypatch):
    capture_id = import_capture(client, tmp_path, monkeypatch)
    api = client[0]
    listed = api.get('/api/inspector/packets', params={'capture_id': capture_id}).json()
    assert listed['total'] == 5
    assert [p['number'] for p in listed['items']] == [1, 2, 3, 4, 5]
    assert listed['items'][-1]['protocol'] == 'ARP' and listed['items'][-1]['flow_id'] is None
    packet = listed['items'][2]
    detail = api.get(f'/api/inspector/packets/{packet["id"]}').json()
    assert bytes.fromhex(detail['hex']).endswith(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
    assert {layer['name'] for layer in detail['layers']} >= {'Ethernet', 'IPv4', 'TCP', 'HTTP'}
    assert detail['flow']['id'] == packet['flow_id']
    selected = api.get('/api/inspector/packets', params={'capture_id': capture_id, 'filter': 'tcp && ip.addr == 10.0.0.1 && tcp.port == 80'}).json()
    assert selected['total'] == 3
    for expression, count in [('tcp.flags.syn == 1', 2), ('dns || arp', 2), ('ipv6.addr == 2001:db8::1', 1), ('frame.time_relative >= 3', 2), ('frame.len > 1000', 0)]:
        response = api.get('/api/inspector/packets', params={'capture_id': capture_id, 'filter': expression})
        assert response.status_code == 200, response.text
        assert response.json()['total'] == count
    ordered = api.get('/api/inspector/packets', params={'capture_id': capture_id, 'sort': 'number', 'order': 'desc', 'page_size': 2}).json()
    assert [p['number'] for p in ordered['items']] == [5, 4]
    assert api.get('/api/inspector/packets', params={'capture_id': capture_id, 'filter': "__import__('os')"}).status_code == 422
    assert api.get('/api/inspector/packets', params={'capture_id': capture_id, 'sort': 'DROP TABLE'}).status_code == 422


@pytest.mark.parametrize('expression', ['tcp.port == 99999', 'ip.addr == nonsense', 'frame.len == -1', '(' * 40 + 'tcp' + ')' * 40, 'frame.len >', 'tcp &&', 'x' * 1025])
def test_invalid_filters_fail_closed(client, expression):
    from backend.app.models import InspectionPacket
    with pytest.raises(FilterError):
        compile_filter(expression, InspectionPacket.__table__.c, relative_time=InspectionPacket.timestamp)


def test_tcp_follow_orders_bytes_and_preserves_direction_and_gaps(client, tmp_path, monkeypatch):
    rows = capture_rows()[:2]
    for seq, body in [(106, b'world'), (101, b'hello'), (101, b'hello'), (114, b'!')]:
        rows.append(Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=1234, dport=80, seq=seq, ack=501, flags='PA')/Raw(load=body))
    rows.append(Ether()/IP(src='10.0.0.2', dst='10.0.0.1')/TCP(sport=80, dport=1234, seq=501, ack=115, flags='PA')/Raw(load=b'reply'))
    for index, raw in enumerate(rows):
        raw.time = 1700000000 + index * .1
    capture_id = import_capture(client, tmp_path, monkeypatch, rows)
    api = client[0]
    packets = api.get('/api/inspector/packets', params={'capture_id': capture_id}).json()['items']
    assert len({p['stream_id'] for p in packets}) == 1
    stream = api.get(f'/api/inspector/streams/{packets[0]["stream_id"]}').json()
    forward, backward = stream['directions']
    assert 'helloworld' in forward['text'] and forward['gaps']
    assert forward['retransmissions'] >= 1 and backward['text'] == 'reply'


def test_legacy_metadata_has_no_fabricated_bytes(client):
    from backend.app.models import Capture, Flow, PacketRecord
    api, factory = client
    api.put('/api/settings', json={'demo_mode': False, 'refresh_seconds': 30})
    with factory() as db:
        capture = Capture(filename='old.pcap', imported_at='2026-10-27T00:00:00+00:00', packet_count=1, flow_count=0, source='pcap')
        db.add(capture); db.flush()
        # Legacy packet metadata predates inspection storage.
        db.add(PacketRecord(capture_id=capture.id, flow_id=999, timestamp='2026-10-27T00:00:00+00:00', source='10.0.0.1', destination='10.0.0.2', source_port=1, destination_port=2, protocol='TCP', size=40, flags='S', direction='forward'))
        db.commit(); capture_id = capture.id
    listed = api.get('/api/inspector/packets', params={'capture_id': capture_id}).json()
    assert listed['legacy'] is True and listed['items'][0]['id'] < 0
    detail = api.get(f'/api/inspector/packets/{listed["items"][0]["id"]}').json()
    assert detail['hex'] == '' and detail['warnings']


def test_inspector_is_local_only_and_sample_isolated(client):
    api, _ = client
    assert api.get('/api/inspector/captures').status_code == 409
    api.put('/api/settings', json={'demo_mode': False, 'refresh_seconds': 30})
    assert api.get('/api/inspector/captures', headers={'Origin': 'https://evil.example'}).status_code == 403


def test_retention_limit_preserves_metadata_and_stream_reuse(client):
    from backend.app.dissection import capture_frame
    from backend.app.inspection_store import InspectionWriter
    from backend.app.models import Capture, InspectionPacket, PacketBytes
    api, factory = client
    api.put('/api/settings', json={'demo_mode': False, 'refresh_seconds': 30})
    with factory() as db:
        capture = Capture(filename='quota', imported_at='2026-10-27T00:00:00+00:00', packet_count=3, flow_count=0, source='live')
        db.add(capture); db.flush()
        writer = InspectionWriter(db, capture.id, raw_limit=64)
        rows = []
        for seq, flags in [(100, 'S'), (101, 'F'), (2000, 'S')]:
            raw = Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=1234, dport=80, seq=seq, flags=flags)
            rows.append(writer.write(db, capture_frame(raw)))
        db.commit()
        assert writer.state.raw_bytes_retained <= 64
        assert rows[0].stream_id == rows[1].stream_id != rows[2].stream_id
        assert rows[1].raw_status == 'retention_limit' and db.get(PacketBytes, rows[1].id) is None
        detail = api.get(f'/api/inspector/packets/{rows[1].id}').json()
        assert detail['hex'] == '' and 'retention_limit' in detail['warnings'][0]


def test_live_inspection_updates_include_arp_without_disrupting_flows(client, monkeypatch):
    import asyncio
    from backend.app import live
    from backend.tests.test_live import FakeSniffer, make_capture
    from backend.app.models import InspectionPacket, PacketBytes, PacketRecord
    events = []
    async def collect(message):
        json.dumps(message)  # No raw bytes may leak into routine WebSocket messages.
        events.append(message)
    monkeypatch.setattr(live, 'broadcast', collect)
    controller = make_capture(client[1], sniffer_factory=FakeSniffer)
    async def exercise():
        await controller.start({'id': 'test', 'name': 'Test'})
        for packet in (Ether()/ARP(psrc='10.0.0.1', pdst='10.0.0.2'), capture_rows()[0]):
            packet.time = time.time()
            controller.enqueue(packet)
        await controller.close()
    asyncio.run(exercise())
    state = controller.snapshot()
    assert state['processed_packets'] == 1 and state['inspection_count'] == 2
    assert state['inspection_queue_bytes'] == 0 and state['unsupported_packets'] == 1
    with client[1]() as db:
        assert len(list(db.scalars(select(InspectionPacket)))) == 2
        assert len(list(db.scalars(select(PacketRecord)))) == 1
        assert len(list(db.scalars(select(PacketBytes)))) == 2
    assert any(e['type'] == 'packet_updates' for e in events)


def test_raw_queue_limit_keeps_flow_processing_and_marks_missing_bytes(client, monkeypatch):
    import asyncio
    from backend.app import live
    from backend.tests.test_live import FakeSniffer, make_capture
    from backend.app.models import InspectionPacket, PacketBytes
    monkeypatch.setattr(live, 'RAW_QUEUE_LIMIT', 0)
    controller = make_capture(client[1], sniffer_factory=FakeSniffer)
    async def exercise():
        await controller.start({'id': 'test', 'name': 'Test'})
        packet = capture_rows()[0]; packet.time = time.time()
        controller.enqueue(packet)
        await controller.close()
    asyncio.run(exercise())
    assert controller.snapshot()['processed_packets'] == 1
    with client[1]() as db:
        row = db.scalar(select(InspectionPacket))
        assert row.protocol == 'TCP' and row.raw_status == 'queue_limit'
        assert db.get(PacketBytes, row.id) is None


def test_arp_only_pcap_is_inspectable_without_inventing_a_flow(client, tmp_path, monkeypatch):
    capture_id = import_capture(client, tmp_path, monkeypatch, [Ether()/ARP(psrc='10.0.0.1', pdst='10.0.0.2')])
    result = client[0].get('/api/inspector/packets', params={'capture_id': capture_id}).json()
    assert result['total'] == 1 and result['items'][0]['flow_id'] is None
    assert client[0].get('/api/flows').json()['total'] == 0


def test_fragmented_tcp_stream_is_explicitly_incomplete(client, tmp_path, monkeypatch):
    from scapy.all import fragment
    rows = [Ether()/piece for piece in fragment(IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=1234, dport=80, seq=10, flags='PA')/Raw(load=b'x' * 100), fragsize=48)]
    for index, row in enumerate(rows): row.time = 1700000000 + index
    capture_id = import_capture(client, tmp_path, monkeypatch, rows)
    api = client[0]
    packet = api.get('/api/inspector/packets', params={'capture_id': capture_id}).json()['items'][0]
    stream = api.get(f'/api/inspector/streams/{packet["stream_id"]}').json()
    assert stream['directions'][0]['truncated'] is True
    assert any('fragment' in warning.lower() for warning in stream['warnings'])


def test_legacy_number_filter_and_exact_stored_timestamp(client):
    from backend.app.models import Capture, PacketRecord
    api, factory = client
    api.put('/api/settings', json={'demo_mode': False, 'refresh_seconds': 30})
    with factory() as db:
        capture = Capture(filename='old', imported_at='2026-10-27T00:00:00+00:00', packet_count=3, flow_count=0, source='live')
        db.add(capture); db.flush()
        for index in range(3):
            db.add(PacketRecord(capture_id=capture.id, flow_id=999, timestamp=f'2026-10-27T00:00:0{index}.123456+00:00', source='10.0.0.1', destination='10.0.0.2', source_port=1, destination_port=80, protocol='TCP', size=40, flags='S', direction='forward'))
        db.commit(); capture_id = capture.id
    response = api.get('/api/inspector/packets', params={'capture_id': capture_id, 'filter': 'frame.number >= 2'})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['total'] == 2 and [r['number'] for r in result['items']] == [2, 3]
    assert result['items'][0]['timestamp'] == '2026-10-27T00:00:01.123456+00:00'


def test_packet_flow_prediction_and_alert_links_stay_consistent(client, tmp_path, monkeypatch):
    from backend.app import advanced
    monkeypatch.setattr(advanced, 'predict', lambda features: {'category': 'Port scan', 'confidence': .91, 'severity': 'High', 'model_version': 'test', 'explanation': []})
    capture_id = import_capture(client, tmp_path, monkeypatch)
    api = client[0]
    packets = api.get('/api/inspector/packets', params={'capture_id': capture_id, 'filter': 'http'}).json()['items']
    detail = api.get(f'/api/inspector/packets/{packets[0]["id"]}').json()
    assert detail['flow']['classification'] == 'malicious'
    assert detail['detection']['category'] == 'Port scan' and len(detail['alerts']) == 1
    alert_id = detail['alerts'][0]['id']
    assert api.patch(f'/api/alerts/{alert_id}', json={'status': 'Resolved'}).status_code == 200
    assert api.get(f'/api/inspector/packets/{packets[0]["id"]}').json()['alerts'][0]['status'] == 'Resolved'
    flow_packets = api.get('/api/inspector/packets', params={'capture_id': capture_id, 'flow_id': detail['flow']['id']}).json()['items']
    assert len(flow_packets) == 3 and {p['flow_id'] for p in flow_packets} == {detail['flow']['id']}
