"""Capture-scoped inspection storage, independent of the ML flow lifecycle."""
from collections import OrderedDict
import json

from .models import InspectionCapture, InspectionPacket, PacketBytes, TcpStream
from .traffic import FLOW_TIMEOUT, MAX_FLOWS, packet_key

RAW_CAPTURE_LIMIT = 64 * 1024 * 1024
RAW_QUEUE_LIMIT = 16 * 1024 * 1024


class InspectionWriter:
    def __init__(self, db, capture_id, raw_limit=RAW_CAPTURE_LIMIT):
        self.capture_id, self.raw_limit = capture_id, raw_limit
        self.state = InspectionCapture(capture_id=capture_id, packet_count=0, raw_bytes_retained=0)
        db.add(self.state)
        self.streams = OrderedDict()
        self.latest_id = 0

    def _stream(self, db, frame):
        if frame['transport'] != 'TCP':
            return None, ''
        key = packet_key({**frame, 'protocol': 'TCP'})
        previous = self.streams.pop(key, None)
        initial_syn = bool(frame['tcp_flags'] & 2 and not frame['tcp_flags'] & 16)
        if previous and (frame['timestamp'] - previous['last'] > FLOW_TIMEOUT or (initial_syn and (previous['closed'] or previous['syn_seq'] != frame['tcp_seq']))):
            previous = None
        if previous is None:
            stream = TcpStream(capture_id=self.capture_id, source=frame['source'], destination=frame['destination'],
                               source_port=frame['source_port'], destination_port=frame['destination_port'],
                               first_seen=frame['timestamp'], last_seen=frame['timestamp'])
            db.add(stream); db.flush()
            previous = {'id': stream.id, 'endpoint': (frame['source'], frame['source_port']), 'last': frame['timestamp'],
                        'syn_seq': frame['tcp_seq'] if initial_syn else None, 'closed': False}
        previous['last'] = frame['timestamp']
        previous['closed'] |= bool(frame['tcp_flags'] & 5)
        self.streams[key] = previous
        if len(self.streams) > MAX_FLOWS:
            self.streams.popitem(last=False)
        db.get(TcpStream, previous['id']).last_seen = frame['timestamp']
        return previous['id'], 'forward' if previous['endpoint'] == (frame['source'], frame['source_port']) else 'backward'

    def write(self, db, frame, flow_id=None, direction=''):
        stream_id, stream_direction = self._stream(db, frame)
        raw = frame.get('raw_data', b'')
        status = frame['raw_status']
        if self.state.raw_bytes_retained + len(raw) > self.raw_limit:
            raw, status = b'', 'retention_limit'
        self.state.packet_count += 1
        keys = ('timestamp', 'source', 'destination', 'source_port', 'destination_port', 'protocol', 'transport', 'ip_version',
                'length', 'captured_length', 'linktype', 'summary', 'tcp_seq', 'tcp_ack', 'tcp_flags', 'payload_offset', 'payload_length')
        row = InspectionPacket(capture_id=self.capture_id, number=frame.get('number', self.state.packet_count), flow_id=flow_id,
                               stream_id=stream_id, direction=stream_direction or direction, raw_status=status,
                               warnings_json=json.dumps(frame.get('warnings', [])), **{k: frame[k] for k in keys})
        db.add(row); db.flush()
        if raw:
            db.add(PacketBytes(packet_id=row.id, data=raw))
            self.state.raw_bytes_retained += len(raw)
        self.latest_id = row.id
        return row
