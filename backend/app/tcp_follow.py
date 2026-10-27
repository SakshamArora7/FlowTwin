"""Bounded TCP payload reconstruction with capture-order overlap precedence."""
from collections import Counter
import json

from sqlalchemy import case, func, select

from .models import InspectionPacket, PacketBytes

SCAN_LIMIT = 1000
PACKET_LIMIT = 8192
OUTPUT_LIMIT = 65536


def follow_stream(db, stream):
    packet = InspectionPacket
    count = db.scalar(select(func.count()).select_from(packet).where(packet.stream_id == stream.id))
    # Fetch only the bounded payload slices, never full frame blobs or ORM relationships.
    size = case((packet.payload_length > PACKET_LIMIT, PACKET_LIMIT),
                (packet.payload_length < 0, 0), else_=packet.payload_length)
    payload = func.substr(PacketBytes.data, packet.payload_offset + 1, size)
    rows = db.execute(select(packet.id, packet.direction, packet.tcp_seq, packet.tcp_flags,
                             packet.payload_offset, packet.payload_length, packet.raw_status, packet.warnings_json,
                             packet.source, packet.source_port, payload.label('payload'))
                      .outerjoin(PacketBytes, PacketBytes.packet_id == packet.id)
                      .where(packet.stream_id == stream.id)
                      .order_by(packet.number, packet.id).limit(SCAN_LIMIT)).all()
    warnings = []
    if count > SCAN_LIMIT:
        warnings.append(f'Packet scan limited to {SCAN_LIMIT} of {count} packets.')
    directions = []
    for name in ('forward', 'backward'):
        forward = name == 'forward'
        selected = [row for row in rows if (row.direction if row.direction in ('forward', 'backward')
                    else 'forward' if (row.source, row.source_port) == (stream.source, stream.source_port)
                    else 'backward') == name]
        result = dict(name=name, source=stream.source if forward else stream.destination,
                      destination=stream.destination if forward else stream.source,
                      text='', hex='', gaps=[], retransmissions=0, segments=[],
                      truncated=count > SCAN_LIMIT)
        directions.append(result)
        issues = Counter()
        syn = next((row for row in selected if row.tcp_seq is not None and row.tcp_flags & 2), None)
        first_payload = next((row for row in selected if row.tcp_seq is not None and row.payload_length > 0), None)
        base = (syn.tcp_seq + 1) & 0xffffffff if syn else first_payload.tcp_seq if first_payload else 0
        accepted = []
        encrypted = False
        for row in selected:
            for warning in json.loads(row.warnings_json):
                if any(word in warning.lower() for word in ('fragment', 'truncated', 'malformed')):
                    issues[warning] += 1
            if row.payload_length <= 0:
                if row.payload_length < 0:
                    issues['invalid payload metadata'] += 1
                continue
            if row.tcp_seq is None:
                issues['missing TCP sequence metadata'] += 1
                continue
            if row.payload_offset < 0:
                issues['invalid payload metadata'] += 1
                continue
            if row.payload is None:
                issues['missing raw payload (retention quota or unavailable bytes)'] += 1
                continue
            if row.payload_length > PACKET_LIMIT:
                issues[f'payload limited to {PACKET_LIMIT} bytes per packet'] += 1
            body = bytes(row.payload)
            if len(body) < min(row.payload_length, PACKET_LIMIT) or row.raw_status != 'available':
                issues['truncated retained raw payload'] += 1
            if not body:
                continue
            if len(body) >= 5 and body[0] in (20, 21, 22, 23, 24) and body[1] == 3 and body[2] <= 4:
                encrypted = True
            sequence = (row.tcp_seq + bool(row.tcp_flags & 2)) & 0xffffffff
            start = ((sequence-base+0x80000000) & 0xffffffff)-0x80000000
            stop = start + len(body)
            cursor, additions, overlap, conflict = start, [], False, False
            # Accepted intervals do not overlap; the first captured copy owns each byte.
            for old_start, old_body, old_id in accepted:
                old_stop = old_start + len(old_body)
                if old_stop <= start:
                    continue
                if old_start >= stop:
                    break
                left, right = max(start, old_start), min(stop, old_stop)
                overlap = True
                if body[left-start:right-start] != old_body[left-old_start:right-old_start]:
                    conflict = True
                if cursor < old_start:
                    additions.append((cursor, body[cursor-start:old_start-start], row.id))
                cursor = max(cursor, old_stop)
            if cursor < stop:
                additions.append((cursor, body[cursor-start:], row.id))
            if overlap:
                result['retransmissions'] += 1
            if conflict:
                issues['conflicting overlap; first-captured bytes kept'] += 1
            accepted.extend(additions)
            accepted.sort(key=lambda item: item[0])

        if encrypted:
            warnings.append(f'{name}: TLS records are encrypted; bytes are shown without decryption.')
        # Sequence holes are annotations, not allocations or fabricated zero bytes.
        origin = min(0, accepted[0][0]) if accepted else 0
        cursor, emitted, output, text = origin, 0, [], []
        for start, body, packet_id in accepted:
            if emitted == OUTPUT_LIMIT:
                issues[f'output limited to {OUTPUT_LIMIT} payload bytes'] += 1
                break
            if start > cursor:
                gap = start-cursor
                result['gaps'].append(dict(offset=cursor-origin, length=gap))
                text.append(f'[gap {gap} bytes]')
            keep = body[:OUTPUT_LIMIT-emitted]
            output.append(keep)
            # Latin-1 preserves one character per captured byte, including binary data.
            text.append(keep.decode('latin1'))
            result['segments'].append(dict(packet_id=packet_id, offset=start-origin, length=len(keep)))
            emitted += len(keep)
            cursor = start + len(keep)
            if len(keep) < len(body):
                issues[f'output limited to {OUTPUT_LIMIT} payload bytes'] += 1
                break
        result['text'] = ''.join(text)
        result['hex'] = b''.join(output).hex()
        for issue, total in issues.items():
            warnings.append(f'{name}: {total} packet(s): {issue}.')
            if not issue.startswith('conflicting overlap'):
                result['truncated'] = True
    return dict(id=stream.id, capture_id=stream.capture_id, packet_count=count,
                directions=directions, warnings=warnings)
