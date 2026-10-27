"""Bounded, original-byte packet inspection. No capture or persistence side effects."""
import re
import socket
import struct

from scapy.all import conf

MAX_BYTES = 65535
HTTP_START = re.compile(rb'^(?:[A-Z]{3,16} [^\r\n ]{1,4096} HTTP/1\.[01]|HTTP/1\.[01] [0-9]{3}(?: [^\r\n]*)?)\r\n')


def _inspect(data, linktype):
    data = bytes(data[:MAX_BYTES])
    n = len(data)
    layers, warnings = [], []
    meta = dict(source='', destination='', source_port=0, destination_port=0,
                protocol='UNKNOWN', transport='', ip_version=0, tcp_seq=None,
                tcp_ack=None, tcp_flags=0, payload_offset=n, payload_length=0)

    def layer(name, offset, length):
        item = dict(name=name, offset=min(offset, n), length=max(0, min(length, n-offset)), fields=[])
        layers.append(item)
        return item

    def field(item, name, offset, length, value=None):
        if length <= 0 or offset < 0 or offset + length > n:
            return
        chunk = data[offset:offset+length]
        if value is None:
            value = int.from_bytes(chunk, 'big')
        item['fields'].append(dict(name=name, value=value, offset=offset, length=length))

    def need(offset, length, name, end=None):
        if offset + length > min(n, n if end is None else end):
            warnings.append('Truncated ' + name)
            return False
        return True

    def number(offset, length=2):
        return int.from_bytes(data[offset:offset+length], 'big')

    def address(offset, version):
        size = 4 if version == 4 else 16
        return socket.inet_ntop(socket.AF_INET if version == 4 else socket.AF_INET6, data[offset:offset+size])

    def options(item, start, end):
        # Each option is a real contiguous range, including its kind/length bytes.
        for _ in range(64):
            if start >= end:
                break
            kind = data[start]
            length = 1 if kind in (0, 1) else (data[start+1] if start+1 < end else 0)
            if length < 1 or start + length > end:
                warnings.append('Malformed or truncated options')
                break
            field(item, 'Option ' + str(kind), start, length, data[start:start+length].hex())
            start += length
            if kind == 0:
                break

    def dns(start, end):
        item = layer('DNS', start, end-start)
        if not need(start, 12, 'DNS header', end):
            return
        for name, off in [('Transaction ID', 0), ('Flags', 2), ('Questions', 4), ('Answers', 6), ('Authority records', 8), ('Additional records', 10)]:
            field(item, name, start+off, 2)

        def name_at(pos):
            initial, consumed, labels, visited = pos, None, [], set()
            for _ in range(128):
                if pos >= end or pos in visited:
                    raise ValueError('Truncated or cyclic DNS name')
                visited.add(pos)
                length = data[pos]
                if length & 0xc0 == 0xc0:
                    if pos+2 > end:
                        raise ValueError('Truncated DNS pointer')
                    if consumed is None:
                        consumed = pos+2-initial
                    pos = start + (number(pos) & 0x3fff)
                    if pos < start or pos >= end:
                        raise ValueError('Invalid DNS pointer')
                    continue
                if length > 63 or pos+1+length > end:
                    raise ValueError('Invalid DNS label')
                pos += 1
                if not length:
                    return '.'.join(labels), consumed if consumed is not None else pos-initial
                labels.append(data[pos:pos+length].decode('ascii', 'replace'))
                pos += length
            raise ValueError('DNS name exceeds inspection limit')

        pos = start+12
        counts = [number(start+off) for off in (4, 6, 8, 10)]
        budget = 128
        try:
            for section, count in zip(('Question', 'Answer', 'Authority', 'Additional'), counts):
                for _ in range(min(count, budget)):
                    budget -= 1
                    value, size = name_at(pos)
                    field(item, section + ' name', pos, size, value)
                    pos += size
                    header_size = 4 if section == 'Question' else 10
                    if not need(pos, header_size, 'DNS record', end):
                        return
                    record_type = number(pos)
                    field(item, section + ' type', pos, 2)
                    field(item, section + ' class', pos+2, 2)
                    if section == 'Question':
                        pos += 4
                        continue
                    field(item, section + ' TTL', pos+4, 4)
                    size = number(pos+8)
                    field(item, section + ' data length', pos+8, 2)
                    pos += 10
                    if not need(pos, size, 'DNS record data', end):
                        return
                    value = data[pos:pos+size].hex()
                    if record_type == 1 and size == 4:
                        value = address(pos, 4)
                    elif record_type == 28 and size == 16:
                        value = address(pos, 6)
                    elif record_type in (2, 5, 12):
                        value, _ = name_at(pos)
                    field(item, section + ' data', pos, size, value)
                    pos += size
                if count > 128 or budget == 0:
                    warnings.append('DNS record inspection limit reached')
                    break
        except ValueError as exc:
            warnings.append(str(exc))

    root = conf.l2types.num2layer.get(linktype)
    if root is None:
        warnings.append('Unsupported link type: ' + str(linktype))
        return dict(layers=layers, warnings=warnings), meta
    # Respect Scapy's link registry; never infer a link header from an IP nibble.
    try:
        root(data)
    except Exception:
        warnings.append('Scapy could not decode the captured frame')
    root_name = root.__name__
    pos, protocol, end = 0, None, n
    if root_name == 'Ether':
        item = layer('Ethernet', 0, 14)
        for label, off in [('Destination', 0), ('Source', 6)]:
            if need(off, 6, 'Ethernet address'):
                value = ':'.join(f'{b:02x}' for b in data[off:off+6])
                field(item, label, off, 6, value)
                meta[label.lower()] = value
        if not need(0, 14, 'Ethernet header'):
            return dict(layers=layers, warnings=warnings), meta
        field(item, 'Type', 12, 2)
        protocol, pos = number(12), 14
    elif root_name in ('CookedLinux', 'CookedLinuxV2'):
        size = 16 if root_name == 'CookedLinux' else 20
        item = layer('Linux cooked', 0, size)
        if not need(0, size, 'Linux cooked header'):
            return dict(layers=layers, warnings=warnings), meta
        type_offset = 14 if size == 16 else 0
        field(item, 'Protocol', type_offset, 2)
        protocol, pos = number(type_offset), size
    elif root_name in ('Loopback', 'LoopbackOpenBSD'):
        item = layer('Loopback', 0, 4)
        if not need(0, 4, 'Loopback header'):
            return dict(layers=layers, warnings=warnings), meta
        family = int.from_bytes(data[:4], 'big' if root_name == 'LoopbackOpenBSD' else 'little')
        field(item, 'Family', 0, 4, family)
        protocol, pos = (0x800 if family == 2 else 0x86dd if family in (10, 24, 28, 30) else None), 4
    elif root_name in ('IP', 'IPv46'):
        protocol = 0x800 if data and data[0] >> 4 == 4 else 0x86dd if data and data[0] >> 4 == 6 else None
    elif root_name == 'IPv6':
        protocol = 0x86dd
    else:
        warnings.append('Unsupported link decoder: ' + root_name)
        return dict(layers=layers, warnings=warnings), meta

    for _ in range(8):
        if protocol not in (0x8100, 0x88a8, 0x9100):
            break
        item = layer('VLAN', pos, 4)
        if not need(pos, 4, 'VLAN header'):
            return dict(layers=layers, warnings=warnings), meta
        field(item, 'Tag control', pos, 2)
        field(item, 'Type', pos+2, 2)
        protocol, pos = number(pos+2), pos+4

    if protocol == 0x806:
        item = layer('ARP', pos, n-pos)
        meta['protocol'] = 'ARP'
        for label, off, size in [('Hardware type', 0, 2), ('Protocol type', 2, 2), ('Hardware size', 4, 1), ('Protocol size', 5, 1), ('Operation', 6, 2)]:
            field(item, label, pos+off, size)
        if need(pos, 8, 'ARP header'):
            hlen, plen = data[pos+4], data[pos+5]
            cursor = pos+8
            for label, size in [('Sender MAC', hlen), ('Sender IP', plen), ('Target MAC', hlen), ('Target IP', plen)]:
                if not need(cursor, size, 'ARP address'):
                    break
                value = address(cursor, 4) if label.endswith('IP') and plen == 4 and number(pos+2) == 0x800 else data[cursor:cursor+size].hex(':')
                field(item, label, cursor, size, value)
                if label == 'Sender IP':
                    meta['source'] = value
                if label == 'Target IP':
                    meta['destination'] = value
                cursor += size
        return dict(layers=layers, warnings=warnings), meta

    next_header = None
    fragmented = False
    if protocol == 0x800:
        item = layer('IPv4', pos, min(20, n-pos))
        meta.update(protocol='IPv4', ip_version=4)
        for label, off, size in [('Version / header length', 0, 1), ('DSCP / ECN', 1, 1), ('Total length', 2, 2), ('Identification', 4, 2), ('Flags / fragment offset', 6, 2), ('TTL', 8, 1), ('Protocol', 9, 1), ('Checksum', 10, 2)]:
            field(item, label, pos+off, size)
        for label, off in [('Source', 12), ('Destination', 16)]:
            if pos+off+4 <= n:
                value = address(pos+off, 4)
                field(item, label, pos+off, 4, value)
                meta[label.lower()] = value
        if not need(pos, 20, 'IPv4 header'):
            return dict(layers=layers, warnings=warnings), meta
        hlen, total = (data[pos] & 15)*4, number(pos+2)
        if data[pos] >> 4 != 4 or hlen < 20 or total < hlen:
            warnings.append('Malformed IPv4 header length')
            return dict(layers=layers, warnings=warnings), meta
        if pos+total > n:
            warnings.append('Truncated IPv4 packet')
        end = min(n, pos+total)
        item['length'] = min(hlen, n-pos)
        if not need(pos, hlen, 'IPv4 options', end):
            return dict(layers=layers, warnings=warnings), meta
        options(item, pos+20, pos+hlen)
        fragmented = bool(number(pos+6) & 0x1fff)
        if number(pos+6) & 0x3fff:
            warnings.append('IPv4 fragment: IP reassembly is not performed; transport payload may be incomplete')
        next_header, pos = data[pos+9], pos+hlen
    elif protocol == 0x86dd:
        item = layer('IPv6', pos, 40)
        meta.update(protocol='IPv6', ip_version=6)
        for label, off, size in [('Version / traffic class / flow label', 0, 4), ('Payload length', 4, 2), ('Next header', 6, 1), ('Hop limit', 7, 1)]:
            field(item, label, pos+off, size)
        for label, off in [('Source', 8), ('Destination', 24)]:
            if pos+off+16 <= n:
                value = address(pos+off, 6)
                field(item, label, pos+off, 16, value)
                meta[label.lower()] = value
        if not need(pos, 40, 'IPv6 header'):
            return dict(layers=layers, warnings=warnings), meta
        if data[pos] >> 4 != 6:
            warnings.append('Malformed IPv6 version')
            return dict(layers=layers, warnings=warnings), meta
        declared_end = pos+40+number(pos+4)
        if declared_end > n:
            warnings.append('Truncated IPv6 packet')
        end = min(n, declared_end)
        next_header, pos = data[pos+6], pos+40
        for _ in range(16):
            if next_header not in (0, 43, 44, 51, 60):
                break
            if not need(pos, 2, 'IPv6 extension', end):
                return dict(layers=layers, warnings=warnings), meta
            size = 8 if next_header == 44 else (data[pos+1]+2)*4 if next_header == 51 else (data[pos+1]+1)*8
            item = layer('IPv6 extension ' + str(next_header), pos, min(size, end-pos))
            field(item, 'Next header', pos, 1)
            if not need(pos, size, 'IPv6 extension', end):
                return dict(layers=layers, warnings=warnings), meta
            if next_header == 44:
                field(item, 'Fragment offset / flags', pos+2, 2)
                fragmented = bool(number(pos+2) & 0xfff8)
                if number(pos+2) & 0xfff9:
                    warnings.append('IPv6 fragment: IP reassembly is not performed; transport payload may be incomplete')
            field(item, 'Extension data', pos+1, size-1, data[pos+1:pos+size].hex())
            next_header, pos = data[pos], pos+size
    else:
        warnings.append('Unsupported network protocol')

    if fragmented:
        warnings.append('Noninitial fragment: transport header unavailable')
        return dict(layers=layers, warnings=warnings), meta
    if next_header in (6, 17):
        transport = 'TCP' if next_header == 6 else 'UDP'
        minimum = 20 if transport == 'TCP' else 8
        item = layer(transport, pos, min(minimum, end-pos))
        meta.update(protocol=transport, transport=transport)
        for label, off in [('Source port', 0), ('Destination port', 2)]:
            if pos+off+2 <= end:
                value = number(pos+off)
                field(item, label, pos+off, 2, value)
                meta[label.lower().replace(' ', '_')] = value
        if transport == 'TCP':
            for label, off, size in [('Sequence number', 4, 4), ('Acknowledgment number', 8, 4), ('Header length / flags', 12, 2), ('Window', 14, 2), ('Checksum', 16, 2), ('Urgent pointer', 18, 2)]:
                if pos+off+size <= end:
                    field(item, label, pos+off, size)
            if pos+12 <= end:
                meta.update(tcp_seq=number(pos+4, 4), tcp_ack=number(pos+8, 4))
            if pos+14 <= end:
                meta['tcp_flags'] = number(pos+12) & 0x1ff
                field(item, 'Flags', pos+12, 2, meta['tcp_flags'])
            hlen = (data[pos+12] >> 4)*4 if pos+13 <= end else minimum
            if hlen < 20:
                warnings.append('Malformed TCP header length')
                return dict(layers=layers, warnings=warnings), meta
        else:
            field(item, 'Length', pos+4, 2)
            field(item, 'Checksum', pos+6, 2)
            hlen = 8
        if not need(pos, max(minimum, hlen), transport + ' header', end):
            return dict(layers=layers, warnings=warnings), meta
        item['length'] = hlen
        if transport == 'TCP':
            options(item, pos+20, pos+hlen)
        else:
            udp_length = number(pos+4)
            if udp_length < 8:
                warnings.append('Malformed UDP length')
                return dict(layers=layers, warnings=warnings), meta
            if pos+udp_length > end:
                warnings.append('Truncated UDP datagram')
            end = min(end, pos+udp_length)
        pos += hlen
        meta.update(payload_offset=pos, payload_length=max(0, end-pos))
        payload = data[pos:end]
        if 53 in (meta['source_port'], meta['destination_port']):
            dns_pos = pos
            if transport == 'TCP':
                if not need(pos, 2, 'DNS TCP length', end):
                    return dict(layers=layers, warnings=warnings), meta
                size = number(pos)
                dns_pos += 2
                if dns_pos+size > end:
                    warnings.append('Truncated DNS TCP message')
                end = min(end, dns_pos+size)
            if end-dns_pos >= 12:
                meta['protocol'] = 'DNS'
                dns(dns_pos, end)
        elif transport == 'TCP' and HTTP_START.match(payload[:8192]):
            meta['protocol'] = 'HTTP'
            item = layer('HTTP', pos, end-pos)
            cursor = pos
            for index in range(128):
                line_end = data.find(b'\r\n', cursor, min(end, pos+16384))
                if line_end < 0 or line_end == cursor:
                    break
                line = data[cursor:line_end]
                if index == 0:
                    field(item, 'Start line', cursor, len(line), line.decode('latin1'))
                elif b':' in line:
                    name, value = line.split(b':', 1)
                    field(item, name.decode('latin1'), cursor, len(line), value.decode('latin1').strip())
                cursor = line_end+2
        elif transport == 'TCP' and len(payload) >= 5 and payload[0] in (20, 21, 22, 23, 24) and payload[1] == 3 and payload[2] <= 4:
            meta['protocol'] = 'TLS'
            item = layer('TLS', pos, end-pos)
            field(item, 'Content type', pos, 1)
            field(item, 'Version', pos+1, 2)
            field(item, 'Record length', pos+3, 2)
            if number(pos+3)+5 > len(payload):
                warnings.append('Truncated TLS record')
        elif payload:
            layer('Data', pos, end-pos)
    elif next_header in (1, 58):
        meta.update(protocol='ICMP', transport='ICMP')
        item = layer('ICMP' if next_header == 1 else 'ICMPv6', pos, max(0, end-pos))
        for label, off, size in [('Type', 0, 1), ('Code', 1, 1), ('Checksum', 2, 2)]:
            if pos+off+size <= end:
                field(item, label, pos+off, size)
        need(pos, 4, 'ICMP header', end)
        meta.update(payload_offset=min(pos+8, end), payload_length=max(0, end-pos-8))
    return dict(layers=layers, warnings=warnings[:32]), meta


def dissect(data: bytes, linktype: int) -> dict:
    """Return observed fields and exact ranges into the retained original bytes."""
    try:
        result, _ = _inspect(data, linktype)
        return result
    except Exception as exc:
        return dict(layers=[], warnings=['Malformed frame: ' + type(exc).__name__])


def frame_snapshot(raw) -> dict:
    """Copy bounded original bytes on the sniffer thread; defer decoding to its worker."""
    original = getattr(raw, 'original', None)
    data = original if isinstance(original, bytes) and original else bytes(raw)
    captured_length = len(data)
    retained = data[:MAX_BYTES]
    wirelen = getattr(raw, 'wirelen', None)
    length = int(wirelen) if wirelen is not None else captured_length
    try:
        timestamp = float(raw.time)
    except (TypeError, ValueError, AttributeError):
        timestamp = 0.0
    return dict(timestamp=timestamp, length=length, captured_length=captured_length,
                linktype=conf.l2types.layer2num.get(type(raw), -1), raw_data=retained,
                header_data=retained[:512], raw_status='truncated' if captured_length > MAX_BYTES or length > captured_length else 'available')


def decode_snapshot(snapshot) -> dict:
    try:
        decoded, meta = _inspect(snapshot['raw_data'] or snapshot.get('header_data', b''), snapshot['linktype'])
    except Exception:
        decoded, meta = _inspect(b'', -1)
    summary = f"{meta['protocol']} {meta['source']}:{meta['source_port']} -> {meta['destination']}:{meta['destination_port']}"
    if meta['transport'] == 'TCP':
        flags = [name for name, value in [('FIN', 1), ('SYN', 2), ('RST', 4), ('ACK', 16)] if meta['tcp_flags'] & value]
        summary += ' [' + ', '.join(flags) + f"] Seq={meta['tcp_seq']} Ack={meta['tcp_ack']}"
    for item in decoded['layers']:
        if item['name'] in ('DNS', 'HTTP'):
            values = [str(f['value']) for f in item['fields'] if f['name'] in ('Question name', 'Start line')]
            if values:
                summary += ' / ' + values[0]
    return {**snapshot, **meta, 'summary': summary[:256], 'warnings': decoded['warnings']}


def capture_frame(raw) -> dict:
    """Take an original-byte snapshot and decode its bounded inspection projection."""
    return decode_snapshot(frame_snapshot(raw))
