import struct

import pytest
from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, IPv6, Raw, TCP, UDP
from scapy.layers.inet6 import IPv6ExtHdrHopByHop
from scapy.layers.l2 import CookedLinux, Loopback

from backend.app import dissection


def field(result, layer, name):
    return next(f for item in result['layers'] if item['name'] == layer for f in item['fields'] if f['name'] == name)


def ranges(result, data):
    for layer in result['layers']:
        assert 0 <= layer['offset'] <= len(data)
        assert 0 <= layer['length'] <= len(data) - layer['offset']
        for item in layer['fields']:
            assert 0 <= item['offset'] < len(data)
            assert 0 < item['length'] <= len(data) - item['offset']


def test_original_bytes_and_options_offsets():
    packet = Ether()/IP(src='10.0.0.1', dst='10.0.0.2', options=b'\x01\x01\x00\x00')/TCP(sport=123, dport=80, seq=123456, ack=42, flags='PA', options=[('MSS', 1460)])/Raw(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
    data = bytes(packet)
    packet = Ether(data)
    packet.wirelen = len(data) + 9
    frame = dissection.capture_frame(packet)
    assert frame['raw_data'] == data
    assert frame['length'] == len(data) + 9
    assert frame['captured_length'] == len(data)
    assert frame['raw_status'] == 'truncated'
    assert frame['protocol'] == 'HTTP'
    assert frame['tcp_seq'] == 123456
    assert frame['tcp_ack'] == 42
    assert frame['tcp_flags'] == 24
    assert frame['payload_offset'] == 14 + 24 + 24
    assert frame['payload_length'] == len(data) - frame['payload_offset']
    result = dissection.dissect(data, 1)
    assert field(result, 'IPv4', 'Source')['offset'] == 26
    assert field(result, 'TCP', 'Sequence number')['offset'] == 42
    assert field(result, 'TCP', 'Flags')['value'] == 24
    assert struct.unpack('!I', data[42:46])[0] == field(result, 'TCP', 'Sequence number')['value']
    assert field(result, 'HTTP', 'Host')['value'] == 'example.test'
    ranges(result, data)


def test_arp_and_raw_ip_preserve_framing():
    packet = Ether()/ARP(psrc='192.0.2.1', pdst='192.0.2.2')
    frame = dissection.capture_frame(Ether(bytes(packet)))
    assert frame['protocol'] == 'ARP'
    assert frame['source'] == '192.0.2.1'
    ranges(dissection.dissect(bytes(packet), 1), bytes(packet))
    packet = IP(bytes(IP(src='192.0.2.5')/UDP()/Raw(b'abc')))
    frame = dissection.capture_frame(packet)
    assert frame['raw_data'] == bytes(packet)
    assert frame['linktype'] in (12, 101, 228)
    assert frame['payload_offset'] == 28


def test_ipv6_dns_fields():
    data = bytes(Ether()/IPv6(src='2001:db8::1', dst='2001:db8::2')/UDP(sport=53, dport=53000)/DNS(id=99, qr=1, qd=DNSQR(qname='example.test'), an=DNSRR(rrname='example.test', rdata='192.0.2.1')))
    frame = dissection.capture_frame(Ether(data))
    assert frame['protocol'] == 'DNS'
    assert frame['ip_version'] == 6
    result = dissection.dissect(data, 1)
    assert field(result, 'DNS', 'Transaction ID')['offset'] == 62
    assert field(result, 'DNS', 'Question name')['value'] == 'example.test'
    assert field(result, 'DNS', 'Answer data')['value'] == '192.0.2.1'
    ranges(result, data)


def test_tls_is_opaque():
    data = bytes(Ether()/IP()/TCP(dport=443)/Raw(b'\x16\x03\x03\x00\x03abc'))
    assert dissection.capture_frame(Ether(data))['protocol'] == 'TLS'
    result = dissection.dissect(data, 1)
    assert 'TLS' in [layer['name'] for layer in result['layers']]
    assert 'HTTP' not in [layer['name'] for layer in result['layers']]
    ranges(result, data)


@pytest.mark.parametrize('data,linktype', [(b'abc', 1), (b'\x45' + b'\x00'*9, 101), (b'garbage', 99999), (b'', 1)])
def test_truncated_and_unknown_are_bounded(data, linktype):
    result = dissection.dissect(data, linktype)
    assert result['warnings']
    ranges(result, data)


def test_retention_cap():
    packet = Ether()/IP()/UDP()/Raw(b'x'*65500)
    data = bytes(packet)
    frame = dissection.capture_frame(Ether(data))
    assert frame['raw_data'] == data[:65535]
    assert frame['captured_length'] == len(data)
    assert frame['raw_status'] == 'truncated'


def test_cooked_loopback_and_ipv6_extension_payload_offsets():
    for packet, offset in [(CookedLinux()/IP()/UDP()/Raw(b'abc'), 44),
                           (Loopback()/IP()/UDP()/Raw(b'abc'), 32),
                           (Ether()/IPv6()/IPv6ExtHdrHopByHop()/TCP()/Raw(b'abc'), 82)]:
        packet = type(packet)(bytes(packet))
        frame = dissection.capture_frame(packet)
        assert frame['payload_offset'] == offset
        assert frame['payload_length'] == 3
        assert frame['raw_data'][offset:] == b'abc'
        ranges(dissection.dissect(frame['raw_data'], frame['linktype']), frame['raw_data'])


def test_original_capture_survives_scapy_field_changes():
    data = bytes(Ether()/IP(src='192.0.2.1')/TCP(seq=91)/Raw(b'abc'))
    packet = Ether(data)
    packet[IP].src = '198.51.100.1'
    assert bytes(packet) != data
    frame = dissection.capture_frame(packet)
    assert frame['raw_data'] == data
    assert frame['source'] == '192.0.2.1'


def test_noninitial_fragment_does_not_invent_transport():
    data = bytes(Ether()/IP(proto=6, frag=1)/Raw(b'x'*30))
    frame = dissection.capture_frame(Ether(data))
    assert frame['transport'] == ''
    assert frame['tcp_seq'] is None
    assert 'TCP' not in [item['name'] for item in dissection.dissect(data, 1)['layers']]


def test_dns_compression_cycle_is_bounded():
    payload = struct.pack('!HHHHHH', 1, 0, 1, 0, 0, 0) + b'\xc0\x0c\x00\x01\x00\x01'
    data = bytes(Ether()/IP()/UDP(dport=53)/Raw(payload))
    result = dissection.dissect(data, 1)
    assert any('cyclic' in warning for warning in result['warnings'])
    ranges(result, data)
