"""Create a tiny, clearly synthetic PCAP for the reviewer walkthrough.

This is a parser/replay exercise, not a labeled intrusion dataset or evidence of attacks.
"""
from pathlib import Path

from scapy.all import Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

TARGET = Path(__file__).resolve().parent / "sample_capture.pcap"


def main():
    packets = []
    for source, destination, source_port, dest_port in [
        ("192.0.2.10", "198.51.100.20", 51001, 443),
        ("192.0.2.11", "198.51.100.20", 51002, 22),
    ]:
        packets += [
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src=source, dst=destination)/TCP(sport=source_port, dport=dest_port, flags="S"),
            Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")/IP(src=destination, dst=source)/TCP(sport=dest_port, dport=source_port, flags="SA"),
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src=source, dst=destination)/TCP(sport=source_port, dport=dest_port, flags="A")/Raw(load=b"review-only"),
        ]
    packets += [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.10", dst="198.51.100.53")/UDP(sport=53000, dport=53)/Raw(load=b"test"),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.10", dst="198.51.100.20")/ICMP(type="echo-request"),
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")/IP(src="198.51.100.20", dst="192.0.2.10")/ICMP(type="echo-reply"),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1_700_000_000 + index * 0.08
    wrpcap(str(TARGET), packets)
    print(f"Wrote {len(packets)} synthetic packets to {TARGET}")


if __name__ == "__main__":
    main()
