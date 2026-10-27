"""Bounded offline PCAP analysis. No packet content is executed or persisted."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev

from scapy.all import ICMP, IP, IPv6, TCP, UDP, PcapReader

MAX_PACKETS = 50_000
MAX_FLOWS = 5_000
FLOW_TIMEOUT = 120.0  # seconds; matches CICFlowMeter default duration boundary


def iso(timestamp):
    return datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat()


def extract_packet(packet):
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip is None:
        return None
    transport = packet.getlayer(TCP) or packet.getlayer(UDP) or packet.getlayer(ICMP)
    if transport is None:
        return None
    proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP"
    src_port = int(transport.sport) if proto != "ICMP" else 0
    dst_port = int(transport.dport) if proto != "ICMP" else 0
    flags = str(packet[TCP].flags) if proto == "TCP" else ""
    return {
        "timestamp": float(packet.time), "source": str(ip.src), "destination": str(ip.dst),
        "source_port": src_port, "destination_port": dst_port, "protocol": proto,
        "size": len(bytes(ip)), "payload_size": len(bytes(transport.payload)), "flags": flags,
    }


def packet_key(p):
    a = (p["source"], p["source_port"])
    b = (p["destination"], p["destination_port"])
    return (p["protocol"], min(a, b), max(a, b))


def summarize(flow):
    packets = flow["packets"]
    stamps = [p["timestamp"] for p in packets]
    lengths = [p["size"] for p in packets]
    fwd = [p for p in packets if p["direction"] == "forward"]
    bwd = [p for p in packets if p["direction"] == "backward"]
    duration_seconds = max(stamps) - min(stamps)
    iats = [max(0, b - a) * 1e6 for a, b in zip(stamps, stamps[1:])]
    flags = Counter(flag for p in packets for flag in "FSRPAUEC" if flag in p["flags"])
    features = {
        "Flow Duration": max(0, duration_seconds * 1e6),
        "Total Fwd Packets": len(fwd), "Total Backward Packets": len(bwd),
        "Total Length of Fwd Packets": sum(p["payload_size"] for p in fwd),
        "Total Length of Bwd Packets": sum(p["payload_size"] for p in bwd),
        "Packet Length Mean": mean(lengths), "Packet Length Std": pstdev(lengths),
        "Flow Packets/s": len(packets) / duration_seconds if duration_seconds else 0,
        "Flow IAT Mean": mean(iats) if iats else 0,
        "Flow IAT Std": pstdev(iats) if iats else 0,
        "FIN Flag Count": flags["F"], "SYN Flag Count": flags["S"],
        "RST Flag Count": flags["R"], "PSH Flag Count": flags["P"],
        "ACK Flag Count": flags["A"], "URG Flag Count": flags["U"],
    }
    return {
        "timestamp": iso(min(stamps)), "source": flow["source"], "destination": flow["destination"],
        "source_port": flow["source_port"], "destination_port": flow["destination_port"],
        "protocol": flow["protocol"], "packets": len(packets), "bytes": sum(lengths),
        "duration_ms": round(duration_seconds * 1000, 3), "features": features,
        "packet_size_min": min(lengths), "packet_size_max": max(lengths),
        "packet_size_mean": mean(lengths), "packet_size_std": pstdev(lengths),
        "forward_packets": len(fwd), "backward_packets": len(bwd),
        "forward_bytes": sum(p["size"] for p in fwd), "backward_bytes": sum(p["size"] for p in bwd),
        "tcp_flags": dict(flags), "iat_mean_us": features["Flow IAT Mean"],
        "iat_std_us": features["Flow IAT Std"], "flow_packets_per_second": features["Flow Packets/s"],
        "records": packets,
    }


def analyze_pcap(path: Path):
    active = {}
    completed = []
    accepted = 0
    with PcapReader(str(path)) as reader:
        for raw_index, raw in enumerate(reader):
            if raw_index >= MAX_PACKETS:
                raise ValueError(f"PCAP exceeds the {MAX_PACKETS:,} packet processing limit")
            packet = extract_packet(raw)
            if packet is None:
                continue
            accepted += 1
            key = packet_key(packet)
            previous = active.get(key)
            if previous and (packet["timestamp"] - previous["last"] > FLOW_TIMEOUT or packet["timestamp"] - previous["first"] > FLOW_TIMEOUT or (previous["protocol"] == "TCP" and any("F" in p["flags"] or "R" in p["flags"] for p in previous["packets"][-1:]))):
                completed.append(summarize(previous))
                del active[key]
                previous = None
            if previous is None:
                if len(active) + len(completed) >= MAX_FLOWS:
                    raise ValueError(f"PCAP exceeds the {MAX_FLOWS:,} flow processing limit")
                previous = {"source": packet["source"], "destination": packet["destination"], "source_port": packet["source_port"], "destination_port": packet["destination_port"], "protocol": packet["protocol"], "first": packet["timestamp"], "last": packet["timestamp"], "packets": []}
                active[key] = previous
            packet["direction"] = "forward" if packet["source"] == previous["source"] and packet["source_port"] == previous["source_port"] else "backward"
            previous["packets"].append(packet)
            previous["last"] = packet["timestamp"]
    completed.extend(summarize(flow) for flow in active.values())
    completed.sort(key=lambda row: row["timestamp"])
    return {"packet_count": accepted, "flows": completed}
