"""Bounded offline flow analysis with independently retained inspection frames."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from math import sqrt

from scapy.all import ICMP, IP, IPv6, TCP, UDP, PcapReader

from .dissection import capture_frame

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


class Moments:
    """Constant-space population mean and variance (Welford)."""
    def __init__(self):
        self.count = 0
        self.mean = self.m2 = 0.0

    def add(self, value):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def std(self):
        return sqrt(max(0, self.m2 / self.count)) if self.count else 0.0


def flow_expiration(first, last, protocol, flags, timestamp):
    if timestamp - last > FLOW_TIMEOUT:
        return "inactivity"
    if timestamp - first > FLOW_TIMEOUT:
        return "duration"
    if protocol == "TCP" and ("F" in flags or "R" in flags):
        return "tcp_end"
    return None


class FlowStats:
    """Incremental statistics shared by PCAP summaries and live capture."""
    def __init__(self, packet):
        self.endpoint = {k: packet[k] for k in ("source", "destination", "source_port", "destination_port", "protocol")}
        self.first = self.last = packet["timestamp"]
        self.minimum_time = self.maximum_time = self.first
        self.lengths, self.iats = Moments(), Moments()
        self.minimum_size = float("inf")
        self.maximum_size = 0
        self.flags = Counter()
        self.directions = {d: {"packets": 0, "bytes": 0, "payload": 0} for d in ("forward", "backward")}
        self.last_flags = ""

    def add(self, packet):
        direction = "forward" if (packet["source"], packet["source_port"]) == (self.endpoint["source"], self.endpoint["source_port"]) else "backward"
        packet["direction"] = direction
        if self.lengths.count:
            self.iats.add(max(0, packet["timestamp"] - self.last) * 1e6)
        self.last = packet["timestamp"]
        self.minimum_time = min(self.minimum_time, self.last)
        self.maximum_time = max(self.maximum_time, self.last)
        self.last_flags = packet["flags"]
        self.lengths.add(packet["size"])
        self.minimum_size = min(self.minimum_size, packet["size"])
        self.maximum_size = max(self.maximum_size, packet["size"])
        self.flags.update(flag for flag in "FSRPAUEC" if flag in packet["flags"])
        totals = self.directions[direction]
        totals["packets"] += 1
        totals["bytes"] += packet["size"]
        totals["payload"] += packet["payload_size"]
        return direction

    def expiration(self, timestamp):
        return flow_expiration(self.first, self.last, self.endpoint["protocol"], self.last_flags, timestamp)

    def summary(self):
        forward, backward = self.directions["forward"], self.directions["backward"]
        duration = self.maximum_time - self.minimum_time
        rate = self.lengths.count / duration if duration else 0
        features = {
            "Flow Duration": max(0, duration * 1e6),
            "Total Fwd Packets": forward["packets"], "Total Backward Packets": backward["packets"],
            "Total Length of Fwd Packets": forward["payload"], "Total Length of Bwd Packets": backward["payload"],
            "Packet Length Mean": self.lengths.mean, "Packet Length Std": self.lengths.std,
            "Flow Packets/s": rate, "Flow IAT Mean": self.iats.mean, "Flow IAT Std": self.iats.std,
            **{f"{name} Flag Count": self.flags[flag] for name, flag in (("FIN", "F"), ("SYN", "S"), ("RST", "R"), ("PSH", "P"), ("ACK", "A"), ("URG", "U"))},
        }
        return {
            **self.endpoint, "timestamp": iso(self.minimum_time), "packets": self.lengths.count,
            "bytes": forward["bytes"] + backward["bytes"], "duration_ms": round(duration * 1000, 3), "features": features,
            "packet_size_min": self.minimum_size, "packet_size_max": self.maximum_size,
            "packet_size_mean": self.lengths.mean, "packet_size_std": self.lengths.std,
            "forward_packets": forward["packets"], "backward_packets": backward["packets"],
            "forward_bytes": forward["bytes"], "backward_bytes": backward["bytes"],
            "tcp_flags": dict(self.flags), "iat_mean_us": self.iats.mean, "iat_std_us": self.iats.std,
            "flow_packets_per_second": rate,
        }


def summarize(flow):
    stats = FlowStats(flow["packets"][0])
    for packet in flow["packets"]:
        stats.add(packet)
    return {**stats.summary(), "records": flow["packets"]}


def analyze_pcap(path: Path):
    active = {}
    completed = []
    accepted = 0
    inspection_frames = []
    retained_bytes = 0
    with PcapReader(str(path)) as reader:
        for raw_index, raw in enumerate(reader):
            if raw_index >= MAX_PACKETS:
                raise ValueError(f"PCAP exceeds the {MAX_PACKETS:,} packet processing limit")
            frame = capture_frame(raw)
            frame['number'] = raw_index + 1
            if retained_bytes + len(frame['raw_data']) > 64 * 1024 * 1024:
                frame.update(raw_data=b'', raw_status='retention_limit')
            retained_bytes += len(frame['raw_data'])
            inspection_frames.append(frame)
            packet = extract_packet(raw)
            if packet is None:
                continue
            packet["_number"] = raw_index + 1
            accepted += 1
            key = packet_key(packet)
            previous = active.get(key)
            if previous and flow_expiration(previous["first"], previous["last"], previous["protocol"], previous["packets"][-1]["flags"], packet["timestamp"]):
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
    return {"packet_count": accepted, "flows": completed, "inspection_frames": inspection_frames}
