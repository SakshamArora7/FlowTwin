"""Versioned CIC-IDS2017 subset used without renaming or unit conversion."""

SCHEMA_VERSION = "cicids2017-counts-flags-us-v1"
FEATURES = (
    "Flow Duration",                 # microseconds
    "Total Fwd Packets",             # count, first observed direction
    "Total Backward Packets",        # count
    "FIN Flag Count",                # count across both directions
    "SYN Flag Count",                # count
    "RST Flag Count",                # count
    "ACK Flag Count",                # count
)


def normalize_label(raw):
    label = str(raw).strip().lower()
    if label == "benign":
        return "Benign"
    if label == "ddos":
        return "DDoS"
    if label.startswith("dos "):
        return "DoS"
    if label in {"portscan", "port scan"}:
        return "Port scan"
    if "patator" in label or "brute force" in label:
        return "Brute force"
    if label == "bot":
        return "Botnet"
    return None
