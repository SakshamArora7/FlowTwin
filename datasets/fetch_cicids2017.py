"""Download selected original CIC-IDS2017 flow tables from a documented Parquet mirror.

Run from the project root with .venv/Scripts/python.exe datasets/fetch_cicids2017.py.
Files are converted, not relabeled. The upstream source remains UNB/CIC.
"""
import hashlib
import json
import urllib.request
from pathlib import Path

BASE = "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/machine_learning/"
FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet",
    "Tuesday-WorkingHours.pcap_ISCX.csv.parquet",
    "Wednesday-workingHours.pcap_ISCX.csv.parquet",
]
ROOT = Path(__file__).resolve().parent / "raw"


def main():
    ROOT.mkdir(exist_ok=True)
    manifest = {}
    for name in FILES:
        target = ROOT / name
        if not target.exists():
            print(f"Downloading {name}", flush=True)
            request = urllib.request.Request(BASE + name, headers={"User-Agent": "FlowTwin-study/1.0"})
            with urllib.request.urlopen(request, timeout=90) as response, (ROOT / (name + ".part")).open("wb") as out:
                while chunk := response.read(1024 * 1024):
                    out.write(chunk)
            (ROOT / (name + ".part")).replace(target)
        with target.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        manifest[name] = {"url": BASE + name, "bytes": target.stat().st_size, "sha256": digest}
        print(f"Ready {name} ({target.stat().st_size} bytes)", flush=True)
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
