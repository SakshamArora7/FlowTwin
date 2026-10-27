"""Deterministic UI fixtures. These are NOT packets, predictions, or evaluation data."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .models import Flow, Settings


def seed_demo(db):
    if db.get(Settings, 1) is None:
        db.add(Settings(id=1, demo_mode=True, refresh_seconds=30))
    if db.scalar(select(Flow.id).where(Flow.is_demo.is_(True)).limit(1)) is None:
        start = datetime(2026, 10, 25, 0, 0, tzinfo=timezone.utc)
        for i in range(240):
            classification = "malicious" if i % 19 == 0 else "suspicious" if i % 11 == 0 else "benign"
            category = ("Port scan" if i % 2 else "DoS") if classification == "malicious" else "Unusual connection" if classification == "suspicious" else "Benign"
            protocol = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"][i % 6]
            db.add(Flow(
                timestamp=(start + timedelta(minutes=i * 6)).isoformat(),
                source=f"192.168.1.{10 + i % 18}",
                destination=f"198.51.100.{1 + i % 9}",
                source_port=0 if protocol == "ICMP" else 49152 + i,
                destination_port=0 if protocol == "ICMP" else [443, 80, 22, 53, 8080][i % 5],
                protocol=protocol, packets=12 + (i * 17) % 180,
                bytes=(12 + (i * 17) % 180) * (96 + (i * 31) % 1300),
                duration_ms=round(15 + (i * 19.7) % 4500, 2),
                classification=classification, category=category, is_demo=True,
            ))
    db.commit()
