from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine, get_db
from .demo import seed_demo
from .models import Flow, Settings
from .schemas import FlowSchema, SettingsSchema
from .advanced import router as advanced_router


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed_demo(db)
    yield


app = FastAPI(title="FlowTwin", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5174", "http://127.0.0.1:5174"], allow_methods=["GET", "PUT", "POST", "PATCH"], allow_headers=["Content-Type"])
app.include_router(advanced_router)


def selected_flows(db, hours=24):
    settings = db.get(Settings, 1)
    rows = list(db.scalars(select(Flow).where(Flow.is_demo == settings.demo_mode).order_by(Flow.timestamp)))
    if rows:
        cutoff = datetime.fromisoformat(rows[-1].timestamp) - timedelta(hours=hours)
        rows = [f for f in rows if datetime.fromisoformat(f.timestamp) > cutoff]
    return rows


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    from .detection import model_metrics
    return {"status": "ok", "database": "connected", "phase": 4, "model": "trained" if model_metrics() else "not_trained", "capture": "pcap_import_and_replay"}


@app.get("/api/settings", response_model=SettingsSchema)
def settings(db: Session = Depends(get_db)):
    return db.get(Settings, 1)


@app.put("/api/settings", response_model=SettingsSchema)
def update_settings(payload: SettingsSchema, db: Session = Depends(get_db)):
    row = db.get(Settings, 1)
    row.demo_mode = payload.demo_mode
    row.refresh_seconds = payload.refresh_seconds
    db.commit()
    db.refresh(row)
    return row


@app.get("/api/overview")
def overview(hours: int = Query(24), db: Session = Depends(get_db)):
    if hours not in (1, 6, 24):
        raise HTTPException(422, "hours must be 1, 6, or 24")
    rows = selected_flows(db, hours)
    counts = Counter(f.classification for f in rows)
    timeline = {}
    for f in rows:
        key = f.timestamp[:13] + ":00:00+00:00"
        bucket = timeline.setdefault(key, {"time": key, "benign": 0, "suspicious": 0, "malicious": 0, "bytes": 0})
        bucket[f.classification] += 1
        bucket["bytes"] += f.bytes
    return {
        "is_demo": db.get(Settings, 1).demo_mode,
        "window_hours": hours, "window_end": rows[-1].timestamp if rows else None,
        "total": len(rows), "benign": counts["benign"], "suspicious": counts["suspicious"], "malicious": counts["malicious"], "unanalyzed": counts["unanalyzed"],
        "packets": sum(f.packets for f in rows), "bytes": sum(f.bytes for f in rows),
        "protocols": [{"name": k, "value": v} for k, v in Counter(f.protocol for f in rows).items()],
        "threats": [{"name": k, "value": v} for k, v in Counter(f.category for f in rows if f.classification != "benign").items()],
        "timeline": list(timeline.values()),
        "top_sources": [{"name": k, "value": v} for k, v in Counter(f.source for f in rows).most_common(6)],
        "alerts": [FlowSchema.model_validate(f).model_dump() for f in reversed(rows) if f.classification != "benign"][:6],
    }


@app.get("/api/flows")
def flows(q: str = Query("", max_length=100), protocol: Literal["all", "TCP", "UDP", "ICMP"] = "all", classification: Literal["all", "benign", "suspicious", "malicious", "unanalyzed"] = "all", page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100), db: Session = Depends(get_db)):
    rows = list(reversed(selected_flows(db)))
    rows = [f for f in rows if (protocol == "all" or f.protocol == protocol) and (classification == "all" or f.classification == classification) and q.lower() in f"{f.source} {f.destination} {f.category} {f.id}".lower()]
    start = (page - 1) * page_size
    return {"is_demo": db.get(Settings, 1).demo_mode, "total": len(rows), "page": page, "items": [FlowSchema.model_validate(f).model_dump() for f in rows[start:start + page_size]]}


@app.get("/api/flows/{flow_id}", response_model=FlowSchema)
def flow_detail(flow_id: int, db: Session = Depends(get_db)):
    row = db.get(Flow, flow_id)
    if not row or row.is_demo != db.get(Settings, 1).demo_mode:
        raise HTTPException(404, "Flow not found in the current data mode")
    return row
