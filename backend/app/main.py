import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text, func, case, cast, String
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine, get_db
from .demo import seed_demo
from .models import Flow, Settings
from .schemas import FlowSchema, SettingsSchema
from .advanced import router as advanced_router
from .live_api import router as live_router
from . import live


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed_demo(db)
        live.recover_sessions(db)
    try:
        yield
    finally:
        await live.capture.close()


app = FastAPI(title="FlowTwin", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5174", "http://127.0.0.1:5174"], allow_methods=["GET", "PUT", "POST", "PATCH"], allow_headers=["Content-Type"])
app.include_router(advanced_router)
app.include_router(live_router)


def selected_flows(db, hours=24):
    settings = db.get(Settings, 1)
    query = select(Flow).where(Flow.is_demo == settings.demo_mode)
    latest = db.scalar(query.with_only_columns(func.max(Flow.timestamp)))
    if latest:
        cutoff = (datetime.fromisoformat(latest) - timedelta(hours=hours)).isoformat()
        query = query.where(Flow.timestamp > cutoff)
    return query


@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    from .detection import model_metrics
    return {"status": "ok", "database": "connected", "phase": 4, "model": "trained" if model_metrics() else "not_trained", "capture": "pcap_import_and_replay"}


@app.get("/api/settings", response_model=SettingsSchema)
def settings(db: Session = Depends(get_db)):
    return db.get(Settings, 1)


@app.put("/api/settings", response_model=SettingsSchema)
async def update_settings(payload: SettingsSchema, db: Session = Depends(get_db)):
    async with live.capture.control:
        if payload.demo_mode and live.capture.busy:
            raise HTTPException(409, "Stop live monitoring before enabling sample mode")
        return await asyncio.to_thread(save_settings, payload, db)


def save_settings(payload, db):
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
    query = selected_flows(db, hours)
    counts = dict(db.execute(query.with_only_columns(Flow.classification, func.count(Flow.id)).group_by(Flow.classification)).all())
    totals = db.execute(query.with_only_columns(func.sum(Flow.packets), func.sum(Flow.bytes), func.max(Flow.timestamp))).one()
    def distribution(column, flagged=False, limit=None):
        grouped = query.where(Flow.classification.in_(["suspicious", "malicious"])) if flagged else query
        grouped = grouped.with_only_columns(column, func.count(Flow.id)).group_by(column)
        if limit:
            grouped = grouped.order_by(func.count(Flow.id).desc(), column).limit(limit)
        return [{"name": name, "value": value} for name, value in db.execute(grouped)]
    labels = ("benign", "suspicious", "malicious", "unanalyzed")
    hour = func.substr(Flow.timestamp, 1, 13)
    buckets = db.execute(query.with_only_columns(hour, *(func.sum(case((Flow.classification == label, 1), else_=0)) for label in labels), func.sum(Flow.bytes)).group_by(hour).order_by(hour))
    timeline = [{"time": row[0] + ":00:00+00:00", **dict(zip(labels, row[1:5])), "bytes": row[5]} for row in buckets]
    alerts = db.scalars(query.where(Flow.classification.in_(["suspicious", "malicious"])).order_by(Flow.timestamp.desc(), Flow.id.desc()).limit(6))
    return {
        "is_demo": db.get(Settings, 1).demo_mode,
        "window_hours": hours, "window_end": totals[2], "total": sum(counts.values()),
        **{label: counts.get(label, 0) for label in labels},
        "packets": totals[0] or 0, "bytes": totals[1] or 0,
        "protocols": distribution(Flow.protocol), "threats": distribution(Flow.category, flagged=True),
        "timeline": timeline, "top_sources": distribution(Flow.source, limit=6),
        "alerts": [FlowSchema.model_validate(f).model_dump() for f in alerts],
    }



@app.get("/api/flows")
def flows(q: str = Query("", max_length=100), protocol: Literal["all", "TCP", "UDP", "ICMP"] = "all", classification: Literal["all", "benign", "suspicious", "malicious", "unanalyzed"] = "all", page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100), db: Session = Depends(get_db)):
    query = selected_flows(db)
    if protocol != "all":
        query = query.where(Flow.protocol == protocol)
    if classification != "all":
        query = query.where(Flow.classification == classification)
    if q:
        searchable = Flow.source + " " + Flow.destination + " " + Flow.category + " " + cast(Flow.id, String)
        query = query.where(searchable.icontains(q, autoescape=True))
    total = db.scalar(query.with_only_columns(func.count(Flow.id)))
    rows = db.scalars(query.order_by(Flow.timestamp.desc(), Flow.id.desc()).offset((page - 1) * page_size).limit(page_size))
    return {"is_demo": db.get(Settings, 1).demo_mode, "total": total, "page": page, "items": [FlowSchema.model_validate(f).model_dump() for f in rows]}



@app.get("/api/flows/{flow_id}", response_model=FlowSchema)
def flow_detail(flow_id: int, db: Session = Depends(get_db)):
    row = db.get(Flow, flow_id)
    if not row or row.is_demo != db.get(Settings, 1).demo_mode:
        raise HTTPException(404, "Flow not found in the current data mode")
    return row
