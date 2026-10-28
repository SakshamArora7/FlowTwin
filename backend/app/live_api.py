import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import live
from .database import get_db
from .local_access import require_local
from .models import LiveSession, Settings

router = APIRouter(prefix="/api/live")


def local_only(request: Request):
    require_local(request)


router.dependencies.append(Depends(local_only))


def real_mode(db):
    if db.get(Settings, 1).demo_mode:
        raise HTTPException(409, "Turn off sample mode in Settings before using live monitoring")


class StartCapture(BaseModel):
    interface_id: str = Field(min_length=1, max_length=500)


@router.get("/interfaces")
async def list_interfaces(db: Session = Depends(get_db)):
    await asyncio.to_thread(real_mode, db)
    return await asyncio.to_thread(live.interfaces)


@router.get("")
def status(db: Session = Depends(get_db)):
    real_mode(db)
    return live.capture.snapshot()


@router.post("/start")
async def start(payload: StartCapture, db: Session = Depends(get_db)):
    await asyncio.to_thread(real_mode, db)
    available = await asyncio.to_thread(live.interfaces)
    if not available["available"]:
        raise HTTPException(503, available["error"])
    interface = next((row for row in available["interfaces"] if row["id"] == payload.interface_id), None)
    if interface is None:
        raise HTTPException(400, "Choose an interface from the current interface list")
    if live.capture.busy:
        raise HTTPException(409, "A live capture is already running or stopping")
    try:
        return await live.capture.start(interface)
    except RuntimeError as exc:
        raise HTTPException(409 if "already" in str(exc) or "sample mode" in str(exc) else 503, str(exc)) from exc


@router.post("/stop")
async def stop():
    # Stop remains accessible even if settings changed or startup failed.
    return await live.capture.stop()


@router.get("/sessions")
def sessions(db: Session = Depends(get_db)):
    real_mode(db)
    rows = db.scalars(select(LiveSession).order_by(LiveSession.capture_id.desc()).limit(50))
    return [{**json.loads(r.counters_json), "capture_id": r.capture_id, "source": "live", "interface_id": r.interface_id,
             "interface_name": r.interface_name, "started_at": r.started_at, "stopped_at": r.stopped_at,
             "status": r.status, "error": r.error} for r in rows]
