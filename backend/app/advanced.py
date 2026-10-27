"""PCAP ingestion, replay, detections, alerts and downloadable reports."""
import asyncio
import csv
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import SessionLocal, get_db
from .detection import load_model, model_metrics, predict
from .models import Alert, Capture, Detection, Flow, FlowData, PacketRecord, Settings
from .traffic import analyze_pcap, iso

router = APIRouter(prefix="/api")
UPLOAD_DIR = Path(__file__).resolve().parents[2] / "uploads"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
clients: set[WebSocket] = set()
replay_state = {"active": False, "capture_id": None, "processed": 0, "total": 0}
replay_task = None


def active_real(db):
    if db.get(Settings, 1).demo_mode:
        raise HTTPException(409, "Turn off sample mode in Settings to work with imported traffic")


def serialize_flow(flow):
    return {column.name: getattr(flow, column.name) for column in Flow.__table__.columns}


@router.post("/captures", status_code=201)
async def import_pcap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    active_real(db)
    filename = Path(file.filename or "capture.pcap").name
    if Path(filename).suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(400, "Upload a .pcap, .pcapng, or .cap file")
    UPLOAD_DIR.mkdir(exist_ok=True)
    target = UPLOAD_DIR / f"{uuid.uuid4().hex}{Path(filename).suffix.lower()}"
    size = 0
    try:
        with target.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "Capture exceeds the 25 MB upload limit")
                out.write(chunk)
        with target.open("rb") as uploaded:
            magic = uploaded.read(4)
        if size < 24 or magic not in MAGIC:
            raise HTTPException(400, "File is not a recognized PCAP or PCAPNG capture")
        try:
            analysis = analyze_pcap(target)
        except (ValueError, OSError, EOFError, RuntimeError) as exc:
            raise HTTPException(400, f"Capture could not be processed: {exc}") from exc
        if not analysis["flows"]:
            raise HTTPException(400, "Capture contains no supported IPv4/IPv6 TCP, UDP or ICMP packets")
        capture = Capture(filename=filename, imported_at=datetime.now(timezone.utc).isoformat(), packet_count=analysis["packet_count"], flow_count=len(analysis["flows"]), source="pcap")
        db.add(capture)
        db.flush()
        detected = 0
        for row in analysis["flows"]:
            result = predict(row["features"])
            classification = "unanalyzed" if result is None else "benign" if result["category"] == "Benign" else "malicious" if result["severity"] == "High" else "suspicious"
            flow = Flow(timestamp=row["timestamp"], source=row["source"], destination=row["destination"], source_port=row["source_port"], destination_port=row["destination_port"], protocol=row["protocol"], packets=row["packets"], bytes=row["bytes"], duration_ms=row["duration_ms"], classification=classification, category=result["category"] if result else "Not classified", is_demo=False)
            db.add(flow)
            db.flush()
            detail = {key: value for key, value in row.items() if key != "records"}
            db.add(FlowData(flow_id=flow.id, capture_id=capture.id, features_json=json.dumps(detail), explanation_json=json.dumps(result["explanation"] if result else [])))
            for p in row["records"]:
                db.add(PacketRecord(capture_id=capture.id, flow_id=flow.id, timestamp=iso(p["timestamp"]), source=p["source"], destination=p["destination"], source_port=p["source_port"], destination_port=p["destination_port"], protocol=p["protocol"], size=p["size"], flags=p["flags"], direction=p["direction"]))
            if result:
                detected += 1
                detection = Detection(flow_id=flow.id, timestamp=datetime.now(timezone.utc).isoformat(), category=result["category"], confidence=result["confidence"], severity=result["severity"], model_version=result["model_version"], explanation_json=json.dumps(result["explanation"]))
                db.add(detection)
                db.flush()
                if result["category"] != "Benign":
                    db.add(Alert(detection_id=detection.id, status="New"))
        db.commit()
        await broadcast({"type": "capture_imported", "capture_id": capture.id, "packet_count": capture.packet_count, "flow_count": capture.flow_count})
        return {"id": capture.id, "filename": filename, "packet_count": capture.packet_count, "flow_count": capture.flow_count, "detected_flow_count": detected, "model_status": "trained" if detected else "unavailable", "source": "pcap"}
    except Exception:
        db.rollback()
        target.unlink(missing_ok=True)
        raise
    finally:
        await file.close()


@router.get("/captures")
def list_captures(db: Session = Depends(get_db)):
    active_real(db)
    return [{column.name: getattr(capture, column.name) for column in Capture.__table__.columns} for capture in db.scalars(select(Capture).order_by(Capture.id.desc()).limit(50))]


@router.post("/captures/{capture_id}/analyze")
async def analyze_existing_capture(capture_id: int, db: Session = Depends(get_db)):
    active_real(db)
    if load_model() is None:
        raise HTTPException(409, "Train a model before analyzing this capture")
    capture = db.get(Capture, capture_id)
    if not capture:
        raise HTTPException(404, "Capture not found")
    details = list(db.scalars(select(FlowData).where(FlowData.capture_id == capture_id)))
    classified = 0
    for detail in details:
        flow = db.get(Flow, detail.flow_id)
        result = predict(json.loads(detail.features_json)["features"])
        flow.classification = "benign" if result["category"] == "Benign" else "malicious" if result["severity"] == "High" else "suspicious"
        flow.category = result["category"]
        detail.explanation_json = json.dumps(result["explanation"])
        detection = db.scalar(select(Detection).where(Detection.flow_id == flow.id))
        if detection is None:
            detection = Detection(flow_id=flow.id, timestamp=datetime.now(timezone.utc).isoformat(), category=result["category"], confidence=result["confidence"], severity=result["severity"], model_version=result["model_version"], explanation_json=json.dumps(result["explanation"]))
            db.add(detection)
            db.flush()
        else:
            detection.timestamp = datetime.now(timezone.utc).isoformat()
            detection.category = result["category"]
            detection.confidence = result["confidence"]
            detection.severity = result["severity"]
            detection.model_version = result["model_version"]
            detection.explanation_json = json.dumps(result["explanation"])
        alert = db.scalar(select(Alert).where(Alert.detection_id == detection.id))
        if result["category"] != "Benign" and alert is None:
            db.add(Alert(detection_id=detection.id, status="New"))
        if result["category"] == "Benign" and alert is not None:
            db.delete(alert)
        classified += 1
    db.commit()
    await broadcast({"type": "analysis_completed", "capture_id": capture_id, "classified_flow_count": classified})
    return {"capture_id": capture_id, "classified_flow_count": classified, "model_status": "trained"}


@router.get("/captures/{capture_id}/packets")
def packets(capture_id: int, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100), q: str = Query("", max_length=100), db: Session = Depends(get_db)):
    active_real(db)
    if not db.get(Capture, capture_id):
        raise HTTPException(404, "Capture not found")
    rows = list(db.scalars(select(PacketRecord).where(PacketRecord.capture_id == capture_id).order_by(PacketRecord.timestamp)))
    if q:
        rows = [r for r in rows if q.lower() in f"{r.source} {r.destination} {r.protocol} {r.flags}".lower()]
    start = (page - 1) * page_size
    return {"total": len(rows), "page": page, "items": [{column.name: getattr(r, column.name) for column in PacketRecord.__table__.columns} for r in rows[start:start + page_size]]}


@router.get("/flows/{flow_id}/analysis")
def flow_analysis(flow_id: int, db: Session = Depends(get_db)):
    active_real(db)
    flow = db.get(Flow, flow_id)
    detail = db.get(FlowData, flow_id)
    if not flow or flow.is_demo or not detail:
        raise HTTPException(404, "Imported flow not found")
    detection = db.scalar(select(Detection).where(Detection.flow_id == flow_id))
    return {"flow": serialize_flow(flow), "capture_id": detail.capture_id, "statistics": json.loads(detail.features_json), "detection": None if not detection else {"category": detection.category, "confidence": detection.confidence, "severity": detection.severity, "model_version": detection.model_version, "timestamp": detection.timestamp, "explanation": json.loads(detection.explanation_json)}}


@router.get("/model")
def model_status():
    metrics = model_metrics()
    return {"status": "trained" if metrics else "unavailable", "metrics": metrics}


@router.get("/analytics/packet-sizes")
def packet_sizes(db: Session = Depends(get_db)):
    active_real(db)
    buckets = [("0–63 B", 0, 63), ("64–127 B", 64, 127), ("128–255 B", 128, 255), ("256–511 B", 256, 511), ("512–1023 B", 512, 1023), ("1024+ B", 1024, float("inf"))]
    counts = [0] * len(buckets)
    for size in db.scalars(select(PacketRecord.size)):
        for index, (_, minimum, maximum) in enumerate(buckets):
            if minimum <= size <= maximum:
                counts[index] += 1
                break
    return [{"name": name, "value": counts[index]} for index, (name, _, _) in enumerate(buckets)]


@router.get("/detections")
def detections(db: Session = Depends(get_db)):
    active_real(db)
    rows = db.execute(select(Detection, Flow).join(Flow, Detection.flow_id == Flow.id).order_by(Detection.id.desc()).limit(100)).all()
    return [{"id": d.id, "flow": serialize_flow(f), "timestamp": d.timestamp, "category": d.category, "confidence": d.confidence, "severity": d.severity, "model_version": d.model_version, "explanation": json.loads(d.explanation_json)} for d, f in rows]


@router.get("/alerts")
def alerts(db: Session = Depends(get_db)):
    active_real(db)
    rows = db.execute(select(Alert, Detection, Flow).join(Detection, Alert.detection_id == Detection.id).join(Flow, Detection.flow_id == Flow.id).order_by(Alert.id.desc()).limit(200)).all()
    return [{"id": a.id, "status": a.status, "timestamp": d.timestamp, "source": f.source, "destination": f.destination, "flow_id": f.id, "category": d.category, "confidence": d.confidence, "severity": d.severity, "explanation": json.loads(d.explanation_json)} for a, d, f in rows]


class AlertUpdate(BaseModel):
    status: Literal["New", "Investigating", "Resolved"]


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)):
    active_real(db)
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = payload.status
    db.commit()
    return {"id": alert.id, "status": alert.status}


@router.get("/reports/{kind}")
def export_report(kind: Literal["csv", "pdf"], db: Session = Depends(get_db)):
    demo = db.get(Settings, 1).demo_mode
    rows = list(db.scalars(select(Flow).where(Flow.is_demo == demo).order_by(Flow.timestamp.desc()).limit(5000)))
    source = "SAMPLE FIXTURE - NOT REAL DETECTIONS" if demo else "IMPORTED PCAP DATA"
    if kind == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["data_source", "flow_id", "timestamp_utc", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "packets", "bytes", "duration_ms", "classification", "category"])
        for f in rows:
            writer.writerow([source, f.id, f.timestamp, f.source, f.source_port, f.destination, f.destination_port, f.protocol, f.packets, f.bytes, f.duration_ms, f.classification, f.category])
        data = output.getvalue().encode("utf-8-sig")
        return StreamingResponse(io.BytesIO(data), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="flowtwin-flows.csv"'})
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    items = [Paragraph("FlowTwin — Security Summary", styles["Title"]), Spacer(1, 10), Paragraph(source, styles["Heading2"]), Paragraph(f"Generated {datetime.now(timezone.utc).isoformat()} · {len(rows)} flows", styles["Normal"]), Spacer(1, 14)]
    counts = {label: sum(f.classification == label for f in rows) for label in ("benign", "suspicious", "malicious", "unanalyzed")}
    items.append(Paragraph("Traffic classification", styles["Heading2"]))
    summary = Table([["Benign", "Suspicious", "Malicious", "Unanalyzed"], [counts[k] for k in ("benign", "suspicious", "malicious", "unanalyzed")]], colWidths=[110] * 4)
    summary.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163149")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("PADDING", (0, 0), (-1, -1), 7)]))
    items.extend([summary, Spacer(1, 14), Paragraph("Recent flows", styles["Heading2"])])
    table_rows = [["Time (UTC)", "Source", "Destination", "Protocol", "Category"]]
    for f in rows[:25]:
        table_rows.append([f.timestamp[:16], f.source[:20], f.destination[:20], f.protocol, f.category[:18]])
    report = Table(table_rows, repeatRows=1, colWidths=[95, 105, 105, 55, 90])
    report.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#163149")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]), ("FONTSIZE", (0, 0), (-1, -1), 7), ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("PADDING", (0, 0), (-1, -1), 5)]))
    items.append(report)
    items.extend([Spacer(1, 12), Paragraph("Review flagged connections, verify against packet details, and apply appropriate network controls. Classifier output is probabilistic and requires analyst validation.", styles["Normal"])])
    doc.build(items)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": 'attachment; filename="flowtwin-report.pdf"'})


async def broadcast(message):
    for client in list(clients):
        try:
            await client.send_json(message)
        except Exception:
            clients.discard(client)


async def run_replay(capture_id):
    global replay_task
    try:
        with SessionLocal() as db:
            rows = db.execute(select(Flow).join(FlowData, Flow.id == FlowData.flow_id).where(FlowData.capture_id == capture_id).order_by(Flow.timestamp)).scalars().all()
            flows = [serialize_flow(f) for f in rows]
            packet_rows = db.execute(select(PacketRecord).where(PacketRecord.capture_id == capture_id).order_by(PacketRecord.timestamp)).scalars().all()
            packets_by_flow = {}
            for packet in packet_rows:
                packets_by_flow.setdefault(packet.flow_id, []).append({"timestamp": packet.timestamp, "source": packet.source, "destination": packet.destination, "protocol": packet.protocol, "size": packet.size, "flags": packet.flags})
        replay_state.update(active=True, capture_id=capture_id, processed=0, total=len(flows))
        await broadcast({"type": "replay_started", "capture_id": capture_id, "total": len(flows)})
        for index, flow in enumerate(flows, 1):
            for packet in packets_by_flow.get(flow["id"], []):
                await broadcast({"type": "packet", "source": "pcap_replay", "capture_id": capture_id, "flow_id": flow["id"], "packet": packet})
            await broadcast({"type": "flow", "source": "pcap_replay", "capture_id": capture_id, "index": index, "total": len(flows), "flow": flow})
            replay_state["processed"] = index
            await asyncio.sleep(0.15)
        await broadcast({"type": "replay_completed", "capture_id": capture_id, "total": len(flows)})
    finally:
        replay_state["active"] = False
        replay_task = None


@router.post("/captures/{capture_id}/replay")
async def start_replay(capture_id: int, db: Session = Depends(get_db)):
    global replay_task
    active_real(db)
    if replay_state["active"] or (replay_task and not replay_task.done()):
        raise HTTPException(409, "A replay is already running")
    capture = db.get(Capture, capture_id)
    if not capture:
        raise HTTPException(404, "Capture not found")
    replay_task = asyncio.create_task(run_replay(capture_id))
    return {"status": "started", "source": "pcap_replay", "capture_id": capture_id, "total": capture.flow_count}


@router.get("/replay")
def get_replay():
    return {**replay_state, "source": "pcap_replay"}


@router.websocket("/ws/monitor")
async def monitor(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    await websocket.send_json({"type": "connected", "source": "pcap_replay", "replay": replay_state.copy()})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.discard(websocket)
