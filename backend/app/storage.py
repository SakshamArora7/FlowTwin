"""Shared flow, prediction and structured-header persistence."""
import json
from datetime import datetime, timezone

from sqlalchemy import select

from .models import Alert, Detection, Flow, FlowData, PacketRecord
from .schemas import FlowSchema
from .traffic import iso


def serialize_flow(flow):
    return FlowSchema.model_validate(flow).model_dump()


def apply_prediction(db, flow, detail, result):
    flow.classification = "unanalyzed" if result is None else "benign" if result["category"] == "Benign" else "malicious" if result["severity"] == "High" else "suspicious"
    flow.category = result["category"] if result else "Not classified"
    detail.explanation_json = json.dumps(result["explanation"] if result else [])
    if result is None:
        return None
    detection = db.scalar(select(Detection).where(Detection.flow_id == flow.id))
    if detection is None:
        detection = Detection(flow_id=flow.id)
        db.add(detection)
    for key in ("category", "confidence", "severity", "model_version"):
        setattr(detection, key, result[key])
    detection.timestamp = datetime.now(timezone.utc).isoformat()
    detection.explanation_json = detail.explanation_json
    db.flush()
    alert = db.scalar(select(Alert).where(Alert.detection_id == detection.id))
    if result["category"] != "Benign" and alert is None:
        alert = Alert(detection_id=detection.id, status="New")
        db.add(alert)
        db.flush()
    elif result["category"] == "Benign" and alert is not None:
        db.delete(alert)
        alert = None
    return alert


def save_flow(db, capture_id, row, result=None):
    fields = ("timestamp", "source", "destination", "source_port", "destination_port", "protocol", "packets", "bytes", "duration_ms")
    flow = Flow(**{k: row[k] for k in fields}, classification="unanalyzed", category="Not classified", is_demo=False)
    db.add(flow)
    db.flush()
    detail = FlowData(flow_id=flow.id, capture_id=capture_id, features_json=json.dumps({k: v for k, v in row.items() if k != "records"}), explanation_json="[]")
    db.add(detail)
    apply_prediction(db, flow, detail, result)
    return flow


def packet_record(capture_id, flow_id, packet):
    keys = ("source", "destination", "source_port", "destination_port", "protocol", "size", "flags", "direction")
    return PacketRecord(capture_id=capture_id, flow_id=flow_id, timestamp=iso(packet["timestamp"]), **{k: packet[k] for k in keys})
