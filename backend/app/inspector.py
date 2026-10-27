"""Local, capture-scoped packet browsing and on-demand dissection."""
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, func, literal, case
from sqlalchemy.orm import Session

from .database import get_db
from .dissection import dissect
from .inspection_store import RAW_CAPTURE_LIMIT
from .local_access import require_local
from .models import Alert, Capture, Detection, Flow, InspectionCapture, InspectionPacket, PacketBytes, PacketRecord, Settings, TcpStream
from .packet_filters import compile_filter, FilterError
from .storage import serialize_flow
from .traffic import iso


def workspace(request: Request, db: Session = Depends(get_db)):
    require_local(request)
    if db.get(Settings, 1).demo_mode:
        raise HTTPException(409, "Turn off sample mode to inspect captured packets")


router = APIRouter(prefix="/api/inspector", dependencies=[Depends(workspace)])
LEGACY_NOTICE = "Metadata only: original bytes and original capture order were not retained. Numbers follow stored timestamps; reimport the PCAP or start a new live session for byte inspection."
RETENTION_NOTICE = "Original packet bytes are retained locally up to 64 MiB per capture and 65,535 bytes per frame. Payloads may contain sensitive information; missing or truncated bytes are identified explicitly."


def capture_or_404(db, capture_id):
    row = db.get(Capture, capture_id)
    if row is None:
        raise HTTPException(404, "Capture not found")
    return row


def packet_columns(db, capture_id, numbered=True):
    if db.get(InspectionCapture, capture_id) is not None:
        return select(InspectionPacket).where(InspectionPacket.capture_id == capture_id).subquery(), False
    p = PacketRecord
    flags = sum(case((p.flags.contains(flag), mask), else_=0) for flag, mask in [('F', 1), ('S', 2), ('R', 4), ('A', 16)])
    query = select(
        (-p.id).label('id'), p.capture_id, p.flow_id, literal(None).label('stream_id'),
        (func.row_number().over(order_by=(p.timestamp, p.id)) if numbered else literal(0)).label('number'),
        ((func.julianday(p.timestamp) - 2440587.5) * 86400).label('timestamp'),
        p.timestamp.label('timestamp_text'),
        p.source, p.destination, p.source_port, p.destination_port, p.protocol, p.protocol.label('transport'),
        case((p.source.contains(':'), 6), else_=4).label('ip_version'), p.size.label('length'), p.size.label('captured_length'),
        literal(-1).label('linktype'), (p.protocol + ' / historical header metadata').label('summary'), p.direction,
        literal(None).label('tcp_seq'), literal(None).label('tcp_ack'), flags.label('tcp_flags'),
        literal(0).label('payload_offset'), literal(0).label('payload_length'), literal('legacy').label('raw_status'),
    ).where(p.capture_id == capture_id)
    return query.subquery(), True


def summarize(row, first_timestamp):
    item = dict(row)
    original_timestamp = item.pop('timestamp_text', None)
    item['epoch'] = item['timestamp']
    item['time_relative'] = max(0, item['timestamp'] - (item['timestamp'] if first_timestamp is None else first_timestamp))
    item['timestamp'] = original_timestamp or iso(item['epoch'])
    return item


def first_timestamp(db, capture_id, legacy):
    if legacy:
        stamp = db.scalar(select(func.min(PacketRecord.timestamp)).where(PacketRecord.capture_id == capture_id))
        return datetime.fromisoformat(stamp).timestamp() if stamp else None
    return db.scalar(select(func.min(InspectionPacket.timestamp)).where(InspectionPacket.capture_id == capture_id))


@router.get('/captures')
def captures(db: Session = Depends(get_db)):
    rows = db.execute(select(Capture, InspectionCapture).outerjoin(InspectionCapture, Capture.id == InspectionCapture.capture_id).order_by(Capture.id.desc()).limit(50))
    return [{'id': c.id, 'filename': c.filename, 'source': c.source, 'packet_count': c.packet_count,
             'inspection_count': state.packet_count if state else c.packet_count,
             'raw_bytes_retained': state.raw_bytes_retained if state else 0,
             'legacy': state is None, 'notice': LEGACY_NOTICE if state is None else RETENTION_NOTICE} for c, state in rows]


@router.get('/packets')
def packets(capture_id: int = Query(..., ge=1), filter: str = Query('', max_length=1024),
            sort: Literal['number', 'timestamp', 'source', 'destination', 'protocol', 'length'] = 'number',
            order: Literal['asc', 'desc'] = 'asc', page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=100),
            flow_id: int | None = Query(None, ge=1), stream_id: int | None = Query(None, ge=1), db: Session = Depends(get_db)):
    capture_or_404(db, capture_id)
    query, legacy = packet_columns(db, capture_id)
    c = query.c
    first = first_timestamp(db, capture_id, legacy)
    try:
        condition = compile_filter(filter, c, relative_time=c.timestamp - (first or 0))
    except FilterError as exc:
        raise HTTPException(422, str(exc)) from exc
    conditions = [condition]
    if flow_id is not None: conditions.append(c.flow_id == flow_id)
    if stream_id is not None: conditions.append(c.stream_id == stream_id)
    count_query = query
    count_conditions = conditions
    if legacy and 'frame.number' not in filter.lower():
        count_query, _ = packet_columns(db, capture_id, numbered=False)
        cc = count_query.c
        count_conditions = [compile_filter(filter, cc, relative_time=cc.timestamp - (first or 0))]
        if flow_id is not None: count_conditions.append(cc.flow_id == flow_id)
        if stream_id is not None: count_conditions.append(cc.stream_id == stream_id)
    total = db.scalar(select(func.count()).select_from(count_query).where(*count_conditions))
    ordered = c[sort].asc() if order == 'asc' else c[sort].desc()
    rows = db.execute(select(query).where(*conditions).order_by(ordered, c.id.asc()).offset((page - 1) * page_size).limit(page_size)).mappings()
    latest = db.scalar(select(func.max(PacketRecord.id)).where(PacketRecord.capture_id == capture_id)) if legacy else db.scalar(select(func.max(c.id)))
    if legacy and latest is not None:
        latest = -latest
    return {'capture_id': capture_id, 'items': [summarize(row, first) for row in rows], 'total': total, 'page': page, 'page_size': page_size,
            'legacy': legacy, 'notice': LEGACY_NOTICE if legacy else RETENTION_NOTICE,
            'latest_id': latest,
            'raw_limit_bytes': RAW_CAPTURE_LIMIT}


@router.get('/packets/{packet_id}')
def detail(packet_id: int, db: Session = Depends(get_db)):
    if packet_id == 0:
        raise HTTPException(404, 'Packet not found')
    model = InspectionPacket if packet_id > 0 else PacketRecord
    stored = db.get(model, abs(packet_id))
    if stored is None:
        raise HTTPException(404, 'Packet not found')
    query, legacy = packet_columns(db, stored.capture_id)
    row = db.execute(select(query).where(query.c.id == packet_id)).mappings().first()
    if row is None:
        raise HTTPException(404, 'Packet not found in this capture')
    packet = summarize(row, first_timestamp(db, stored.capture_id, legacy))
    raw = db.get(PacketBytes, packet_id) if packet_id > 0 else None
    decoded = dissect(raw.data, row['linktype']) if raw else {'layers': [], 'warnings': [LEGACY_NOTICE if legacy else f"Original bytes unavailable ({row['raw_status']})"]}
    if raw and row['raw_status'] != 'available':
        decoded['warnings'].append(f"Retained bytes are incomplete ({row['raw_status']}); no missing bytes have been synthesized")
    flow = db.get(Flow, row['flow_id']) if row['flow_id'] else None
    detection = db.scalar(select(Detection).where(Detection.flow_id == row['flow_id'])) if flow else None
    alerts = list(db.scalars(select(Alert).where(Alert.detection_id == detection.id))) if detection else []
    return {'packet': packet, 'hex': raw.data.hex() if raw else '', **decoded, 'flow': serialize_flow(flow) if flow else None,
            'detection': {'category': detection.category, 'confidence': detection.confidence, 'severity': detection.severity} if detection else None,
            'alerts': [{'id': alert.id, 'status': alert.status} for alert in alerts]}


@router.get('/streams/{stream_id}')
def stream(stream_id: int, db: Session = Depends(get_db)):
    row = db.get(TcpStream, stream_id)
    if row is None:
        raise HTTPException(404, 'TCP conversation not found; historical metadata has no original TCP stream')
    from .tcp_follow import follow_stream
    return follow_stream(db, row)
