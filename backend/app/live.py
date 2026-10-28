"""One local AsyncSniffer session, bounded intake and a dedicated SQLite worker."""
import asyncio
from collections import Counter, deque
from copy import deepcopy
import json
import logging
import queue
import sys
import threading
import time

from scapy.all import AsyncSniffer, conf
from sqlalchemy import select

from .database import SessionLocal
from .detection import predict
from .dissection import frame_snapshot, decode_snapshot
from .inspection_store import InspectionWriter, RAW_QUEUE_LIMIT
from .events import broadcast
from .models import Capture, Flow, FlowData, LiveSession, Settings
from .storage import apply_prediction, packet_record, save_flow, serialize_flow
from .traffic import FlowStats, MAX_FLOWS, extract_packet, iso, packet_key

log = logging.getLogger(__name__)


def interfaces():
    try:
        conf.ifaces.reload()
        if sys.platform == "win32" and not conf.use_pcap:
            return {"available": False, "interfaces": [], "error": "Npcap is required. Install Npcap, then restart the backend. Administrator permission may be required."}
        rows = []
        for iface in conf.ifaces.values():
            if iface.is_valid():
                rows.append({"id": iface.network_name, "name": iface.description or iface.name, "addresses": [address for group in iface.ips.values() for address in group]})
        return {"available": bool(rows), "interfaces": rows, "error": "" if rows else "No capture interfaces found. Check Npcap and network adapter permissions."}
    except Exception as exc:
        return {"available": False, "interfaces": [], "error": f"Could not enumerate interfaces: {exc}"}


class LiveCapture:
    def __init__(self, factory, sniffer_factory=AsyncSniffer, queue_size=4096):
        self.factory, self.sniffer_factory = factory, sniffer_factory
        self.queue = queue.Queue(maxsize=queue_size)
        self.lock = threading.Lock()
        self.control = asyncio.Lock()
        self.stop_event, self.ready = threading.Event(), threading.Event()
        self.thread = self.sniffer = self.publisher = None
        self.accepting = False
        self.state = self._empty()

    @staticmethod
    def _empty():
        return {"source": "live", "status": "stopped", "capture_id": None, "interface_id": None,
                "interface_name": "", "started_at": None, "stopped_at": None, "error": "",
                "received_packets": 0, "unsupported_packets": 0, "malformed_packets": 0,
                "dropped_packets": 0, "capacity_dropped_packets": 0, "persistence_dropped_packets": 0,
                "processed_packets": 0, "bytes": 0, "active_flows": 0, "completed_flows": 0,
                "inspection_count": 0, "inspection_raw_bytes": 0, "inspection_queue_bytes": 0, "inspector_latest_id": 0, "inspection_errors": 0,
                "packets_per_second": 0, "bits_per_second": 0, "protocols": [],
                "model_status": "unavailable", "model_error": "", "inference_errors": 0,
                # shortcut: AsyncSniffer has no portable driver-drop counter; add pcap_stats when driver telemetry is required.
                "driver_dropped_packets": None, "recent_packets": [], "recent_flows": [], "alerts": []}

    def snapshot(self):
        with self.lock:
            return {**deepcopy(self.state), "queue_depth": self.queue.qsize(), "queue_capacity": self.queue.maxsize}

    @property
    def busy(self):
        driver_thread = getattr(self.sniffer, "thread", None)
        return bool((self.thread and self.thread.is_alive()) or (driver_thread and driver_thread.is_alive()) or (self.sniffer and self.sniffer.running))

    def enqueue(self, raw):
        # Runs on the sniffer thread; never schedule one event-loop callback per packet.
        with self.lock:
            if not self.accepting:
                return
            self.state["received_packets"] += 1
        try:
            packet = extract_packet(raw)
        except Exception:
            with self.lock:
                self.state["malformed_packets"] += 1
            packet = None
        try:
            frame = frame_snapshot(raw)
        except Exception:
            frame = None
            with self.lock:
                self.state["inspection_errors"] += 1
        with self.lock:
            if packet is None:
                self.state["unsupported_packets"] += 1
                if frame is None:
                    return
                packet = {"_inspection_only": True, "timestamp": frame['timestamp']}
            if frame is not None:
                if self.state["inspection_queue_bytes"] + len(frame["raw_data"]) > RAW_QUEUE_LIMIT:
                    frame.update(raw_data=b'', raw_status='queue_limit')
                packet["_frame"] = frame
            if self.accepting:
                try:
                    self.queue.put_nowait(packet)
                    self.state["inspection_queue_bytes"] += len(frame["raw_data"]) if frame else 0
                except queue.Full:
                    self.state["dropped_packets"] += 1
            else:
                self.state["dropped_packets"] += 1

    def _check_mode(self):
        with self.factory() as db:
            if db.get(Settings, 1).demo_mode:
                raise RuntimeError("Turn off sample mode in Settings before using live monitoring")

    async def start(self, interface):
        async with self.control:
            if self.busy:
                raise RuntimeError("A live capture is already running or stopping")
            if self.publisher:
                await self.publisher
            await asyncio.to_thread(self._check_mode)
            with self.lock:
                self.state = {**self._empty(), "status": "starting", "interface_id": interface["id"],
                              "interface_name": interface["name"], "started_at": iso(time.time())}
            self.queue = queue.Queue(maxsize=self.queue.maxsize)
            self.sniffer = None
            self.stop_event.clear()
            self.ready.clear()
            self.thread = threading.Thread(target=self._run, name="flowtwin-live", daemon=True)
            self.thread.start()
            self.publisher = asyncio.create_task(self._publish())
            if not await asyncio.to_thread(self.ready.wait, 7):
                self.stop_event.set()
                raise RuntimeError("Capture startup timed out; stopping the session")
            state = self.snapshot()
            if state["status"] == "error":
                raise RuntimeError(state["error"])
            return state

    async def stop(self):
        async with self.control:
            if self.thread and self.thread.is_alive():
                with self.lock:
                    if self.state["status"] != "error":
                        self.state["status"] = "stopping"
                    self.accepting = False
                self.stop_event.set()
            return self.snapshot()

    async def close(self):
        await self.stop()
        if self.thread:
            await asyncio.to_thread(self.thread.join)
        if self.publisher:
            await self.publisher

    async def _publish(self):
        last_inspection = 0
        while True:
            finished = not self.thread.is_alive()
            snapshot = self.snapshot()
            await broadcast({"type": "live_snapshot", "source": "live", "live": snapshot})
            if snapshot["inspection_count"] != last_inspection:
                last_inspection = snapshot["inspection_count"]
                await broadcast({"type": "packet_updates", "source": "live", "capture_id": snapshot["capture_id"], "inspection_count": last_inspection, "latest_id": snapshot["inspector_latest_id"]})
            if finished:
                break
            await asyncio.sleep(0.5)

    def _halt_sniffer(self):
        with self.lock:
            self.accepting = False
        if self.sniffer:
            thread = getattr(self.sniffer, "thread", None)
            if thread and not thread.is_alive():
                self.sniffer.running = False
                return
            if self.sniffer.running:
                self.sniffer.stop(join=False)
            self.sniffer.join(timeout=3)
            if thread and thread.is_alive():
                raise RuntimeError("Capture driver did not stop; restart the backend before capturing again")

    def _run(self):
        active, dirty = {}, {}
        recent_packets, recent_flows, alerts = deque(maxlen=15), deque(maxlen=50), deque(maxlen=20)
        protocols = Counter()
        processed = total_bytes = completed = created = 0
        capture_id = None
        pending = 0
        last_sample, last_packets, last_bytes = time.monotonic(), 0, 0
        try:
            with self.factory() as db:
                state = self.snapshot()
                capture_row = Capture(filename=f"Live: {state['interface_name']}", imported_at=state["started_at"], packet_count=0, flow_count=0, source="live")
                db.add(capture_row)
                db.flush()
                capture_id = capture_row.id
                session = LiveSession(capture_id=capture_id, interface_id=state["interface_id"], interface_name=state["interface_name"], started_at=state["started_at"], status="starting")
                db.add(session)
                inspector = InspectionWriter(db, capture_id)
                db.commit()
                with self.lock:
                    self.state["capture_id"] = capture_id
                    self.accepting = True
                opened = threading.Event()
                self.sniffer = self.sniffer_factory(iface=state["interface_id"], store=False, promisc=False,
                                                    prn=self.enqueue, started_callback=opened.set)
                self.sniffer.start()
                deadline = time.monotonic() + 5
                while not opened.wait(0.05):
                    driver_thread = getattr(self.sniffer, "thread", None)
                    if getattr(self.sniffer, "exception", None) or (driver_thread and not driver_thread.is_alive()) or time.monotonic() >= deadline:
                        raise RuntimeError(str(getattr(self.sniffer, "exception", None) or "Npcap/interface could not be opened within 5 seconds"))
                if not self.sniffer.running:
                    raise RuntimeError(str(getattr(self.sniffer, "exception", None) or "Capture driver stopped during startup"))
                with self.lock:
                    self.state["status"] = "running"
                self.ready.set()
                halted = False
                while True:
                    stopping = self.stop_event.is_set()
                    if stopping and not halted:
                        self._halt_sniffer()
                        halted = True
                    if not stopping and not self.sniffer.running:
                        raise RuntimeError(str(getattr(self.sniffer, "exception", None) or "Capture interface stopped unexpectedly"))
                    batch = []
                    try:
                        batch.append(self.queue.get(timeout=0.1))
                    except queue.Empty:
                        pass
                    while len(batch) < 256:
                        try:
                            batch.append(self.queue.get_nowait())
                        except queue.Empty:
                            break
                    pending = len(batch)
                    for packet in batch:
                        snapshot = packet.pop('_frame', None)
                        if snapshot:
                            with self.lock:
                                self.state['inspection_queue_bytes'] -= len(snapshot['raw_data'])
                        frame = decode_snapshot(snapshot) if snapshot else None
                        if packet.pop('_inspection_only', False):
                            if frame:
                                inspector.write(db, frame)
                            continue
                        key = packet_key(packet)
                        entry = active.get(key)
                        if entry:
                            reason = entry[0].expiration(packet["timestamp"])
                            if reason:
                                dirty[entry[1]] = (entry[0], reason)
                                del active[key]
                                entry = None
                        if entry is None:
                            if len(active) >= MAX_FLOWS:
                                with self.lock:
                                    self.state["dropped_packets"] += 1
                                    self.state["capacity_dropped_packets"] += 1
                                pending -= 1
                                if frame:
                                    inspector.write(db, frame)
                                continue
                            stats = FlowStats(packet)
                            stats.add(packet)
                            row = save_flow(db, capture_id, {**stats.summary(), "complete": False})
                            entry = (stats, row.id)
                            active[key] = entry
                            created += 1
                        else:
                            entry[0].add(packet)
                        dirty[entry[1]] = (entry[0], None)
                        db.add(packet_record(capture_id, entry[1], packet))
                        if frame:
                            inspector.write(db, frame, entry[1], packet['direction'])
                        processed += 1
                        total_bytes += packet["size"]
                        protocols[packet["protocol"]] += 1
                        recent_packets.appendleft({**packet, "timestamp": iso(packet["timestamp"]), "flow_id": entry[1], "capture_id": capture_id})
                    # Packet time advances expiration even under backlog; wall time is safe only when drained.
                    drained = self.queue.empty()
                    watermark = time.time() if drained else batch[-1]["timestamp"] if batch else None
                    for key, (stats, flow_id) in list(active.items()):
                        reason = "stopped" if stopping and drained else stats.expiration(watermark) if watermark is not None else None
                        if reason:
                            dirty[flow_id] = (stats, reason)
                            del active[key]
                            if sum(reason is not None for _, reason in dirty.values()) >= 64:
                                break
                    for flow_id, (stats, reason) in dirty.items():
                        flow, detail = db.get(Flow, flow_id), db.get(FlowData, flow_id)
                        summary = {**stats.summary(), "complete": reason is not None, "completion_reason": reason}
                        for key in ("packets", "bytes", "duration_ms"):
                            setattr(flow, key, summary[key])
                        detail.features_json = json.dumps(summary)
                        if reason:
                            try:
                                result = predict(summary["features"])
                                with self.lock:
                                    self.state["model_status"] = "trained" if result else "unavailable"
                                    self.state["model_error"] = ""
                            except Exception as exc:
                                result = None
                                with self.lock:
                                    self.state["model_status"] = "error"
                                    self.state["model_error"] = str(exc)
                                    self.state["inference_errors"] += 1
                            alert = apply_prediction(db, flow, detail, result)
                            completed += 1
                            if alert:
                                alerts.appendleft({"id": alert.id, "flow_id": flow_id, "category": result["category"], "confidence": result["confidence"], "severity": result["severity"], "source": flow.source, "destination": flow.destination, "timestamp": iso(time.time())})
                        recent_flows = deque((r for r in recent_flows if r["id"] != flow_id), maxlen=50)
                        recent_flows.appendleft({**serialize_flow(flow), "complete": reason is not None})
                    dirty.clear()
                    finished = stopping and self.queue.empty() and not active
                    elapsed = time.monotonic() - last_sample
                    update = dict(processed_packets=processed, bytes=total_bytes, completed_flows=completed, active_flows=len(active),
                                  protocols=[{"name": k, "value": v} for k, v in protocols.items()], recent_packets=list(recent_packets), recent_flows=list(recent_flows), alerts=list(alerts),
                                  inspection_count=inspector.state.packet_count, inspection_raw_bytes=inspector.state.raw_bytes_retained, inspector_latest_id=inspector.latest_id)
                    if elapsed >= 0.5:
                        update.update(packets_per_second=round((processed - last_packets) / elapsed, 1), bits_per_second=round((total_bytes - last_bytes) * 8 / elapsed))
                        last_sample, last_packets, last_bytes = time.monotonic(), processed, total_bytes
                    if finished:
                        update.update(status="stopped", stopped_at=iso(time.time()), packets_per_second=0, bits_per_second=0)
                    capture_row = db.get(Capture, capture_id)
                    capture_row.packet_count, capture_row.flow_count = processed, created
                    self._save_session(db, capture_id, {**self.snapshot(), **update})
                    db.commit()
                    # Publish only committed data; Stop must not claim success before the final commit.
                    with self.lock:
                        self.state.update(update)
                    pending = 0
                    if finished:
                        break
        except Exception as exc:
            log.exception("Live capture failed")
            with self.lock:
                self.accepting = False
                self.state.update(status="error", error=f"Live capture failed: {exc}. Check Npcap, interface access and local storage.", stopped_at=iso(time.time()), packets_per_second=0, bits_per_second=0, active_flows=0)
                lost = pending + self.queue.qsize()
                self.state["persistence_dropped_packets"] += lost
                self.state["dropped_packets"] += lost
            self.stop_event.set()
            try:
                self._halt_sniffer()
            except Exception:
                log.exception("Capture driver cleanup failed")
            if capture_id:
                try:
                    with self.factory() as db:
                        persisted = db.get(Capture, capture_id)
                        with self.lock:
                            self.state["processed_packets"] = persisted.packet_count
                        self._save_session(db, capture_id)
                        db.commit()
                except Exception:
                    log.exception("Could not persist live-session failure")
        finally:
            with self.lock:
                self.accepting = False
            self.ready.set()

    def _save_session(self, db, capture_id, state=None):
        state = state or self.snapshot()
        row = db.get(LiveSession, capture_id)
        row.status, row.stopped_at, row.error = state["status"], state["stopped_at"], state["error"]
        row.counters_json = json.dumps({k: v for k, v in state.items() if k not in {"recent_packets", "recent_flows", "alerts"}})


def recover_sessions(db):
    for row in db.scalars(select(LiveSession).where(LiveSession.status.in_(["starting", "running", "stopping"]))):
        row.status, row.stopped_at = "interrupted", iso(time.time())
        row.error = "Backend restarted before this session stopped. Persisted partial flows remain unanalyzed."
    db.commit()


capture = LiveCapture(SessionLocal)
