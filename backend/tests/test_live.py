import asyncio
import json
import time

import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
from sqlalchemy import select

from backend.app.traffic import FlowStats, analyze_pcap, extract_packet


def packets():
    rows = [
        Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=443, flags="S"),
        Ether()/IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=443, dport=1234, flags="SA"),
        Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=443, flags="FA")/Raw(load=b"abc"),
    ]
    for index, packet in enumerate(rows):
        packet.time = 1700000000 + index * 0.1
    return rows


def test_incremental_statistics_match_offline_without_retaining_packets(tmp_path):
    raw = packets()
    path = tmp_path / "same.pcap"
    wrpcap(str(path), raw)
    expected = analyze_pcap(path)["flows"][0]
    stats = FlowStats(extract_packet(raw[0]))
    for packet in raw:
        stats.add(extract_packet(packet))
    actual = stats.summary()
    assert actual["features"] == pytest.approx(expected["features"])
    for key in ("packet_size_std", "iat_std_us", "bytes", "forward_bytes", "backward_packets"):
        assert actual[key] == pytest.approx(expected[key])
    assert stats.expiration(stats.last) == "tcp_end"
    assert not hasattr(stats, "packets")


def test_flow_expiration_and_high_volume_memory_bound():
    p = extract_packet(packets()[0])
    stats = FlowStats(p)
    for index in range(10000):
        stats.add({**p, "timestamp": p["timestamp"] + index * 0.001})
    assert stats.summary()["packets"] == 10000
    assert stats.expiration(stats.last + 121) == "inactivity"
    assert stats.expiration(stats.first + 121) == "duration"
    assert len(vars(stats)) < 25


class FakeSniffer:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.running = False
        self.exception = None

    def start(self):
        self.running = True
        self.options["started_callback"]()

    def stop(self, join=False):
        self.running = False

    def join(self, timeout=None):
        pass


def wait_until(predicate):
    deadline = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < deadline, "Worker did not reach expected state"
        time.sleep(0.01)


def make_capture(factory, **options):
    from backend.app import live
    from backend.app.models import Settings
    with factory() as db:
        db.get(Settings, 1).demo_mode = False
        db.commit()
    return live.LiveCapture(factory, **options)


def test_live_worker_persists_headers_finalizes_and_classifies(client, monkeypatch):
    from backend.app import live
    from backend.app.models import Capture, Detection, Flow, FlowData, LiveSession, PacketRecord, Alert
    _, factory = client
    seen = []
    def prediction(features):
        seen.append(features)
        return {"category": "Port scan", "confidence": 0.9, "severity": "High", "model_version": "test", "explanation": []}
    monkeypatch.setattr(live, "predict", prediction)
    controller = make_capture(factory, sniffer_factory=FakeSniffer)
    async def exercise():
        await controller.start({"id": "test-interface", "name": "Test Ethernet"})
        for raw in packets():
            # A real sniffer supplies current wall-clock timestamps.
            raw.time = time.time()
            controller.sniffer.options["prn"](raw)
        await controller.stop()
        await controller.close()
    asyncio.run(exercise())
    state = controller.snapshot()
    assert state["status"] == "stopped" and state["processed_packets"] == 3
    assert state["active_flows"] == 0 and state["completed_flows"] == 1
    assert state["dropped_packets"] == 0 and len(seen) == 1
    assert seen[0]["Total Fwd Packets"] == 2 and seen[0]["Total Backward Packets"] == 1
    assert controller.sniffer.options["store"] is False
    assert controller.sniffer.options["iface"] == "test-interface"
    assert controller.sniffer.options["promisc"] is False
    with factory() as db:
        session = db.get(LiveSession, state["capture_id"])
        assert session.status == "stopped"
        assert db.get(Capture, session.capture_id).source == "live"
        flow = db.scalar(select(Flow).where(Flow.is_demo.is_(False)))
        assert flow.classification == "malicious" and flow.traffic_source == "live"
        detail = json.loads(db.get(FlowData, flow.id).features_json)
        assert detail["complete"] is True
        stored = list(db.scalars(select(PacketRecord)))
        assert len(stored) == 3 and stored[1].direction == "backward"
        assert not hasattr(stored[0], "payload")
        assert len(list(db.scalars(select(Detection)))) == 1
        assert len(list(db.scalars(select(Alert)))) == 1


def test_live_queue_overflow_and_start_failure_are_visible(client):
    from backend.app.live import LiveCapture
    _, factory = client
    controller = make_capture(factory, sniffer_factory=FakeSniffer, queue_size=1)
    controller.accepting = True
    controller.enqueue(packets()[0])
    controller.enqueue(packets()[1])
    assert controller.queue.qsize() == 1
    assert controller.snapshot()["dropped_packets"] == 1
    class FailedSniffer(FakeSniffer):
        def start(self):
            raise PermissionError("Npcap access denied")
    controller = make_capture(factory, sniffer_factory=FailedSniffer)
    async def exercise():
        with pytest.raises(RuntimeError, match="Npcap access denied"):
            await controller.start({"id": "test", "name": "Test"})
        await controller.close()
    asyncio.run(exercise())
    assert controller.snapshot()["status"] == "error"
    assert "Npcap access denied" in controller.snapshot()["error"]


def test_live_api_requires_local_origin_explicit_interface_and_real_mode(client, monkeypatch):
    from backend.app import live
    api, factory = client
    monkeypatch.setattr(live, "capture", live.LiveCapture(factory, sniffer_factory=FakeSniffer))
    monkeypatch.setattr(live, "interfaces", lambda: {"available": True, "error": "", "interfaces": [{"id": "ethernet", "name": "Ethernet", "addresses": []}]})
    assert api.post("/api/live/start", json={"interface_id": "ethernet"}).status_code == 409
    api.put("/api/settings", json={"demo_mode": False, "refresh_seconds": 30})
    assert api.post("/api/live/start", json={}).status_code == 422
    assert api.post("/api/live/start", json={"interface_id": "unknown"}).status_code == 400
    assert api.post("/api/live/start", json={"interface_id": "ethernet"}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert api.get("/api/live/interfaces", headers={"Host": "evil.example"}).status_code == 403
    async def exercise():
        # Keep one event loop alive, as in the real ASGI application.
        await live.capture.start({"id": "ethernet", "name": "Ethernet"})
        with pytest.raises(RuntimeError, match="already"):
            await live.capture.start({"id": "ethernet", "name": "Ethernet"})
        await live.capture.stop()
        await live.capture.close()
    asyncio.run(exercise())
    assert api.get("/api/live/sessions").json()[0]["source"] == "live"


def test_quiet_flow_expires_without_another_packet(client, monkeypatch):
    from backend.app import live, traffic
    monkeypatch.setattr(traffic, "FLOW_TIMEOUT", 0.05)
    monkeypatch.setattr(live, "predict", lambda features: None)
    controller = make_capture(client[1], sniffer_factory=FakeSniffer)
    async def exercise():
        await controller.start({"id": "test", "name": "Test"})
        raw = packets()[0]
        raw.time = time.time()
        controller.enqueue(raw)
        await asyncio.to_thread(wait_until, lambda: controller.snapshot()["completed_flows"] == 1)
        assert controller.snapshot()["active_flows"] == 0
        await controller.close()
    asyncio.run(exercise())


def test_stop_flushes_nonterminated_flow_and_capacity_drops_are_counted(client, monkeypatch):
    from backend.app import live
    from backend.app.models import FlowData
    monkeypatch.setattr(live, "MAX_FLOWS", 1)
    monkeypatch.setattr(live, "predict", lambda features: None)
    controller = make_capture(client[1], sniffer_factory=FakeSniffer)
    async def exercise():
        await controller.start({"id": "test", "name": "Test"})
        for port in (100, 101):
            raw = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=port, dport=53)
            raw.time = time.time()
            controller.enqueue(raw)
        await controller.close()
    asyncio.run(exercise())
    state = controller.snapshot()
    assert state["processed_packets"] == state["capacity_dropped_packets"] == state["dropped_packets"] == 1
    assert state["completed_flows"] == 1
    with client[1]() as db:
        row = db.scalar(select(FlowData))
        assert json.loads(row.features_json)["completion_reason"] == "stopped"


def test_model_failure_keeps_measured_flow_without_fabricating_alert(client, monkeypatch):
    from backend.app import live
    from backend.app.models import Alert, Flow
    def broken(features):
        raise RuntimeError("incompatible artifact")
    monkeypatch.setattr(live, "predict", broken)
    controller = make_capture(client[1], sniffer_factory=FakeSniffer)
    async def exercise():
        await controller.start({"id": "test", "name": "Test"})
        raw = packets()[0]
        raw.time = time.time()
        controller.enqueue(raw)
        await controller.close()
    asyncio.run(exercise())
    state = controller.snapshot()
    assert state["inference_errors"] == 1 and "incompatible artifact" in state["model_error"]
    with client[1]() as db:
        assert db.scalar(select(Flow).where(Flow.is_demo.is_(False))).classification == "unanalyzed"
        assert db.scalar(select(Alert)) is None
    overview = client[0].put("/api/settings", json={"demo_mode": False, "refresh_seconds": 30})
    assert overview.status_code == 200
    overview = client[0].get("/api/overview").json()
    assert overview["unanalyzed"] == 1 and overview["alerts"] == overview["threats"] == []
    assert b"LIVE INTERFACE CAPTURE" in client[0].get("/api/reports/csv").content


def test_driver_failure_and_restart_recovery_are_persisted(client):
    from backend.app import live
    from backend.app.models import LiveSession
    controller = make_capture(client[1], sniffer_factory=FakeSniffer)
    async def exercise():
        await controller.start({"id": "test", "name": "Test"})
        controller.sniffer.exception = OSError("adapter unplugged")
        controller.sniffer.running = False
        await asyncio.to_thread(wait_until, lambda: controller.snapshot()["status"] == "error")
        await controller.close()
    asyncio.run(exercise())
    with client[1]() as db:
        row = db.get(LiveSession, controller.snapshot()["capture_id"])
        assert row.status == "error" and "adapter unplugged" in row.error
        row.status = "running"
        db.commit()
        live.recover_sessions(db)
        assert row.status == "interrupted" and row.stopped_at


def test_local_access_rejects_remote_clients_and_malformed_hosts():
    from types import SimpleNamespace
    from fastapi import HTTPException
    from backend.app.local_access import require_local
    for host, peer in (("localhost:8000", "192.0.2.1"), ("[", "127.0.0.1")):
        with pytest.raises(HTTPException) as error:
            require_local(SimpleNamespace(client=SimpleNamespace(host=peer), headers={"host": host}))
        assert error.value.status_code == 403


def test_websocket_backpressure_is_bounded_and_reports_skipped_updates():
    from backend.app import events
    async def exercise():
        subscription = events.subscribe()
        try:
            for value in range(100):
                await events.broadcast({"type": "live_snapshot", "value": value})
            assert subscription.qsize() == 32
            latest = None
            while not subscription.empty():
                latest = subscription.get_nowait()
            assert latest["value"] == 99 and latest["stream_dropped"] == 68
        finally:
            events.clients.pop(subscription)
    asyncio.run(exercise())


def test_http_start_stop_and_live_websocket(client, monkeypatch):
    from backend.app import live
    api, factory = client
    controller = make_capture(factory, sniffer_factory=FakeSniffer)
    monkeypatch.setattr(live, "capture", controller)
    monkeypatch.setattr(live, "interfaces", lambda: {"available": True, "error": "", "interfaces": [{"id": "wifi", "name": "Wi-Fi"}]})
    api.put("/api/settings", json={"demo_mode": False, "refresh_seconds": 30})
    with api.websocket_connect('/api/ws/monitor') as ws:
        assert ws.receive_json()["type"] == "connected"
        response = api.post('/api/live/start', json={"interface_id": "wifi"})
        assert response.status_code == 200 and response.json()["status"] == "running"
        assert api.post('/api/live/start', json={"interface_id": "wifi"}).status_code == 409
        assert api.put('/api/settings', json={"demo_mode": True, "refresh_seconds": 30}).status_code == 409
        raw = packets()[0]
        raw.time = time.time()
        controller.enqueue(raw)
        assert api.post('/api/live/stop').status_code == 200
        while True:
            message = ws.receive_json()
            if message.get("live", {}).get("capture_id") and message["live"]["status"] == "stopped":
                assert message["live"]["processed_packets"] == 1
                break
    assert api.get('/api/live/sessions').json()[0]["status"] == "stopped"
    flow = api.get('/api/flows').json()["items"][0]
    assert flow["traffic_source"] == "live"
    assert api.get(f'/api/captures/{flow["capture_id"]}/packets').json()["total"] == 1
    assert api.post(f'/api/captures/{flow["capture_id"]}/replay').status_code == 409


def test_failed_commit_never_publishes_unpersisted_packets(client, monkeypatch):
    from sqlalchemy.orm import Session, sessionmaker
    from sqlalchemy import func
    from backend.app import live
    from backend.app.models import PacketRecord, LiveSession
    failed = False
    class FailingSession(Session):
        def commit(self):
            nonlocal failed
            if not failed and self.scalar(select(func.count()).select_from(PacketRecord)):
                failed = True
                raise OSError('disk full')
            super().commit()
    factory = sessionmaker(bind=client[1].kw["bind"], class_=FailingSession)
    controller = make_capture(factory, sniffer_factory=FakeSniffer)
    async def exercise():
        await controller.start({"id": "wifi", "name": "Wi-Fi"})
        raw = packets()[0]
        raw.time = time.time()
        controller.enqueue(raw)
        await asyncio.to_thread(wait_until, lambda: controller.snapshot()["status"] == "error")
        await controller.close()
    asyncio.run(exercise())
    state = controller.snapshot()
    assert state["processed_packets"] == 0 and state["recent_packets"] == []
    assert state["persistence_dropped_packets"] == state["dropped_packets"] == 1
    with client[1]() as db:
        assert db.get(LiveSession, state["capture_id"]).status == "error"
        assert db.scalar(select(PacketRecord)) is None


def test_backlogged_queue_still_expires_terminated_and_quiet_flows(client, monkeypatch):
    import threading
    from backend.app import live
    blocked, release = threading.Event(), threading.Event()
    count = 0
    original = live.packet_record
    def packet_record(*args):
        nonlocal count
        count += 1
        if count == 257:
            blocked.set()
            assert release.wait(5)
        return original(*args)
    class BurstSniffer(FakeSniffer):
        def start(self):
            super().start()
            now = time.time()
            raw = packets()[-1]
            raw.time = now - 122
            self.options['prn'](raw)
            for index in range(799):
                raw = Ether()/IP(src='10.0.0.3', dst='10.0.0.4')/UDP(sport=42, dport=53)
                raw.time = now - 121 if index == 0 else now
                if index == 0:
                    raw[UDP].sport = 41
                self.options['prn'](raw)
    monkeypatch.setattr(live, 'packet_record', packet_record)
    monkeypatch.setattr(live, 'predict', lambda features: None)
    controller = make_capture(client[1], sniffer_factory=BurstSniffer)
    async def exercise():
        await controller.start({'id': 'wifi', 'name': 'Wi-Fi'})
        try:
            assert await asyncio.to_thread(blocked.wait, 5)
            snapshot = controller.snapshot()
            assert snapshot['queue_depth'] > 0
            assert snapshot['completed_flows'] == 2
        finally:
            release.set()
            await controller.close()
    asyncio.run(exercise())


def test_interface_enumeration_returns_addresses_and_reports_missing_npcap(monkeypatch):
    from types import SimpleNamespace
    from backend.app import live
    class Interfaces(dict):
        def reload(self):
            pass
    adapter = SimpleNamespace(network_name='npcap-device', description='Wi-Fi', name='Wi-Fi',
                              ips={4: ['192.168.1.2'], 6: ['fe80::1']}, is_valid=lambda: True)
    config = SimpleNamespace(use_pcap=True, ifaces=Interfaces({'id': adapter}))
    monkeypatch.setattr(live, 'conf', config)
    monkeypatch.setattr(live.sys, 'platform', 'win32')
    result = live.interfaces()
    assert result['interfaces'][0]['addresses'] == ['192.168.1.2', 'fe80::1']
    assert result['interfaces'][0]['id'] == 'npcap-device'
    config.use_pcap = False
    result = live.interfaces()
    assert result['available'] is False and result['interfaces'] == []
    assert 'Npcap' in result['error']


def test_publisher_does_not_lose_final_snapshot_when_worker_exits_between_checks(client, monkeypatch):
    from backend.app import live
    from types import SimpleNamespace
    controller = make_capture(client[1])
    controller.state['status'] = 'running'
    events = []
    def ended():
        controller.state['status'] = 'stopped'
        return False
    async def collect(event):
        events.append(event)
    controller.thread = SimpleNamespace(is_alive=ended)
    monkeypatch.setattr(live, 'broadcast', collect)
    asyncio.run(controller._publish())
    assert events[-1]['live']['status'] == 'stopped'


def test_stop_during_failure_cleanup_preserves_terminal_error(client):
    import threading
    cleanup, release = threading.Event(), threading.Event()
    class SlowCleanup(FakeSniffer):
        def join(self, timeout=None):
            cleanup.set()
            assert release.wait(5)
    controller = make_capture(client[1], sniffer_factory=SlowCleanup)
    async def exercise():
        await controller.start({'id': 'wifi', 'name': 'Wi-Fi'})
        controller.sniffer.running = False
        controller.sniffer.exception = OSError('adapter disconnected')
        try:
            assert await asyncio.to_thread(cleanup.wait, 5)
            assert (await controller.stop())['status'] == 'error'
        finally:
            release.set()
            await controller.close()
        assert controller.snapshot()['status'] == 'error'
    asyncio.run(exercise())


def test_websocket_reconnects_release_subscribers(client):
    from backend.app.events import clients
    api, _ = client
    api.put('/api/settings', json={"demo_mode": False, "refresh_seconds": 30})
    before = len(clients)
    for _ in range(10):
        with api.websocket_connect('/api/ws/monitor') as ws:
            assert ws.receive_json()['type'] == 'connected'
    assert len(clients) == before
