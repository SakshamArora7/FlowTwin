import asyncio

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

from backend.app.main import app
from backend.app.models import Alert, Detection, Flow
from backend.app.traffic import analyze_pcap


def make_pcap(path):
    packets = [
        Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/TCP(sport=12345, dport=443, flags="S"),
        Ether()/IP(src="10.0.0.20", dst="10.0.0.10")/TCP(sport=443, dport=12345, flags="SA"),
        Ether()/IP(src="10.0.0.10", dst="10.0.0.20")/TCP(sport=12345, dport=443, flags="A")/Raw(load=b"sample"),
        Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=3333, dport=53)/Raw(load=b"dns"),
    ]
    for i, packet in enumerate(packets):
        packet.time = 1_700_000_000 + i * 0.1
    wrpcap(str(path), packets)


def test_real_packet_flow_features_and_direction(tmp_path):
    path = tmp_path / "test.pcap"
    make_pcap(path)
    result = analyze_pcap(path)
    assert result["packet_count"] == 4
    assert len(result["flows"]) == 2
    tcp = next(f for f in result["flows"] if f["protocol"] == "TCP")
    assert tcp["forward_packets"] == 2 and tcp["backward_packets"] == 1
    assert tcp["features"]["Total Fwd Packets"] == 2
    assert tcp["features"]["Total Backward Packets"] == 1
    assert tcp["features"]["SYN Flag Count"] == 2
    assert tcp["features"]["ACK Flag Count"] == 2
    assert tcp["features"]["Flow Duration"] > 190_000
    assert tcp["records"][1]["direction"] == "backward"
    assert tcp["records"][2]["payload_size"] == 6


def test_bidirectional_timeout_splits_flows(tmp_path):
    path = tmp_path / "timeout.pcap"
    packets = [Ether()/IP(src="10.1.1.1", dst="10.1.1.2")/UDP(sport=22, dport=23) for _ in range(2)]
    packets[0].time = 1000
    packets[1].time = 1121
    wrpcap(str(path), packets)
    assert len(analyze_pcap(path)["flows"]) == 2


def test_invalid_upload_is_rejected_in_real_mode(client, monkeypatch, tmp_path):
    from backend.app import advanced
    monkeypatch.setattr(advanced, "UPLOAD_DIR", tmp_path)
    api, _ = client
    api.put("/api/settings", json={"demo_mode": False, "refresh_seconds": 30})
    response = api.post("/api/captures", files={"file": ("bad.pcap", b"not a pcap", "application/octet-stream")})
    assert response.status_code == 400
    assert api.get("/api/captures").json() == []


def test_upload_packet_analysis_reports_and_mode_isolation(client, tmp_path, monkeypatch):
    from backend.app import advanced
    monkeypatch.setattr(advanced, "UPLOAD_DIR", tmp_path / "uploads")
    api, _ = client
    path = tmp_path / "demo.pcap"
    make_pcap(path)
    assert api.post("/api/captures", files={"file": ("demo.pcap", path.read_bytes(), "application/octet-stream")}).status_code == 409
    api.put("/api/settings", json={"demo_mode": False, "refresh_seconds": 30})
    response = api.post("/api/captures", files={"file": ("demo.pcap", path.read_bytes(), "application/octet-stream")})
    assert response.status_code == 201, response.text
    capture = response.json()
    assert capture["packet_count"] == 4 and capture["flow_count"] == 2
    assert capture["source"] == "pcap"
    listed = api.get("/api/captures").json()
    assert listed[0]["id"] == capture["id"]
    packets = api.get(f'/api/captures/{capture["id"]}/packets').json()
    assert packets["total"] == 4
    assert {p["protocol"] for p in packets["items"]} == {"TCP", "UDP"}
    sizes = api.get("/api/analytics/packet-sizes").json()
    assert sum(bucket["value"] for bucket in sizes) == 4
    flows = api.get("/api/flows").json()
    assert flows["total"] == 2 and all(not f["is_demo"] for f in flows["items"])
    flow_id = next(f["id"] for f in flows["items"] if f["protocol"] == "TCP")
    detail = api.get(f"/api/flows/{flow_id}/analysis").json()
    assert detail["statistics"]["forward_packets"] == 2
    assert detail["statistics"]["backward_packets"] == 1
    if capture["model_status"] == "trained":
        assert detail["detection"]["confidence"] >= 0
        assert detail["detection"]["explanation"]
    else:
        assert detail["detection"] is None
    csv_report = api.get("/api/reports/csv")
    assert csv_report.status_code == 200 and b"IMPORTED PCAP DATA" in csv_report.content
    pdf_report = api.get("/api/reports/pdf")
    assert pdf_report.status_code == 200 and pdf_report.content.startswith(b"%PDF")
    api.put("/api/settings", json={"demo_mode": True, "refresh_seconds": 30})
    assert api.get("/api/captures").status_code == 409
    assert api.get("/api/analytics/packet-sizes").status_code == 409
    assert api.get(f"/api/flows/{flow_id}/analysis").status_code == 409
    assert api.get("/api/flows").json()["total"] == 240


def test_replay_emits_real_packet_and_flow_events(client, tmp_path, monkeypatch):
    from backend.app import advanced
    api, factory = client
    monkeypatch.setattr(advanced, "UPLOAD_DIR", tmp_path / "uploads")
    monkeypatch.setattr(advanced, "SessionLocal", factory)
    path = tmp_path / "replay.pcap"
    make_pcap(path)
    api.put("/api/settings", json={"demo_mode": False, "refresh_seconds": 30})
    capture = api.post("/api/captures", files={"file": ("replay.pcap", path.read_bytes(), "application/octet-stream")}).json()
    events = []
    class Sink:
        async def send_json(self, payload):
            events.append(payload)
    monkeypatch.setattr(advanced, "clients", {Sink()})
    asyncio.run(advanced.run_replay(capture["id"]))
    assert sum(e["type"] == "packet" for e in events) == 4
    assert sum(e["type"] == "flow" for e in events) == 2
    assert events[0]["type"] == "replay_started"
    assert events[-1]["type"] == "replay_completed"
    assert all(e.get("source") == "pcap_replay" for e in events if e["type"] in {"packet", "flow"})


def test_alert_status_lifecycle(client):
    api, factory = client
    api.put("/api/settings", json={"demo_mode": False, "refresh_seconds": 30})
    with factory() as db:
        flow = Flow(timestamp="2026-10-25T00:00:00+00:00", source="10.0.0.1", destination="10.0.0.2", source_port=1234, destination_port=80, protocol="TCP", packets=12, bytes=500, duration_ms=12.0, classification="malicious", category="DDoS", is_demo=False)
        db.add(flow)
        db.flush()
        detection = Detection(flow_id=flow.id, timestamp="2026-10-25T00:01:00+00:00", category="DDoS", confidence=0.91, severity="High", model_version="test", explanation_json="[]")
        db.add(detection)
        db.flush()
        alert = Alert(detection_id=detection.id, status="New")
        db.add(alert)
        db.commit()
        alert_id = alert.id
    assert api.get("/api/alerts").json()[0]["status"] == "New"
    assert api.patch(f"/api/alerts/{alert_id}", json={"status": "Investigating"}).json()["status"] == "Investigating"
    assert api.patch(f"/api/alerts/{alert_id}", json={"status": "Resolved"}).json()["status"] == "Resolved"
    assert api.get("/api/alerts").json()[0]["status"] == "Resolved"
    assert api.patch(f"/api/alerts/{alert_id}", json={"status": "Deleted"}).status_code == 422
