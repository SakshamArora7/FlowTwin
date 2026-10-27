import pytest
from sqlalchemy import func, select

from backend.app.demo import seed_demo
from backend.app.models import Flow, Settings


def test_health_reports_actual_phase_and_no_model(client):
    response = client[0].get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok" and body["database"] == "connected"
    assert body["phase"] == 4 and body["capture"] == "pcap_import_and_replay"
    assert body["model"] in ("trained", "not_trained")


def test_demo_totals_reconcile_across_charts(client):
    data = client[0].get("/api/overview").json()
    assert data["is_demo"] is True
    assert data["total"] == 240
    assert data["total"] == sum(data[k] for k in ["benign", "suspicious", "malicious"])
    assert data["total"] == sum(x["value"] for x in data["protocols"])
    assert data["total"] == sum(b[k] for b in data["timeline"] for k in ["benign", "suspicious", "malicious"])
    assert data["suspicious"] + data["malicious"] == sum(x["value"] for x in data["threats"])
    assert data["bytes"] == sum(x["bytes"] for x in data["timeline"])
    assert all(x["is_demo"] and "confidence" not in x for x in data["alerts"])


def test_time_windows_use_dataset_end(client):
    api = client[0]
    assert api.get("/api/overview?hours=1").json()["total"] == 10
    assert api.get("/api/overview?hours=6").json()["total"] == 60
    assert api.get("/api/overview?hours=2").status_code == 422


def test_filters_pagination_and_details(client):
    api = client[0]
    data = api.get("/api/flows?protocol=TCP&classification=malicious").json()
    assert data["total"] > 0
    assert all(x["protocol"] == "TCP" and x["classification"] == "malicious" for x in data["items"])
    first = api.get("/api/flows?page=1").json()["items"]
    second = api.get("/api/flows?page=2").json()["items"]
    assert len(first) == len(second) == 10
    assert {x["id"] for x in first}.isdisjoint(x["id"] for x in second)
    flow = api.get(f'/api/flows/{first[0]["id"]}').json()
    assert flow == first[0]
    found = api.get(f'/api/flows?q={flow["source"]}').json()["items"]
    assert found and all(flow["source"] in f["source"] for f in found)
    assert api.get("/api/flows?q=not-a-real-ip").json()["total"] == 0
    assert api.get("/api/flows/99999").status_code == 404


def test_settings_are_persisted_and_demo_cannot_leak(client):
    api, factory = client
    result = api.put("/api/settings", json={"demo_mode": False, "refresh_seconds": 60})
    assert result.status_code == 200
    with factory() as db:
        assert db.get(Settings, 1).demo_mode is False
        assert db.get(Settings, 1).refresh_seconds == 60
        assert db.scalar(select(func.count()).select_from(Flow)) == 240
    overview = api.get("/api/overview").json()
    assert overview["total"] == 0 and overview["is_demo"] is False
    assert overview["alerts"] == overview["timeline"] == overview["protocols"] == []
    assert api.get("/api/flows").json()["items"] == []
    assert api.get("/api/flows/1").status_code == 404
    api.put("/api/settings", json={"demo_mode": True, "refresh_seconds": 30})
    assert api.get("/api/overview").json()["total"] == 240


@pytest.mark.parametrize("url", ["/api/flows?page=0", "/api/flows?page_size=101", "/api/flows?protocol=SSH", "/api/flows?classification=unknown", "/api/flows?q=" + "x" * 101])
def test_invalid_queries_rejected(client, url):
    assert client[0].get(url).status_code == 422


@pytest.mark.parametrize("payload", [{"demo_mode": True, "refresh_seconds": 0}, {"demo_mode": True, "refresh_seconds": 301}, {"demo_mode": "false", "refresh_seconds": 30}])
def test_invalid_settings_rejected_without_modifying_database(client, payload):
    assert client[0].put("/api/settings", json=payload).status_code == 422
    assert client[0].get("/api/settings").json() == {"demo_mode": True, "refresh_seconds": 30}


def test_seeding_is_idempotent_and_preserves_preferences(client):
    _, factory = client
    with factory() as db:
        db.get(Settings, 1).demo_mode = False
        db.commit()
        seed_demo(db)
        assert db.scalar(select(func.count()).select_from(Flow)) == 240
        assert db.get(Settings, 1).demo_mode is False
