"""Executable acceptance subset. Load, SSE reconnection and fault injection remain manual."""
from datetime import timedelta

from sqlalchemy import func, select

from signalharbor.engine import drain_outbox, scan_escalations, scan_health
from signalharbor.models import (
    Alert, Escalation, Event, Incident, Notification, Outbox, SessionLocal, Timeline, utcnow,
)
from .conftest import login, make_events


def test_at01_duplicate_event_id(client):
    body = make_events(1)
    headers = {"x-ingest-key": "fixture-key"}
    for i in range(5):
        response = client.post("/ingest/v1/events", json=body, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["accepted"] == (1 if i == 0 else 0)
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Event.id))) == 1
        assert db.scalar(select(func.count(Outbox.id))) == 1


def test_at02_validation_and_quota(client):
    headers = {"x-ingest-key": "fixture-key"}
    invalid = client.post("/ingest/v1/events", json={"schemaVersion": 1, "events": [
        {"eventId": str(i), "serviceId": 1, "timestamp": utcnow().isoformat(),
         "severity": "error", "type": "error"} for i in range(501)
    ]}, headers=headers)
    assert invalid.status_code == 400
    huge = client.post("/ingest/v1/events", content=b"Z" * 1100000, headers=headers)
    assert huge.status_code == 413
    wrong_source = client.post("/ingest/v1/events", json=make_events(1, service_id=999),
                               headers=headers)
    assert wrong_source.status_code == 403


def test_at03_at04_one_alert_and_one_incident(client):
    response = client.post("/ingest/v1/events", json=make_events(40),
                           headers={"x-ingest-key": "fixture-key"})
    assert response.status_code == 200
    assert response.json()["accepted"] == 40
    assert drain_outbox() == 40
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Alert.id))) == 1
        assert db.scalar(select(func.count(Incident.id))) == 1
        a = db.scalar(select(Alert))
        assert a.state == "firing"
        assert a.count == 40
    again = client.post("/ingest/v1/events", json=make_events(40, prefix="new-"),
                        headers={"x-ingest-key": "fixture-key"})
    assert again.status_code == 200
    drain_outbox()
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Alert.id))) == 1
        assert db.scalar(select(func.count(Incident.id))) == 1


def test_at06_hysteresis_and_at07_at08_escalation(client):
    assert client.post("/ingest/v1/events", json=make_events(40),
                       headers={"x-ingest-key": "fixture-key"}).status_code == 200
    drain_outbox()
    now = utcnow()
    scan_escalations(now + timedelta(seconds=301))
    scan_escalations(now + timedelta(seconds=302))
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Escalation.id))) == 1
        assert db.scalar(select(func.count(Timeline.id)).where(Timeline.kind == "escalated")) == 1
        assert db.scalar(select(func.count(Notification.id)).where(Notification.level == 2)) == 1
    scan_health(now + timedelta(seconds=600))
    scan_health(now + timedelta(seconds=630))
    with SessionLocal() as db:
        assert db.scalar(select(Alert)).state == "firing"
    scan_health(now + timedelta(seconds=781))
    with SessionLocal() as db:
        assert db.scalar(select(Alert)).state == "recovered"


def test_ack_idempotent_team_isolation_postmortem_metrics(client):
    assert client.post("/ingest/v1/events", json=make_events(40),
                       headers={"x-ingest-key": "fixture-key"}).status_code == 200
    drain_outbox()
    login(client, "other@example.test")
    assert client.get("/api/v1/incidents").json() == []
    assert client.get("/api/v1/incidents/1").status_code == 404
    assert client.post("/api/v1/incidents/1/ack").status_code == 404
    login(client, "engineer@example.test")
    assert client.post("/api/v1/incidents/1/ack").status_code == 200
    assert client.post("/api/v1/incidents/1/ack").status_code == 200
    login(client, "backup@example.test")
    assert client.post("/api/v1/incidents/1/ack").status_code == 409
    assert client.post("/api/v1/incidents/1/resolve", json={"reason": "Fixed"}).status_code == 403
    login(client, "commander@example.test")
    assert client.post("/api/v1/incidents/1/resolve",
                       json={"reason": "Traffic spike subsided"}).status_code == 200
    assert client.put("/api/v1/incidents/1/postmortem", json={
        "impact": "Elevated error rate", "rootCause": "Bad deployment", "actionItems": []
    }).status_code == 200
    metrics = client.get("/api/v1/metrics").json()
    assert metrics["ackSampleSize"] == 1
    assert metrics["resolutionSampleSize"] == 1
    assert metrics["mttaSeconds"] >= 0
    assert metrics["mttrSeconds"] >= metrics["mttaSeconds"]


def test_late_event_stored_without_rule_processing(client):
    body = make_events(1)
    body["events"][0]["timestamp"] = (utcnow() - timedelta(minutes=3)).isoformat()
    result = client.post("/ingest/v1/events", json=body,
                         headers={"x-ingest-key": "fixture-key"})
    assert result.status_code == 200
    with SessionLocal() as db:
        assert db.scalar(select(Event)).late is True
        assert db.scalar(select(func.count(Outbox.id))) == 0


def test_csrf_and_role_protection(client):
    login(client, "engineer@example.test")
    token = client.headers.pop("x-csrf-token")
    assert client.post("/api/v1/teams", json={"name": "other"}).status_code == 403
    client.headers["x-csrf-token"] = token
    assert client.post("/api/v1/teams", json={"name": "other"}).status_code == 403
    assert client.get("/api/v1/ingest-keys").status_code == 403


def test_at05_heartbeat_missing_alert(client):
    from signalharbor.models import Rule
    with SessionLocal.begin() as db:
        db.add(Rule(team_id=1, service_id=1, environment_id=1, name="Missing pulse",
                    kind="heartbeat_missing", threshold=180, window_seconds=300,
                    recovery_seconds=180, cooldown_seconds=0, severity="critical",
                    group_labels=[]))
    scan_health(utcnow() + timedelta(seconds=190))
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Alert.id))) == 1
        assert db.scalar(select(Alert)).state == "firing"


def test_at09_maintenance_suppresses_notification_not_history(client):
    from signalharbor.models import Maintenance
    now = utcnow()
    with SessionLocal.begin() as db:
        db.add(Maintenance(environment_id=1, starts_at=now - timedelta(minutes=1),
                           ends_at=now + timedelta(minutes=10), reason="Deploy window"))
    assert client.post("/ingest/v1/events", json=make_events(40),
                       headers={"x-ingest-key": "fixture-key"}).status_code == 200
    drain_outbox()
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Event.id))) == 40
        alert = db.scalar(select(Alert))
        assert alert.state == "firing"
        assert alert.suppressed is True
        assert db.scalar(select(func.count(Notification.id))) == 0
        assert db.scalar(select(func.count(Timeline.id)).where(Timeline.kind == "alert_fired")) == 1


def test_observer_cannot_read_payload_or_timeline(client):
    login(client, "admin@example.test")
    created = client.post("/api/v1/users", json={
        "email": "observer@example.test", "password": "another-strong-password",
        "role": "observer", "teamId": 1,
    })
    assert created.status_code == 201
    assert client.post("/ingest/v1/events", json=make_events(40),
                       headers={"x-ingest-key": "fixture-key"}).status_code == 200
    drain_outbox()
    response = client.post("/api/v1/login", json={
        "email": "observer@example.test", "password": "another-strong-password",
    })
    assert response.status_code == 200
    client.headers["x-csrf-token"] = client.cookies.get("signalharbor_csrf")
    assert client.get("/api/v1/events").status_code == 403
    assert client.get("/api/v1/alerts").status_code == 403
    assert client.get("/api/v1/incidents/1/timeline").status_code == 403
    status = client.get("/api/v1/incidents/1").json()
    assert status["summary"] == "Service status change"
    assert status["ownerId"] is None
