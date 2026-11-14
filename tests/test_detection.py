"""Detection & observability regression scenarios for v0.3.0.

Tests run against an isolated PostgreSQL database in GitHub Actions.
"""
import asyncio
from datetime import timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select
from starlette.requests import Request

from signalharbor.api import stream, stream_rows
from signalharbor.auth import user_from_request
from signalharbor.engine import drain_outbox, scan_health
from signalharbor.models import (
    Alert, Event, Incident, Outbox, Rule, Session, SessionLocal,
    StreamEvent, Timeline, User, utcnow,
)
from .conftest import login, make_events


def test_bounded_late_events_participate_in_short_event_time_window(client):
    with SessionLocal.begin() as db:
        db.get(Rule, 1).window_seconds = 30
    incoming = make_events(40)
    delayed = utcnow() - timedelta(seconds=90)
    for item in incoming["events"]:
        item["timestamp"] = delayed.isoformat()
    resp = client.post(
        "/ingest/v1/events", json=incoming, headers={"x-ingest-key": "fixture-key"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 40
    assert drain_outbox() == 40
    with SessionLocal() as db:
        alert = db.scalar(select(Alert))
        assert alert.state == "firing"
        assert alert.count == 40
        assert db.scalar(select(func.count(Event.id)).where(Event.late.is_(True))) == 0
        fired = db.scalar(select(Timeline).where(Timeline.kind == "alert_fired"))
        assert fired.data["detectionLagMs"] >= 0
    # Recovery is evaluated against wall clock, not the old event timestamp.
    scan_health(utcnow() + timedelta(seconds=35))
    with SessionLocal() as db:
        assert db.scalar(select(Alert)).healthy_since is not None


def test_future_timestamp_event_waits_for_its_time(client):
    with SessionLocal.begin() as db:
        db.get(Rule, 1).threshold = 0
    target = utcnow() + timedelta(seconds=75)
    payload = make_events(1)
    payload["events"][0]["timestamp"] = target.isoformat()
    resp = client.post(
        "/ingest/v1/events", json=payload, headers={"x-ingest-key": "fixture-key"},
    )
    assert resp.status_code == 200, resp.text
    assert drain_outbox() == 0
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Event.id))) == 1
        assert db.scalar(select(func.count(Outbox.id)).where(
            Outbox.processed_at.is_(None),
        )) == 1
    assert drain_outbox(now=target + timedelta(seconds=1)) == 1
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Incident.id))) == 1


def test_rule_label_fingerprints_remain_separate_and_event_filter_scopes(client):
    with SessionLocal.begin() as db:
        db.get(Rule, 1).group_labels = ["region"]
    payload = make_events(50)
    for idx, item in enumerate(payload["events"]):
        item["labels"] = {"region": "eu" if idx < 25 else "us"}
    assert client.post(
        "/ingest/v1/events", json=payload, headers={"x-ingest-key": "fixture-key"},
    ).status_code == 200
    assert drain_outbox() == 50
    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).order_by(Alert.id)).all()
        assert len(alerts) == 2
        assert {a.label_values["region"] for a in alerts} == {"eu", "us"}
        assert db.scalar(select(func.count(Incident.id))) == 1
        eu = next(a for a in alerts if a.label_values["region"] == "eu")
    login(client, "engineer@example.test")
    response = client.get("/api/v1/events", params={"fingerprint": eu.fingerprint})
    assert response.status_code == 200
    assert len(response.json()["items"]) == 25
    assert {e["labels"]["region"] for e in response.json()["items"]} == {"eu"}


def test_ops_metrics_are_durable_and_restricted_to_admin(client):
    assert client.post(
        "/ingest/v1/events", json=make_events(40),
        headers={"x-ingest-key": "fixture-key"},
    ).status_code == 200
    login(client, "engineer@example.test")
    assert client.get("/api/v1/ops").status_code == 403
    drain_outbox()
    login(client, "admin@example.test")
    result = client.get("/api/v1/ops")
    assert result.status_code == 200, result.text
    data = result.json()
    assert data["pendingOutbox"] == 0
    assert data["processedOutboxLastHour"] == 40
    assert data["eventsReceivedLastHour"] == 40
    assert data["detectionLagSamples"] >= 1
    assert data["detectionLagP95Ms"] >= 0
    assert data["lateEventsLastHour"] == 0


def _stream_request(client, last_id=0):
    cookie = client.cookies.get("signalharbor_session")
    assert cookie
    scope = {
        "type": "http", "method": "GET", "path": "/stream/incidents",
        "headers": [(b"cookie", ("signalharbor_session=" + cookie).encode())],
        "query_string": ("lastEventId=" + str(last_id)).encode(),
        "scheme": "http", "http_version": "1.1", "server": ("testserver", 80),
        "client": ("test", 12345),
    }
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    return Request(scope, receive=receive)


def test_stream_reconnect_cursor_and_team_isolation(client):
    login(client, "engineer@example.test")
    with SessionLocal.begin() as db:
        db.add_all([
            StreamEvent(team_id=1, kind="created", content={"incidentId": 8}),
            StreamEvent(team_id=2, kind="secret", content={"incidentId": 99}),
            StreamEvent(team_id=1, kind="resolved", content={"incidentId": 8}),
        ])
    req = _stream_request(client, last_id=1)
    async def read_frames():
        response = await stream(req)
        gen = response.body_iterator
        try:
            first = await anext(gen)
            second = await anext(gen)
            return first, second
        finally:
            await gen.aclose()
    first, second = asyncio.run(read_frames())
    assert "retry: 2000" in first
    assert "id: 3" in second
    assert "resolved" in second
    assert "incidentId" in second and "99" not in second
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "engineer@example.test"))
        assert [r.id for r in stream_rows(db, user, 1)] == [3]
        user.team_id = 2
        db.commit()
    with SessionLocal() as db:
        current = db.scalar(select(User).where(User.email == "engineer@example.test"))
        assert [r.id for r in stream_rows(db, current, 1)] == [2]


def test_sse_session_revocation_is_detected(client):
    login(client, "engineer@example.test")
    request = _stream_request(client)
    with SessionLocal() as db:
        assert user_from_request(request, db).id > 0
    with SessionLocal.begin() as db:
        session = db.scalar(select(Session))
        db.delete(session)
    with SessionLocal() as db:
        with pytest.raises(HTTPException) as error:
            user_from_request(request, db)
    assert error.value.status_code == 401
