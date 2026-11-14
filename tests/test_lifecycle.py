"""Data lifecycle and login security regressions for v0.5.0.

The PostgreSQL test database is dropped/recreated by the fixture; never point
this suite at a production or shared instance.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from sqlalchemy import event as sqlalchemy_event, func, select, text
from fastapi import HTTPException

from signalharbor.auth import hash_token
from signalharbor.engine import retention
from signalharbor.login_security import begin_login, failed_login
from signalharbor.migrations import migrate
from signalharbor.models import (
    Alert, Escalation, Environment, Event, Incident, IngestKey, LoginAttempt,
    MetricHour, Notification, Outbox, Postmortem, SchemaVersion, Service,
    SessionLocal, StreamEvent, Timeline, WorkerStatus, engine, utcnow,
)
from .conftest import login


def event_record(event_id, at, *, kind="error", late=False, svc=1, env=1, key=1):
    return Event(
        event_id=event_id, key_id=key, service_id=svc, environment_id=env,
        kind=kind, severity="error" if kind == "error" else "info",
        occurred_at=at, received_at=at, late=late,
        labels={"region": "eu"}, payload={"secret": "not-in-aggregate"},
    )


def test_raw_events_archive_atomically_and_repeat_safely(client):
    now = utcnow()
    historical = now - timedelta(days=31)
    with SessionLocal.begin() as db:
        db.add_all([
            event_record("old-error", historical),
            event_record("old-info", historical, kind="log", late=True),
            event_record("future-outbox", now - timedelta(days=32)),
            event_record("too-old", now - timedelta(days=185)),
            event_record("recent", now - timedelta(days=1)),
        ])
        db.flush()
        pending = db.scalar(select(Event).where(Event.event_id == "future-outbox"))
        db.add(Outbox(kind="ingest", subject_id=pending.id, created_at=historical))
    report = retention(now)
    assert report["eventsArchived"] == 3
    with SessionLocal() as db:
        assert set(db.scalars(select(Event.event_id)).all()) == {"future-outbox", "recent"}
        aggregates = db.scalars(select(MetricHour)).all()
        assert len(aggregates) == 1
        metric = aggregates[0]
        assert metric.event_count == 2
        assert metric.error_count == 1
        assert metric.late_count == 1
        assert "secret" not in str(metric.__dict__)
    assert retention(now)["eventsArchived"] == 0
    with SessionLocal() as db:
        assert db.scalar(select(MetricHour.event_count)) == 2
    # Once the outbox task is committed, the delayed event can be archived too.
    with SessionLocal.begin() as db:
        pending_outbox = db.scalar(select(Outbox))
        pending_outbox.processed_at = now
    assert retention(now)["eventsArchived"] == 1
    with SessionLocal() as db:
        assert db.scalar(select(func.sum(MetricHour.event_count))) == 3


def test_metrics_expire_after_180_days(client):
    now = utcnow()
    with SessionLocal.begin() as db:
        db.add_all([
            MetricHour(team_id=1, service_id=1, environment_id=1,
                       bucket_at=now - timedelta(days=190),
                       event_count=50, error_count=40, late_count=2),
            MetricHour(team_id=1, service_id=1, environment_id=1,
                       bucket_at=now - timedelta(days=179),
                       event_count=3, error_count=1, late_count=0),
        ])
    outcome = retention(now)
    assert outcome["metricsPurged"] == 1
    with SessionLocal() as db:
        assert db.scalar(select(func.count(MetricHour.id))) == 1
        assert db.scalar(select(MetricHour.event_count)) == 3


def test_history_merges_archive_and_raw_and_enforces_teams(client):
    now = utcnow()
    with SessionLocal.begin() as db:
        svc = Service(name="finance-api", team_id=2)
        db.add(svc)
        db.flush()
        env = Environment(name="prod", service_id=svc.id)
        db.add(env)
        db.flush()
        key = IngestKey(name="finance", environment_id=env.id,
                        token_hash=hash_token("finance-fixture"))
        db.add(key)
        db.flush()
        db.add_all([
            event_record("infra-history", now - timedelta(days=31)),
            event_record("infra-live", now - timedelta(days=1)),
            event_record("finance-history", now - timedelta(days=31),
                         svc=svc.id, env=env.id, key=key.id),
        ])
    retention(now)
    login(client, "engineer@example.test")
    infra = client.get("/api/v1/history", params={"days": 60})
    assert infra.status_code == 200, infra.text
    assert sum(p["count"] for p in infra.json()["points"]) == 2
    assert sum(p["errors"] for p in infra.json()["points"]) == 2
    assert len(infra.json()["points"]) == 60
    assert infra.json()["policy"]["metricsDays"] == 180
    assert client.get("/api/v1/history", params={"serviceId": svc.id}).status_code == 404
    assert client.get("/api/v1/history", params={"days": 181}).status_code == 400
    login(client, "other@example.test")
    other = client.get("/api/v1/history", params={"days": 60})
    assert other.status_code == 200
    assert sum(p["count"] for p in other.json()["points"]) == 1
    login(client, "admin@example.test")
    all_teams = client.get("/api/v1/history", params={"days": 60})
    assert sum(p["count"] for p in all_teams.json()["points"]) == 3
    created = client.post("/api/v1/users", json={
        "email": "historian-observer@example.test",
        "password": "secure-password-123", "role": "observer", "teamId": 1,
    })
    assert created.status_code == 201
    login(client, "historian-observer@example.test")
    assert client.get("/api/v1/history", params={"days": 30}).status_code == 403


def test_resolved_incident_purges_after_365_days_with_all_dependents(client):
    now = utcnow()
    ancient = now - timedelta(days=366)
    recent = now - timedelta(days=60)
    with SessionLocal.begin() as db:
        old = Incident(team_id=1, service_id=1, environment_id=1,
                       summary="Past outage", severity="high",
                       state="resolved", created_at=ancient, resolved_at=ancient)
        new = Incident(team_id=1, service_id=1, environment_id=1,
                       summary="Recent outage", severity="high",
                       state="resolved", created_at=recent, resolved_at=recent)
        active = Incident(team_id=1, service_id=1, environment_id=1,
                          summary="Still active", severity="high",
                          state="open", created_at=ancient)
        db.add_all([old, new, active])
        db.flush()
        db.add_all([
            Alert(fingerprint="a" * 64, rule_id=1, rule_version=1,
                  service_id=1, environment_id=1, incident_id=old.id,
                  state="resolved", value=30, count=30),
            Timeline(incident_id=old.id, kind="resolved", data={"note": "old"}),
            Notification(incident_id=old.id, level=1, recipient_id=1),
            Escalation(incident_id=old.id, level=2),
            Postmortem(incident_id=old.id, impact="loss", root_cause="bad config",
                       action_items=[], created_by=1),
            StreamEvent(incident_id=old.id, team_id=1, kind="resolved", content={}),
        ])
        old_id, new_id, active_id = old.id, new.id, active.id
    first = retention(now)
    assert first["incidentsPruned"] == 1
    with SessionLocal() as db:
        assert set(db.scalars(select(Incident.id)).all()) == {new_id, active_id}
        for cls in (Alert, Timeline, Notification, Escalation, Postmortem, StreamEvent):
            assert db.scalar(select(func.count()).select_from(cls).where(
                cls.incident_id == old_id,
            )) == 0
    assert retention(now)["incidentsPruned"] == 0


def test_login_account_limit_and_success_reset(client):
    for i in range(8):
        r = client.post("/api/v1/login", json={
            "email": "engineer@example.test", "password": "wrong-password",
        })
        assert r.status_code == (429 if i == 7 else 401)
    assert int(r.headers["retry-after"]) > 0
    locked = client.post("/api/v1/login", json={
        "email": "engineer@example.test", "password": "secure-password-123",
    })
    assert locked.status_code == 429
    with SessionLocal() as db:
        row = db.scalar(select(LoginAttempt))
        assert row.failures == 8
        assert "engineer@example.test" not in row.key_hash
    with SessionLocal.begin() as db:
        row = db.scalar(select(LoginAttempt))
        row.window_started_at = utcnow() - timedelta(hours=2)
        row.locked_until = utcnow() - timedelta(hours=1)
    login(client, "engineer@example.test")
    with SessionLocal() as db:
        assert db.scalar(select(func.count(LoginAttempt.key_hash))) == 0


def test_unknown_account_has_generic_response_and_hashed_throttle(client):
    r = client.post("/api/v1/login", json={
        "email": "nobody@example.test", "password": "wrong-password",
    })
    assert r.status_code == 401
    assert r.json()["message"] == "Invalid credentials"
    with SessionLocal() as db:
        a = db.scalar(select(LoginAttempt))
        assert a.failures == 1
        assert "nobody" not in a.key_hash


def test_concurrent_failed_logins_count_every_attempt(fixture_db):
    barrier = Barrier(2)

    def attempt():
        with SessionLocal() as db:
            barrier.wait(timeout=10)
            record, key = begin_login(db, "engineer@example.test")
            with pytest.raises(HTTPException) as exc:
                failed_login(db, record, key)
            return exc.value.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: attempt(), [1, 2]))
    assert statuses == [401, 401]
    with SessionLocal() as db:
        attempts = db.scalars(select(LoginAttempt)).all()
        assert len(attempts) == 1
        assert attempts[0].failures == 2


def test_migration_v3_to_v4_preserves_data(fixture_db):
    with SessionLocal.begin() as db:
        db.add(WorkerStatus(id="worker-keep", processed_count=99, errors_count=3))
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE metric_hours"))
        conn.execute(text("DROP TABLE login_attempts"))
        conn.execute(text("DROP TABLE mfa_credentials"))
        conn.execute(text("DROP TABLE mfa_enrollments"))
        conn.execute(text("DROP TABLE ingest_quotas"))
        conn.execute(text("DELETE FROM schema_version WHERE version>=4"))
    assert migrate() == 5
    assert migrate() == 5
    with SessionLocal() as db:
        assert db.get(WorkerStatus, "worker-keep").processed_count == 99
        assert db.scalars(select(SchemaVersion.version).order_by(
            SchemaVersion.version,
        )).all() == [1, 2, 3, 4, 5]


def test_archive_failure_rolls_back_counts_and_raw_deletion(client):
    now = utcnow()
    with SessionLocal.begin() as db:
        db.add(event_record("inject-failure", now - timedelta(days=45)))

    def inject_failure(conn, cursor, statement, parameters, context, executemany):
        if statement.strip().upper().startswith("DELETE FROM INGEST_EVENTS"):
            raise RuntimeError("archive delete fault injection")

    sqlalchemy_event.listen(engine, "before_cursor_execute", inject_failure)
    try:
        with pytest.raises(RuntimeError, match="archive delete fault injection"):
            retention(now)
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", inject_failure)
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Event.id))) == 1
        assert db.scalar(select(func.count(MetricHour.id))) == 0
    assert retention(now)["eventsArchived"] == 1
    with SessionLocal() as db:
        assert db.scalar(select(func.sum(MetricHour.event_count))) == 1


def test_active_alert_prevents_purging_old_resolved_incident(client):
    now = utcnow()
    ancient = now - timedelta(days=400)
    with SessionLocal.begin() as db:
        old = Incident(
            team_id=1, service_id=1, environment_id=1,
            summary="Old resolved incident with active signal",
            severity="high", state="resolved",
            created_at=ancient, resolved_at=ancient,
        )
        db.add(old)
        db.flush()
        db.add(Alert(
            fingerprint="b" * 64, rule_id=1, rule_version=1,
            service_id=1, environment_id=1, incident_id=old.id,
            state="firing", value=22, count=22,
        ))
    assert retention(now)["incidentsPruned"] == 0
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Incident.id))) == 1
