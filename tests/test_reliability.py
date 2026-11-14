"""Reliability regressions for v0.2.0.

All tests execute on the real dedicated PostgreSQL test service in CI.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from sqlalchemy import func, select, text

from signalharbor.engine import ensure_incident, retention
from signalharbor.migrations import migrate
from signalharbor.models import (
    Alert, Event, Incident, Outbox, Rule, SchemaVersion,
    SessionLocal, Timeline, engine, utcnow,
)


def test_migration_reentrant_and_index_exists(fixture_db):
    assert migrate() == 6
    assert migrate() == 6
    with SessionLocal() as db:
        assert db.scalars(select(SchemaVersion.version).order_by(SchemaVersion.version)).all() == [1, 2, 3, 4, 5, 6]
    with engine.connect() as conn:
        indexes = {row[0] for row in conn.execute(text(
            "SELECT indexname FROM pg_indexes WHERE tablename = 'incidents'"
        )).all()}
    assert "uq_active_incident_scope" in indexes
    with engine.connect() as conn:
        worker_indexes = {row[0] for row in conn.execute(text(
            "SELECT indexname FROM pg_indexes WHERE tablename = 'worker_status'"
        )).all()}
    assert "ix_worker_status_seen" in worker_indexes


def test_active_incident_constraint_and_new_incident_after_resolution(fixture_db):
    with SessionLocal.begin() as db:
        db.add(Incident(team_id=1, service_id=1, environment_id=1,
                        summary="First", severity="high", state="open"))
    with SessionLocal.begin() as db:
        with pytest.raises(Exception):
            with db.begin_nested():
                db.add(Incident(team_id=1, service_id=1, environment_id=1,
                                summary="Duplicate", severity="high", state="acknowledged"))
                db.flush()
    with SessionLocal.begin() as db:
        first = db.scalar(select(Incident))
        first.state = "resolved"
        first.resolution = "Restored"
        first.resolved_at = utcnow()
    with SessionLocal.begin() as db:
        db.add(Incident(team_id=1, service_id=1, environment_id=1,
                        summary="New incident", severity="high", state="open"))
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Incident.id))) == 2


def test_two_workers_open_one_incident(fixture_db):
    barrier = Barrier(2)
    def worker(n):
        with SessionLocal.begin() as db:
            rule = db.get(Rule, 1)
            alert = Alert(
                fingerprint=str(n) * 64, rule_id=rule.id, rule_version=1,
                service_id=1, environment_id=1, state="firing",
                count=21, value=21, fired_at=utcnow(), last_seen_at=utcnow(),
                label_values={"worker": str(n)},
            )
            db.add(alert)
            db.flush()
            barrier.wait(timeout=10)
            return ensure_incident(db, rule, 1, 1, utcnow(), alert).id
    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = list(pool.map(worker, [1, 2]))
    assert a == b
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Incident.id))) == 1
        assert db.scalar(select(func.count(Alert.id))) == 2
        assert db.scalar(select(func.count(Timeline.id)).where(Timeline.kind == "created")) == 1


def test_retention_keeps_unprocessed_events(fixture_db):
    past = utcnow() - timedelta(days=32)
    with SessionLocal.begin() as db:
        db.add_all([
            Event(key_id=1, event_id="pending", service_id=1, environment_id=1,
                  occurred_at=past, received_at=past, severity="error",
                  kind="error", labels={}, payload={}, late=False),
            Event(key_id=1, event_id="finished", service_id=1, environment_id=1,
                  occurred_at=past, received_at=past, severity="error",
                  kind="error", labels={}, payload={}, late=False),
        ])
        db.flush()
        ids = {e.event_id: e.id for e in db.scalars(select(Event)).all()}
        db.add_all([
            Outbox(kind="ingest", subject_id=ids["pending"], created_at=past),
            Outbox(kind="ingest", subject_id=ids["finished"],
                   created_at=past, processed_at=past),
        ])
    retention()
    with SessionLocal() as db:
        surviving = db.scalars(select(Event.event_id)).all()
        assert surviving == ["pending"]
        todo = db.scalars(select(Outbox)).all()
        assert len(todo) == 1
        assert todo[0].processed_at is None


def test_legacy_duplicate_incident_blocks_migration(fixture_db):
    # Simulate an existing v1 database that contains duplicates.
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX uq_active_incident_scope"))
        conn.execute(text("DELETE FROM schema_version WHERE version >= 2"))
    with SessionLocal.begin() as db:
        db.add_all([
            Incident(team_id=1, service_id=1, environment_id=1,
                     summary="Old A", severity="high", state="open"),
            Incident(team_id=1, service_id=1, environment_id=1,
                     summary="Old B", severity="high", state="open"),
        ])
    with pytest.raises(RuntimeError, match="multiple active incidents"):
        migrate()
    with SessionLocal() as db:
        # No silent merge or deletion on migration failure.
        assert db.scalar(select(func.count(Incident.id))) == 2
        assert db.scalars(select(SchemaVersion.version)).all() == [1]
