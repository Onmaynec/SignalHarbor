"""v0.4.0 performance and crash-safety regressions on real PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest.mock import patch

import pytest
from sqlalchemy import func, select

from signalharbor import engine as rules_engine
from signalharbor.engine import drain_outbox
from signalharbor.models import (
    Alert, Incident, Outbox, Rule, SessionLocal, Timeline, WorkerStatus, utcnow,
)
from signalharbor.worker_health import record_worker
from .conftest import login, make_events


def _send(client, count, prefix="batch"):
    response = client.post(
        "/ingest/v1/events", json=make_events(count, prefix=prefix),
        headers={"x-ingest-key": "fixture-key"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == count


def test_large_batch_evaluates_one_fingerprint_once(client):
    _send(client, 300)
    with patch.object(rules_engine, "evaluate", wraps=rules_engine.evaluate) as evaluate:
        processed = drain_outbox(batch_size=500)
    assert processed == 300
    assert evaluate.call_count == 1
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Alert.id))) == 1
        assert db.scalar(select(Alert)).count == 300
        assert db.scalar(select(func.count(Incident.id))) == 1
        assert db.scalar(select(func.count(Timeline.id)).where(
            Timeline.kind == "alert_fired",
        )) == 1


def test_batch_retains_group_boundaries(client):
    with SessionLocal.begin() as db:
        db.get(Rule, 1).group_labels = ["region"]
    payload = make_events(80)
    for idx, item in enumerate(payload["events"]):
        item["labels"] = {"region": "eu" if idx < 40 else "apac"}
    response = client.post(
        "/ingest/v1/events", json=payload,
        headers={"x-ingest-key": "fixture-key"},
    )
    assert response.status_code == 200
    with patch.object(rules_engine, "evaluate", wraps=rules_engine.evaluate) as evaluate:
        assert drain_outbox(batch_size=100) == 80
    assert evaluate.call_count == 2
    with SessionLocal() as db:
        alerts = db.scalars(select(Alert)).all()
        assert len(alerts) == 2
        assert sorted(alert.count for alert in alerts) == [40, 40]
        assert db.scalar(select(func.count(Incident.id))) == 1


def test_worker_failure_rolls_back_entire_batch(client):
    _send(client, 40)
    with patch.object(rules_engine, "evaluate", side_effect=RuntimeError("injected failure")):
        with pytest.raises(RuntimeError, match="injected failure"):
            drain_outbox(batch_size=100)
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Outbox.id)).where(
            Outbox.processed_at.is_not(None),
        )) == 0
        assert db.scalar(select(func.count(Alert.id))) == 0
        assert db.scalar(select(func.count(Incident.id))) == 0
    assert drain_outbox(batch_size=100) == 40
    assert drain_outbox(batch_size=100) == 0
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Alert.id))) == 1
        assert db.scalar(select(func.count(Incident.id))) == 1
        assert db.scalar(select(func.count(Timeline.id)).where(
            Timeline.kind == "alert_fired",
        )) == 1


def test_parallel_drains_are_idempotent(client):
    _send(client, 200)
    barrier = Barrier(2)

    def consume():
        barrier.wait(timeout=10)
        return drain_outbox(batch_size=100)

    with ThreadPoolExecutor(max_workers=2) as pool:
        processed = list(pool.map(lambda _: consume(), [1, 2]))
    assert sum(processed) == 200
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Outbox.id)).where(
            Outbox.processed_at.is_not(None),
        )) == 200
        assert db.scalar(select(func.count(Alert.id))) == 1
        assert db.scalar(select(func.count(Incident.id))) == 1


def test_worker_heartbeat_durable_and_stale(client):
    record_worker("test-worker", processed=5, failures=1)
    record_worker("test-worker", processed=7, batch_completed=True)
    record_worker("stopped-worker", now=utcnow() - timedelta(minutes=10))
    login(client, "admin@example.test")
    response = client.get("/api/v1/ops")
    assert response.status_code == 200, response.text
    state = response.json()
    assert state["activeWorkers"] == 1
    workers = {w["id"]: w for w in state["workers"]}
    assert workers["test-worker"]["healthy"] is True
    assert workers["test-worker"]["processedTotal"] == 12
    assert workers["test-worker"]["errorsTotal"] == 1
    assert workers["stopped-worker"]["healthy"] is False
    with SessionLocal() as db:
        assert db.scalar(select(func.count(WorkerStatus.id))) == 2


def test_future_events_are_not_reported_as_ready(client):
    from signalharbor.models import utcnow
    future = utcnow() + timedelta(seconds=65)
    body = make_events(1)
    body["events"][0]["timestamp"] = future.isoformat()
    response = client.post(
        "/ingest/v1/events", json=body, headers={"x-ingest-key": "fixture-key"},
    )
    assert response.status_code == 200
    login(client, "admin@example.test")
    state = client.get("/api/v1/ops").json()
    assert state["pendingOutbox"] == 1
    assert state["pendingReady"] == 0
    assert state["pendingDeferred"] == 1
    assert drain_outbox() == 0
    assert drain_outbox(now=future + timedelta(seconds=1)) == 1
