"""Event-time, fingerprint and flapping regressions for v0.7.0."""
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from signalharbor.engine import drain_outbox, process_event, scan_health
from signalharbor.models import (
    Alert, Environment, Event, Incident, Rule, RuleRevision, SessionLocal, Timeline, utcnow,
)
from .conftest import login


def event_batch(count, timestamp, prefix, *, labels=None, kind="error", severity="error"):
    return {
        "schemaVersion": 1,
        "events": [
            {
                "eventId": f"{prefix}-{i}",
                "serviceId": 1,
                "timestamp": timestamp.isoformat(),
                "severity": severity,
                "type": kind,
                "labels": dict(labels or {}),
                "payload": {"sequence": i},
            }
            for i in range(count)
        ],
    }


def ingest(client, body):
    response = client.post(
        "/ingest/v1/events", json=body, headers={"x-ingest-key": "fixture-key"},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("delivery_order", ["old-first", "new-first"])
def test_short_window_result_is_independent_of_delivery_order(client, delivery_order):
    base = utcnow()
    with SessionLocal.begin() as db:
        rule = db.get(Rule, 1)
        rule.window_seconds = 60
        rule.threshold = 20
    older = event_batch(11, base - timedelta(seconds=80), "older")
    newer = event_batch(10, base - timedelta(seconds=20), "newer")
    batches = [older, newer] if delivery_order == "old-first" else [newer, older]

    for batch in batches:
        ingest(client, batch)
        drain_outbox()
        with SessionLocal() as db:
            # Each half of the stream is below threshold; only the complete
            # event-time window may fire, regardless of arrival order.
            assert db.scalar(select(func.count(Alert.id))) == 0

    with SessionLocal() as db:
        alert = db.scalar(select(Alert))
        assert alert is not None
        assert alert.state == "firing"
        assert alert.count == 21
        assert alert.value == 21
        assert alert.window_end_at == base - timedelta(seconds=20)
        assert alert.window_start_at == base - timedelta(seconds=80)


def test_missing_selected_label_uses_the_same_empty_value_in_sql_and_fingerprint(client):
    with SessionLocal.begin() as db:
        db.get(Rule, 1).group_labels = ["region"]
    missing = event_batch(21, utcnow(), "missing-region")
    explicit = event_batch(21, utcnow(), "eu-region", labels={"region": "eu"})
    ingest(client, missing)
    ingest(client, explicit)
    assert drain_outbox() == 42

    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).order_by(Alert.id)).all()
        assert len(alerts) == 2
        by_region = {item.label_values["region"]: item for item in alerts}
        assert set(by_region) == {"", "eu"}
        assert all(item.state == "firing" and item.count == 21 for item in alerts)
        missing_fp = by_region[""].fingerprint
        eu_fp = by_region["eu"].fingerprint

    login(client, "engineer@example.test")
    missing_result = client.get("/api/v1/events", params={"fingerprint": missing_fp})
    eu_result = client.get("/api/v1/events", params={"fingerprint": eu_fp})
    assert missing_result.status_code == 200
    assert eu_result.status_code == 200
    assert len(missing_result.json()["items"]) == 21
    assert all("region" not in item["labels"] for item in missing_result.json()["items"])
    assert len(eu_result.json()["items"]) == 21
    assert {item["labels"]["region"] for item in eu_result.json()["items"]} == {"eu"}


def test_fingerprint_event_query_uses_rule_kind_and_exact_window(client):
    with SessionLocal.begin() as db:
        first = db.get(Rule, 1)
        first.group_labels = ["region"]
        db.add(Rule(
            team_id=1, service_id=1, environment_id=1,
            name="Error percentage", kind="error_rate",
            window_seconds=300, threshold=40, recovery_seconds=180,
            cooldown_seconds=0, severity="high", group_labels=["region"],
        ))
    at = utcnow()
    body = event_batch(25, at, "error", labels={"region": "eu"})
    body["events"].extend(event_batch(
        25, at, "info", labels={"region": "eu"}, kind="log", severity="info",
    )["events"])
    body["events"].extend(event_batch(
        5, at - timedelta(seconds=150), "late", labels={"region": "eu"},
    )["events"])
    ingest(client, body)
    assert drain_outbox() == 50

    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).order_by(Alert.rule_id)).all()
        assert len(alerts) == 2
        count_alert = next(a for a in alerts if a.rule_id == 1)
        rate_alert = next(a for a in alerts if a.rule_id != 1)
        assert count_alert.count == 25
        assert rate_alert.value == 50
        assert count_alert.window_start_at is not None
        assert count_alert.window_end_at is not None

    login(client, "engineer@example.test")
    count_events = client.get(
        "/api/v1/events", params={"fingerprint": count_alert.fingerprint},
    ).json()["items"]
    rate_events = client.get(
        "/api/v1/events", params={"fingerprint": rate_alert.fingerprint},
    ).json()["items"]
    assert len(count_events) == 25
    assert all(item["type"] == "error" or item["severity"] == "error"
               for item in count_events)
    assert len(rate_events) == 50


def rule_payload(*, threshold=20, group_labels=None, enabled=True):
    return {
        "name": "Error burst",
        "teamId": 1,
        "serviceId": 1,
        "environmentId": 1,
        "kind": "count_error",
        "windowSeconds": 300,
        "threshold": threshold,
        "cooldownSeconds": 0,
        "recoverySeconds": 180,
        "severity": "high",
        "groupLabels": list(group_labels or []),
        "enabled": enabled,
    }


def test_active_alert_tracks_new_rule_version_after_threshold_edit(client):
    ingest(client, event_batch(40, utcnow(), "version"))
    drain_outbox()
    login(client, "admin@example.test")
    response = client.put(
        "/api/v1/alert-rules/1?expectedVersion=1",
        json=rule_payload(threshold=10),
    )
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 2

    with SessionLocal() as db:
        alert = db.scalar(select(Alert))
        assert alert.state == "firing"
        assert alert.rule_version == 2
        revision = db.scalar(select(RuleRevision).where(
            RuleRevision.rule_id == 1, RuleRevision.version == 2,
        ))
        assert revision is not None
        assert revision.configuration["threshold"] == 10
        assert db.scalar(select(func.count(Timeline.id)).where(
            Timeline.kind == "alert_rule_updated",
        )) == 1


def test_grouping_change_retires_old_alert_generation(client):
    ingest(client, event_batch(40, utcnow(), "old-generation"))
    drain_outbox()
    with SessionLocal() as db:
        old = db.scalar(select(Alert))
        old_fingerprint = old.fingerprint
        old_window_end = old.window_end_at

    login(client, "admin@example.test")
    changed = client.put(
        "/api/v1/alert-rules/1?expectedVersion=1",
        json=rule_payload(group_labels=["region"]),
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["version"] == 2
    with SessionLocal() as db:
        old = db.scalar(select(Alert))
        assert old.state == "recovered"
        assert old.rule_version == 1
        assert old.recovered_at is not None
        assert db.scalar(select(func.count(Timeline.id)).where(
            Timeline.kind == "alert_reconfigured",
        )) == 1

    ingest(client, event_batch(40, utcnow(), "new-generation", labels={"region": "eu"}))
    drain_outbox()
    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).order_by(Alert.id)).all()
        assert len(alerts) == 2
        new = next(item for item in alerts if item.fingerprint != old_fingerprint)
        assert new.state == "firing"
        assert new.rule_version == 2
        assert new.label_values == {"region": "eu"}

    login(client, "engineer@example.test")
    old_items = client.get(
        "/api/v1/events", params={"fingerprint": old_fingerprint},
    ).json()["items"]
    assert len(old_items) == 40
    assert all(item["timestamp"] <= old_window_end.isoformat()
               for item in old_items)


def test_cooldown_rechecks_a_recovered_alert_without_new_ingest(client):
    start = utcnow()
    with SessionLocal.begin() as db:
        rule = db.get(Rule, 1)
        rule.window_seconds = 300
        rule.threshold = 20
        rule.recovery_seconds = 10
        rule.cooldown_seconds = 20
    ingest(client, event_batch(21, start, "first-wave"))
    drain_outbox()

    scan_health(start + timedelta(seconds=301))
    scan_health(start + timedelta(seconds=312))
    with SessionLocal() as db:
        alert = db.scalar(select(Alert))
        assert alert.state == "recovered"
        assert alert.recovered_at == start + timedelta(seconds=312)

    # A second burst occurs inside the cooldown. The recovered alert remains
    # quiet until cooldown expires; the periodic evaluator then sees it again.
    second_at = start + timedelta(seconds=313)
    with SessionLocal.begin() as db:
        rows = [
            Event(
                key_id=1, event_id=f"second-wave-{i}", service_id=1,
                environment_id=1, occurred_at=second_at, received_at=second_at,
                severity="error", kind="error", labels={}, payload={}, late=False,
            )
            for i in range(21)
        ]
        db.add_all(rows)
        db.flush()
        process_event(db, rows[-1], now=second_at)
    with SessionLocal() as db:
        assert db.scalar(select(Alert)).state == "recovered"

    scan_health(start + timedelta(seconds=334))
    with SessionLocal() as db:
        alert = db.scalar(select(Alert))
        assert alert.state == "firing"
        assert alert.recovered_at is None
        assert db.scalar(select(func.count(Timeline.id)).where(
            Timeline.kind == "refired",
        )) == 1
        assert db.scalar(select(func.count(Incident.id))) == 1


def test_error_and_heartbeat_rules_recover_independently(client):
    start = utcnow()
    with SessionLocal.begin() as db:
        db.get(Rule, 1).window_seconds = 300
        db.add(Rule(
            team_id=1, service_id=1, environment_id=1,
            name="Heartbeat gap", kind="heartbeat_missing",
            window_seconds=300, threshold=60, recovery_seconds=10,
            cooldown_seconds=20, severity="critical", group_labels=[],
        ))
    ingest(client, event_batch(21, start, "interleaved-errors"))
    drain_outbox()

    scan_health(start + timedelta(seconds=61))
    with SessionLocal() as db:
        alerts = db.scalars(select(Alert).order_by(Alert.rule_id)).all()
        assert len(alerts) == 2
        assert alerts[0].state == "firing"
        assert alerts[1].state == "firing"
        assert db.scalar(select(func.count(Incident.id))) == 1

    heartbeat_at = start + timedelta(seconds=62)
    with SessionLocal.begin() as db:
        env = db.get(Environment, 1)
        env.last_heartbeat_at = heartbeat_at
        db.add(Event(
            key_id=1, event_id="interleaved-heartbeat", service_id=1,
            environment_id=1, occurred_at=heartbeat_at, received_at=heartbeat_at,
            severity="info", kind="heartbeat", labels={}, payload={}, late=False,
        ))
    scan_health(start + timedelta(seconds=63))
    scan_health(start + timedelta(seconds=74))

    with SessionLocal() as db:
        states = {item.rule_id: item.state for item in db.scalars(select(Alert)).all()}
        assert states[1] == "firing"
        assert states[2] == "recovered"
        assert db.scalar(select(func.count(Incident.id))) == 1


def test_legacy_fingerprint_uses_rule_kind_snapshot_after_edit(client):
    at = utcnow()
    body = event_batch(25, at, "kind-error", labels={"region": "eu"})
    body["events"].extend(event_batch(
        25, at, "kind-info", labels={"region": "eu"}, kind="log", severity="info",
    )["events"])
    ingest(client, body)
    drain_outbox()
    with SessionLocal() as db:
        original = db.scalar(select(Alert))
        fingerprint = original.fingerprint
        assert original.rule_version == 1
        assert original.count == 25

    login(client, "admin@example.test")
    updated = rule_payload(threshold=40, group_labels=["region"])
    updated["kind"] = "error_rate"
    response = client.put(
        "/api/v1/alert-rules/1?expectedVersion=1", json=updated,
    )
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 2

    with SessionLocal() as db:
        original = db.scalar(select(Alert))
        assert original.state == "recovered"
        assert original.rule_version == 1
        snapshot = db.scalar(select(RuleRevision).where(
            RuleRevision.rule_id == 1, RuleRevision.version == 1,
        ))
        assert snapshot.configuration["kind"] == "count_error"

    login(client, "engineer@example.test")
    result = client.get("/api/v1/events", params={"fingerprint": fingerprint})
    assert result.status_code == 200
    assert len(result.json()["items"]) == 25
    assert all(item["type"] == "error" or item["severity"] == "error"
               for item in result.json()["items"])
