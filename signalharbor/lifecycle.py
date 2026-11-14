"""Transactional data lifecycle for raw events, hourly metrics and incidents.

Raw ingest events live for 30 days (unless an outbox task remains pending).
Before raw rows are removed, non-sensitive hourly counters are merged into a
180-day metric store in the same transaction. Resolved incident metadata is
purged 365 days after resolution with dependent records. No silent best-effort
archive: a failed upsert rolls back the corresponding raw deletion.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, exists, select, text
from sqlalchemy.orm import Session

from .models import (
    Alert, Escalation, Event, Incident, LoginAttempt, MetricHour, Notification,
    Outbox, Postmortem, Service, Session as UserSession, SessionLocal,
    StreamEvent, Timeline, WorkerStatus, utcnow,
)


RAW_DAYS = 30
METRICS_DAYS = 180
INCIDENT_DAYS = 365


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _archive(db: Session, now: datetime, limit: int) -> int:
    # Row locks plus the transaction-wide lifecycle lock guard archiving from
    # concurrent retention loops. Pending outbox tasks are explicitly excluded.
    pending = exists(select(Outbox.id).where(
        Outbox.kind == "ingest", Outbox.subject_id == Event.id,
        Outbox.processed_at.is_(None),
    ))
    query = (select(Event).where(
        Event.received_at < now - timedelta(days=RAW_DAYS), ~pending,
    ).order_by(Event.id).limit(limit))
    if db.bind.dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    events = db.scalars(query).all()
    if not events:
        return 0

    service_ids = {event.service_id for event in events}
    service_teams = {
        item.id: item.team_id for item in db.scalars(
            select(Service).where(Service.id.in_(service_ids)),
        ).all()
    }
    metrics = defaultdict(lambda: [0, 0, 0])
    aggregate_cutoff = now - timedelta(days=METRICS_DAYS)
    for event in events:
        received = _utc(event.received_at)
        if received < aggregate_cutoff:
            continue
        bucket = received.replace(minute=0, second=0, microsecond=0)
        group = (service_teams[event.service_id], event.service_id,
                 event.environment_id, bucket)
        counters = metrics[group]
        counters[0] += 1
        counters[1] += int(event.kind == "error" or event.severity == "error")
        counters[2] += int(event.late)

    if metrics:
        records = [
            {
                "team_id": group[0], "service_id": group[1],
                "environment_id": group[2], "bucket_at": group[3],
                "event_count": values[0], "error_count": values[1],
                "late_count": values[2],
            }
            for group, values in metrics.items()
        ]
        if db.bind.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            statement = pg_insert(MetricHour).values(records)
            excluded = statement.excluded
            db.execute(statement.on_conflict_do_update(
                constraint="uq_metric_hour_scope",
                set_={
                    "event_count": MetricHour.event_count + excluded.event_count,
                    "error_count": MetricHour.error_count + excluded.error_count,
                    "late_count": MetricHour.late_count + excluded.late_count,
                },
            ))
        else:
            for item in records:
                group = db.scalar(select(MetricHour).where(
                    MetricHour.team_id == item["team_id"],
                    MetricHour.service_id == item["service_id"],
                    MetricHour.environment_id == item["environment_id"],
                    MetricHour.bucket_at == item["bucket_at"],
                ).with_for_update())
                if group is None:
                    db.add(MetricHour(**item))
                else:
                    group.event_count += item["event_count"]
                    group.error_count += item["error_count"]
                    group.late_count += item["late_count"]

    db.execute(delete(Event).where(Event.id.in_([item.id for item in events])))
    return len(events)


def _prune_incidents(db: Session, now: datetime, limit: int) -> int:
    # Retain every open or acknowledged incident, regardless of age. Resolved
    # ones stay for 365 days after resolution, not after creation.
    cutoff = now - timedelta(days=INCIDENT_DAYS)
    active_alert = exists(select(Alert.id).where(
        Alert.incident_id == Incident.id,
        Alert.state.in_(["firing", "acknowledged"]),
    ))
    q = select(Incident.id).where(
        Incident.state == "resolved",
        Incident.resolved_at.is_not(None),
        Incident.resolved_at < cutoff,
        ~active_alert,
    ).order_by(Incident.id).limit(limit)
    if db.bind.dialect.name == "postgresql":
        q = q.with_for_update(skip_locked=True)
    ids = db.scalars(q).all()
    if not ids:
        return 0
    # Explicit dependent-record deletion; no implicit FK cascading or orphans.
    for cls in (Alert, Timeline, Escalation, Notification, Postmortem, StreamEvent):
        db.execute(delete(cls).where(cls.incident_id.in_(ids)))
    db.execute(delete(Incident).where(Incident.id.in_(ids)))
    return len(ids)


def retention(now: datetime | None = None, *, max_events: int = 10000,
              batch_size: int = 1000, max_incidents: int = 1000) -> dict:
    if max_events < 1 or batch_size < 1 or max_incidents < 1:
        raise ValueError("Retention limits must be positive")
    now = _utc(now or utcnow())
    totals = {"eventsArchived": 0, "incidentsPruned": 0, "metricsPurged": 0}
    with SessionLocal.begin() as db:
        if db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(139724, 205)"))
        while totals["eventsArchived"] < max_events:
            count = _archive(db, now, min(batch_size, max_events - totals["eventsArchived"]))
            if not count:
                break
            totals["eventsArchived"] += count
        totals["incidentsPruned"] = _prune_incidents(db, now, max_incidents)
        totals["metricsPurged"] = db.execute(delete(MetricHour).where(
            MetricHour.bucket_at < now - timedelta(days=METRICS_DAYS),
        )).rowcount
        db.execute(delete(Outbox).where(
            Outbox.processed_at.is_not(None),
            Outbox.processed_at < now - timedelta(days=RAW_DAYS),
        ))
        db.execute(delete(StreamEvent).where(
            StreamEvent.created_at < now - timedelta(days=RAW_DAYS),
        ))
        db.execute(delete(UserSession).where(UserSession.expires_at < now))
        db.execute(delete(LoginAttempt).where(
            LoginAttempt.window_started_at < now - timedelta(days=1),
        ))
        db.execute(delete(WorkerStatus).where(
            WorkerStatus.last_seen_at < now - timedelta(days=7),
        ))
    return totals
