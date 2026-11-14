"""Idempotent rule processing and incident orchestration.

The worker processes committed outbox rows in one DB transaction. A crash before commit
replays the row; a crash after commit finds it already processed. Alert fingerprints,
incident row locks and uniqueness constraints make effects repeat-safe.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .models import (
    Alert, Environment, Escalation, Event, Incident, Maintenance, Notification,
    Outbox, Rule, Schedule, Service, StreamEvent, Timeline, utcnow,
)


def aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def fingerprint(rule: Rule, service_id: int, env_id: int, values: dict) -> str:
    raw = [service_id, env_id, rule.id, sorted(values.items())]
    return hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()


def in_maintenance(db: Session, env_id: int, now: datetime) -> bool:
    return db.scalar(select(Maintenance.id).where(
        Maintenance.environment_id == env_id,
        Maintenance.starts_at <= now, Maintenance.ends_at > now,
    ).limit(1)) is not None


def emit(db: Session, incident: Incident, kind: str, data: dict, actor_id: int | None = None,
         at: datetime | None = None):
    now = at or utcnow()
    db.add(Timeline(incident_id=incident.id, kind=kind, data=data, actor_id=actor_id, created_at=now))
    db.add(StreamEvent(
        team_id=incident.team_id, kind=kind, incident_id=incident.id,
        content={"incidentId": incident.id, "state": incident.state, "severity": incident.severity},
        created_at=now,
    ))


def who_is_oncall(db: Session, team_id: int, now: datetime) -> tuple[int | None, int | None]:
    schedule = db.scalar(select(Schedule).where(Schedule.team_id == team_id))
    if not schedule:
        return None, None
    elapsed = max(0, (aware(now) - aware(schedule.starts_at)).total_seconds())
    turn = int(elapsed // (60 * schedule.rotation_minutes))
    if turn % 2:
        return schedule.backup_id, schedule.primary_id
    return schedule.primary_id, schedule.backup_id


def notify(db: Session, incident: Incident, level: int, now: datetime):
    if in_maintenance(db, incident.environment_id, now):
        return
    primary, backup = who_is_oncall(db, incident.team_id, now)
    recipient = primary if level == 1 else backup
    if recipient is None:
        return
    exists = db.scalar(select(Notification.id).where(
        Notification.incident_id == incident.id,
        Notification.level == level, Notification.recipient_id == recipient,
    ))
    if exists is None:
        db.add(Notification(incident_id=incident.id, level=level, recipient_id=recipient, created_at=now))


def measure(db: Session, rule: Rule, service_id: int, env_id: int,
            group_values: dict, now: datetime) -> tuple[float, int]:
    cutoff = now - timedelta(seconds=rule.window_seconds)
    conditions = [
        Event.service_id == service_id, Event.environment_id == env_id,
        Event.occurred_at >= cutoff, Event.occurred_at <= now,
        Event.late.is_(False),
    ]
    for key, value in group_values.items():
        conditions.append(Event.labels[key].as_string() == str(value))
    count = db.scalar(select(func.count(Event.id)).where(*conditions)) or 0
    errors = db.scalar(select(func.count(Event.id)).where(
        *conditions, or_(Event.kind == "error", Event.severity == "error"),
    )) or 0
    if rule.kind == "count_error":
        return float(errors), int(errors)
    if rule.kind == "error_rate":
        return (100.0 * errors / count if count else 0.0), int(errors)
    if rule.kind == "heartbeat_missing":
        env = db.get(Environment, env_id)
        last = aware(env.last_heartbeat_at) if env and env.last_heartbeat_at else None
        baseline = last or (aware(env.created_at) if env else now)
        return max(0.0, (now - baseline).total_seconds()), 1
    return 0.0, 0


def ensure_incident(db: Session, rule: Rule, service_id: int, env_id: int,
                    now: datetime, alert: Alert) -> Incident:
    incident = db.scalar(select(Incident).where(
        Incident.team_id == rule.team_id,
        Incident.service_id == service_id,
        Incident.environment_id == env_id,
        Incident.state != "resolved",
    ).order_by(Incident.id).limit(1).with_for_update())
    if incident is None:
        incident = Incident(
            team_id=rule.team_id, service_id=service_id, environment_id=env_id,
            summary=rule.name, severity=rule.severity, state="open", created_at=now,
        )
        db.add(incident)
        db.flush()
        emit(db, incident, "created", {"ruleId": rule.id, "alertId": alert.id}, at=now)
        notify(db, incident, 1, now)
    alert.incident_id = incident.id
    return incident


def evaluate(db: Session, rule: Rule, service_id: int, env_id: int,
             values: dict, now: datetime):
    if not rule.enabled:
        return
    fp = fingerprint(rule, service_id, env_id, values)
    value, occurrences = measure(db, rule, service_id, env_id, values, now)
    firing = (value >= rule.threshold) if rule.kind == "heartbeat_missing" else (value > rule.threshold)
    alert = db.scalar(select(Alert).where(Alert.fingerprint == fp).with_for_update())
    if firing:
        if alert:
            alert.value = value
            alert.count = occurrences
            alert.last_seen_at = now
            alert.healthy_since = None
            if alert.state in ("recovered", "resolved"):
                if alert.recovered_at and (now - aware(alert.recovered_at)).total_seconds() < rule.cooldown_seconds:
                    return
                alert.state = "firing"
                alert.fired_at = now
                alert.recovered_at = None
                alert.rule_version = rule.version
                incident = ensure_incident(db, rule, service_id, env_id, now, alert)
                emit(db, incident, "refired", {"fingerprint": fp, "value": value}, at=now)
        else:
            alert = Alert(
                fingerprint=fp, rule_id=rule.id, rule_version=rule.version,
                service_id=service_id, environment_id=env_id, state="firing",
                value=value, count=occurrences, fired_at=now, last_seen_at=now,
                label_values=values,
            )
            db.add(alert)
            db.flush()
            incident = ensure_incident(db, rule, service_id, env_id, now, alert)
            emit(db, incident, "alert_fired", {"fingerprint": fp, "value": value}, at=now)
        alert.suppressed = in_maintenance(db, env_id, now)
    elif alert and alert.state in ("firing", "acknowledged"):
        if alert.healthy_since is None:
            alert.healthy_since = now
        elif (now - aware(alert.healthy_since)).total_seconds() >= rule.recovery_seconds:
            alert.state = "recovered"
            alert.recovered_at = now
            incident = db.get(Incident, alert.incident_id) if alert.incident_id else None
            if incident:
                emit(db, incident, "alert_recovered", {"fingerprint": fp}, at=now)


def process_event(db: Session, event: Event, now: datetime | None = None):
    if event.late:
        return
    service = db.get(Service, event.service_id)
    if not service:
        return
    now = now or utcnow()
    rules = db.scalars(select(Rule).where(
        Rule.team_id == service.team_id, Rule.enabled.is_(True),
        or_(Rule.service_id.is_(None), Rule.service_id == event.service_id),
        or_(Rule.environment_id.is_(None), Rule.environment_id == event.environment_id),
        Rule.kind.in_(["count_error", "error_rate"]),
    )).all()
    for rule in rules:
        values = {name: str(event.labels.get(name, "")) for name in rule.group_labels}
        evaluate(db, rule, event.service_id, event.environment_id, values, now)


def drain_outbox(batch_size: int = 100) -> int:
    from .models import SessionLocal, engine
    with SessionLocal.begin() as db:
        query = select(Outbox).where(Outbox.processed_at.is_(None)).order_by(Outbox.id).limit(batch_size)
        if engine.dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        rows = db.scalars(query).all()
        for row in rows:
            if row.kind == "ingest":
                event = db.get(Event, row.subject_id)
                if event:
                    process_event(db, event)
            row.processed_at = utcnow()
            row.attempts += 1
        return len(rows)


def scan_health(now: datetime | None = None):
    from .models import SessionLocal
    now = now or utcnow()
    with SessionLocal.begin() as db:
        for rule in db.scalars(select(Rule).where(Rule.enabled.is_(True))).all():
            if rule.kind == "heartbeat_missing":
                envs = db.scalars(select(Environment).join(Service).where(
                    Service.team_id == rule.team_id,
                    *( [Environment.service_id == rule.service_id] if rule.service_id else []),
                    *( [Environment.id == rule.environment_id] if rule.environment_id else []),
                )).all()
                for env in envs:
                    evaluate(db, rule, env.service_id, env.id, {}, now)
            else:
                # Continue evaluating active alerts even when new events stop arriving.
                alerts = db.scalars(select(Alert).where(
                    Alert.rule_id == rule.id, Alert.state.in_(["firing", "acknowledged"]),
                )).all()
                for alert in alerts:
                    evaluate(db, rule, alert.service_id, alert.environment_id, alert.label_values, now)


def scan_escalations(now: datetime | None = None, delay_seconds: int = 300):
    from .models import SessionLocal
    now = now or utcnow()
    with SessionLocal.begin() as db:
        incidents = db.scalars(select(Incident).where(
            Incident.state == "open", Incident.created_at <= now - timedelta(seconds=delay_seconds),
        ).with_for_update()).all()
        for incident in incidents:
            exists = db.scalar(select(Escalation.id).where(
                Escalation.incident_id == incident.id, Escalation.level == 2,
            ))
            if exists is None:
                db.add(Escalation(incident_id=incident.id, level=2, created_at=now))
                emit(db, incident, "escalated", {"level": 2}, at=now)
                notify(db, incident, 2, now)


def retention(now: datetime | None = None):
    from sqlalchemy import delete
    from .models import SessionLocal, StreamEvent
    now = now or utcnow()
    with SessionLocal.begin() as db:
        # Ingest idempotency is retained for at least 30 days, not just 7.
        db.execute(delete(Outbox).where(
            Outbox.processed_at.is_not(None),
            Outbox.processed_at < now - timedelta(days=30),
        ))
        db.execute(delete(Event).where(Event.received_at < now - timedelta(days=30)))
        db.execute(delete(StreamEvent).where(StreamEvent.created_at < now - timedelta(days=30)))
