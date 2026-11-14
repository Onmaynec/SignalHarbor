"""Supplementary workflows: safe dry-run replay, status, reporting and severity changes."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session as DBSession

from .auth import (
    ROLE_COMMANDER, ROLE_OBSERVER, User, allow, current_user, db_session, require_team,
)
from .engine import aware, emit
from .models import (
    Event, Incident, Postmortem, Rule, Service, SessionLocal, utcnow,
)

router = APIRouter()


def denied(message: str, status: int = 403):
    raise HTTPException(status, message)


@router.get("/status", tags=["status"])
def public_status():
    """Opt-in-only public status: service names and incident state, never payloads or tokens."""
    raw = os.getenv("PUBLIC_STATUS_SERVICE_IDS", "").strip()
    allowlist = {int(x.strip()) for x in raw.split(",") if x.strip().isdigit()}
    if not allowlist:
        return {"status": "not_configured", "services": []}
    with SessionLocal() as db:
        services = db.scalars(select(Service).where(Service.id.in_(allowlist))).all()
        output = []
        for svc in services:
            active = db.scalar(select(func.count(Incident.id)).where(
                Incident.service_id == svc.id, Incident.state != "resolved",
            )) or 0
            output.append({"name": svc.name, "state": "degraded" if active else "operational"})
        return {"status": "degraded" if any(x["state"] != "operational" for x in output)
                else "operational", "services": output}


@router.get("/api/v1/series", tags=["analytics"])
def series(hours: int = 24, user: User = Depends(current_user),
           db: DBSession = Depends(db_session)):
    if hours < 1 or hours > 168:
        denied("hours must be 1..168", 400)
    top = utcnow().replace(minute=0, second=0, microsecond=0)
    cutoff = top - timedelta(hours=hours - 1)
    hour_bucket = func.date_trunc("hour", Event.received_at)
    q = (select(hour_bucket.label("bucket"), func.count(Event.id).label("count"))
         .join(Service, Service.id == Event.service_id)
         .where(Event.received_at >= cutoff)
         .group_by(hour_bucket))
    if user.role != "admin":
        q = q.where(Service.team_id == user.team_id)
    counts = {aware(x.bucket): int(x.count) for x in db.execute(q).all()}
    return {"bucket": "hour", "timezone": "UTC",
            "points": [{"at": (top - timedelta(hours=k)).isoformat(),
                        "count": counts.get(top - timedelta(hours=k), 0)}
                       for k in range(hours - 1, -1, -1)]}


class ReplayEvent(BaseModel):
    timestamp: datetime
    type: str = Field(min_length=1, max_length=40)
    severity: str = Field(default="info", max_length=20)
    labels: dict[str, str] = Field(default_factory=dict)


class ReplayBody(BaseModel):
    ruleId: int
    events: list[ReplayEvent] = Field(default_factory=list, max_length=1000)
    ticks: list[datetime] = Field(default_factory=list, max_length=1000)
    groupValues: dict[str, str] = Field(default_factory=dict)


@router.post("/api/v1/replay", tags=["analytics"])
def replay(body: ReplayBody, user: User = Depends(current_user),
           db: DBSession = Depends(db_session)):
    if user.role == ROLE_OBSERVER:
        denied("Observer cannot inspect detection rules")
    rule = db.get(Rule, body.ruleId)
    if not rule:
        denied("Rule not found", 404)
    require_team(user, rule.team_id)
    if any(x.timestamp.tzinfo is None for x in body.events) or any(
        x.tzinfo is None for x in body.ticks
    ):
        denied("All timestamps must include a timezone", 400)
    if rule.group_labels and any(label not in body.groupValues for label in rule.group_labels):
        denied("All selected label values must be supplied", 400)
    events = sorted(body.events, key=lambda e: aware(e.timestamp))
    points = sorted(set([aware(e.timestamp) for e in events] + [aware(t) for t in body.ticks]))
    if not points:
        return {"ruleId": rule.id, "ruleVersion": rule.version,
                "transitions": [], "samples": [], "notifications": 0, "persistedEvents": 0}
    transitions, samples = [], []
    state = "idle"
    healthy_since = None
    recovered_at = None
    baseline = points[0]
    cutoff_values = {k: str(v) for k, v in body.groupValues.items() if k in rule.group_labels}
    for now in points:
        matched = [
            e for e in events
            if aware(e.timestamp) <= now and
            all(str(e.labels.get(k, "")) == v for k, v in cutoff_values.items())
        ]
        if rule.kind == "heartbeat_missing":
            hearts = [aware(e.timestamp) for e in matched
                      if e.type == "heartbeat"]
            last = max(hearts) if hearts else baseline
            value = max(0.0, (now - last).total_seconds())
            firing = value >= rule.threshold
        else:
            window = [e for e in matched if aware(e.timestamp) >=
                      now - timedelta(seconds=rule.window_seconds)]
            errors = sum(e.type == "error" or e.severity == "error" for e in window)
            if rule.kind == "count_error":
                value = float(errors)
            else:
                value = (100.0 * errors / len(window)) if window else 0.0
            firing = value > rule.threshold
        if firing:
            healthy_since = None
            if state in ("idle", "recovered"):
                if not recovered_at or (now - recovered_at).total_seconds() >= rule.cooldown_seconds:
                    state = "firing"
                    transitions.append({"at": now.isoformat(), "state": state, "value": value})
        elif state == "firing":
            if healthy_since is None:
                healthy_since = now
            elif (now - healthy_since).total_seconds() >= rule.recovery_seconds:
                state = "recovered"
                recovered_at = now
                transitions.append({"at": now.isoformat(), "state": state, "value": value})
        samples.append({"at": now.isoformat(), "value": round(value, 3), "state": state})
    return {"ruleId": rule.id, "ruleVersion": rule.version,
            "transitions": transitions, "samples": samples,
            "notifications": 0, "persistedEvents": 0,
            "note": "Dry-run: no database writes, incidents or notifications"}


class SeverityBody(BaseModel):
    severity: Literal["low", "medium", "high", "critical"]
    expectedVersion: int = Field(ge=1)


@router.post("/api/v1/incidents/{incident_id}/severity", tags=["incidents"])
def severity(incident_id: int, body: SeverityBody,
             user: User = Depends(allow(ROLE_COMMANDER)),
             db: DBSession = Depends(db_session)):
    incident = db.get(Incident, incident_id)
    if not incident:
        denied("Incident not found", 404)
    require_team(user, incident.team_id)
    if incident.state == "resolved":
        denied("Cannot change resolved incident", 409)
    if incident.version != body.expectedVersion:
        denied("Concurrent incident update", 409)
    if incident.severity == body.severity:
        return {"id": incident.id, "severity": incident.severity, "version": incident.version}
    old = incident.severity
    changed = db.execute(update(Incident).where(
        Incident.id == incident_id, Incident.state != "resolved",
        Incident.version == body.expectedVersion,
    ).values(severity=body.severity, version=Incident.version + 1)).rowcount
    if not changed:
        denied("Concurrent incident update", 409)
    db.refresh(incident)
    emit(db, incident, "severity_changed", {"from": old, "to": body.severity}, actor_id=user.id)
    db.commit()
    return {"id": incident.id, "severity": incident.severity, "version": incident.version}


@router.get("/api/v1/incidents/{incident_id}/postmortem.md", tags=["incidents"])
def postmortem_markdown(incident_id: int, user: User = Depends(current_user),
                        db: DBSession = Depends(db_session)):
    if user.role == ROLE_OBSERVER:
        denied("Observer cannot access postmortem")
    incident = db.get(Incident, incident_id)
    if not incident:
        denied("Incident not found", 404)
    require_team(user, incident.team_id)
    post = db.scalar(select(Postmortem).where(Postmortem.incident_id == incident.id))
    if not post:
        denied("Postmortem not found", 404)
    lines = [
        "# Postmortem INC-" + str(incident.id),
        "",
        "**Service:** " + str(incident.service_id),
        "**Severity:** " + incident.severity,
        "**State:** " + incident.state,
        "",
        "## Impact",
        post.impact,
        "",
        "## Root cause",
        post.root_cause,
        "",
        "## Action items",
    ]
    for index, item in enumerate(post.action_items, 1):
        lines.append(str(index) + ". " + str(item.get("text", "Untitled")) +
                     " — owner #" + str(item.get("ownerId", "unassigned")))
    return PlainTextResponse(
        "\n".join(lines) + "\n", media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="INC-' +
                 str(incident.id) + '-postmortem.md"'},
    )
