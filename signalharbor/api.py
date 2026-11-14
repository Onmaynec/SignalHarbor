"""Versioned HTTP API. Authentication, team scoping and durable ingest are mandatory."""
from __future__ import annotations

import asyncio
import base64
import json
import math
import os
import secrets
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import and_, delete, exists, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from .auth import (
    ROLE_ADMIN, ROLE_COMMANDER, ROLE_ENGINEER, ROLE_OBSERVER, ROLE_ONCALL,
    ROLES, allow, check_password, create_login, current_user, db_session,
    hash_password, hash_token, require_team, session_cookie, user_from_request,
)
from .engine import aware, emit
from .login_security import begin_login, failed_login, successful_login
from .mfa import enable as enable_mfa, enrollment as create_mfa_enrollment
from .mfa import get_credential, verify_factor
from .quota import reserve_quota
from .models import (
    Alert, Environment, Event, IngestKey, Incident, Maintenance, Notification,
    Outbox, Postmortem, Rule, RuleRevision, Schedule, Service, Session, SessionLocal,
    MfaCredential, MfaEnrollment, StreamEvent, Team, Timeline, User, WorkerStatus, utcnow,
)

app = FastAPI(title="SignalHarbor", version="0.6.0",
              description="Monitoring, alert correlation and incident response API")
app.mount("/static", StaticFiles(directory="signalharbor/static"), name="static")

MAX_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "1048576"))
QUOTA = int(os.getenv("INGEST_RATE_PER_MIN", "2400"))
_buckets: OrderedDict[int, tuple[float, int]] = OrderedDict()
_counters = {"ingestBatches": 0, "ingestEvents": 0, "rejected429": 0}


def fail(status: int, message: str):
    raise HTTPException(status, message)


def iso(dt):
    return aware(dt).isoformat() if dt else None


def service_json(s: Service):
    return {"id": s.id, "name": s.name, "teamId": s.team_id}


def incident_json(i: Incident):
    return {
        "id": i.id, "teamId": i.team_id, "serviceId": i.service_id,
        "environmentId": i.environment_id, "summary": i.summary, "severity": i.severity,
        "state": i.state, "ownerId": i.owner_id, "version": i.version,
        "createdAt": iso(i.created_at), "ackedAt": iso(i.acked_at),
        "resolvedAt": iso(i.resolved_at), "resolution": i.resolution,
    }


def status_json(i: Incident):
    return {"id": i.id, "serviceId": i.service_id, "environmentId": i.environment_id,
            "severity": i.severity, "state": i.state, "createdAt": iso(i.created_at),
            "resolvedAt": iso(i.resolved_at), "summary": "Service status change",
            "ownerId": None, "resolution": None, "teamId": i.team_id, "version": i.version,
            "ackedAt": iso(i.acked_at)}


def alert_json(a: Alert):
    return {
        "id": a.id, "fingerprint": a.fingerprint, "state": a.state, "count": a.count,
        "value": a.value, "serviceId": a.service_id, "environmentId": a.environment_id,
        "ruleId": a.rule_id, "ruleVersion": a.rule_version, "incidentId": a.incident_id,
        "suppressed": a.suppressed, "firedAt": iso(a.fired_at),
    }


def admin_or_team(db, user, service_id):
    svc = db.get(Service, service_id)
    if not svc:
        fail(404, "Service not found")
    require_team(user, svc.team_id)
    return svc


def visible_team_ids(user):
    return None if user.role == ROLE_ADMIN else [user.team_id]


@app.middleware("http")
async def envelope(request: Request, call_next):
    request.state.request_id = request.headers.get("x-request-id", str(uuid.uuid4()))[:80]
    if request.method in {"POST", "PATCH", "PUT", "DELETE"}:
        # Browsers must prove same-origin intent for state changes via session cookies.
        if request.url.path.startswith("/api/") and request.url.path != "/api/v1/login":
            if request.cookies.get("signalharbor_session"):
                csrf = request.cookies.get("signalharbor_csrf")
                if not csrf or not secrets.compare_digest(
                    request.headers.get("x-csrf-token", ""), csrf
                ):
                    return JSONResponse(
                        status_code=403, content={"code": "csrf", "message": "Invalid CSRF token",
                                                  "requestId": request.state.request_id, "details": None}
                    )
        if request.url.path.startswith(("/api/", "/ingest/")):
            size = request.headers.get("content-length")
            if size and size.isdecimal() and int(size) > MAX_BYTES:
                return JSONResponse(status_code=413, content={
                    "code": "too_large", "message": "Request exceeds size limit",
                    "requestId": request.state.request_id, "details": None,
                })
            chunks = bytearray()
            async for part in request.stream():
                if len(chunks) + len(part) > MAX_BYTES:
                    return JSONResponse(status_code=413, content={
                        "code": "too_large", "message": "Request exceeds size limit",
                        "requestId": request.state.request_id, "details": None,
                    })
                chunks.extend(part)
            request._body = bytes(chunks)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith(("/api/", "/stream/")):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(HTTPException)
async def http_error(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": str(exc.status_code), "message": str(exc.detail),
                 "requestId": getattr(request.state, "request_id", ""), "details": None},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def invalid_body(request, exc):
    errors = [{"loc": list(x["loc"]), "message": x["msg"]} for x in exc.errors()]
    return JSONResponse(
        status_code=400,
        content={"code": "validation", "message": "Invalid input",
                 "requestId": getattr(request.state, "request_id", ""), "details": errors},
    )


@app.get("/", include_in_schema=False)
def index():
    return FileResponse("signalharbor/static/index.html")


@app.get("/health/live")
def live():
    return {"status": "ok"}


@app.get("/health/ready")
def ready(db: DBSession = Depends(db_session)):
    db.scalar(select(func.count(Team.id)))
    return {"status": "ok", "database": "ready"}


class LoginBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)
    mfaCode: str | None = Field(default=None, max_length=64)


# The same password-hashing work is performed for nonexistent/disabled users.
_DUMMY_LOGIN_HASH = hash_password("account-does-not-exist", salt="00" * 16)


@app.post("/api/v1/login")
def login(body: LoginBody, response: Response, db: DBSession = Depends(db_session)):
    email = body.email.strip().lower()
    if not email:
        fail(400, "Invalid input")
    attempt, key = begin_login(db, email)
    user = db.scalar(select(User).where(User.email == email, User.enabled.is_(True)))
    stored_hash = user.password_hash if user else _DUMMY_LOGIN_HASH
    password_valid = check_password(body.password, stored_hash)
    if not user or not password_valid:
        failed_login(db, attempt, key)
    credential = get_credential(db, user.id)
    if credential is not None:
        if not body.mfaCode:
            fail(401, "MFA code required")
        if not verify_factor(credential, body.mfaCode):
            failed_login(db, attempt, key)
    successful_login(db, attempt)
    token = create_login(db, user)
    session_cookie(response, token)
    response.set_cookie(
        "signalharbor_csrf", hash_token(token)[:32], max_age=43200,
        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
        samesite="strict", path="/",
    )
    return {"id": user.id, "email": user.email, "role": user.role, "teamId": user.team_id}


class MfaSetupBody(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class MfaCodeBody(BaseModel):
    code: str = Field(min_length=6, max_length=64)


class MfaDisableBody(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    code: str = Field(min_length=6, max_length=64)


@app.get("/api/v1/mfa/status")
def mfa_status(user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    return {
        "enabled": db.get(MfaCredential, user.id) is not None,
        "pending": db.get(MfaEnrollment, user.id) is not None,
    }


@app.post("/api/v1/mfa/setup")
def mfa_setup(body: MfaSetupBody, user: User = Depends(current_user),
              db: DBSession = Depends(db_session)):
    if not check_password(body.password, user.password_hash):
        fail(403, "Invalid credentials")
    return create_mfa_enrollment(db, user.id, user.email)


@app.post("/api/v1/mfa/enable")
def mfa_enable(body: MfaCodeBody, request: Request,
               user: User = Depends(current_user),
               db: DBSession = Depends(db_session)):
    codes = enable_mfa(db, user.id, body.code)
    # Existing sessions from other devices were authenticated without MFA.
    # Invalidate them; preserve this one for account recovery/setup.
    current_hash = hash_token(request.cookies["signalharbor_session"])
    db.execute(delete(Session).where(
        Session.user_id == user.id, Session.token_hash != current_hash,
    ))
    db.commit()
    return {"enabled": True, "recoveryCodes": codes,
            "note": "Save recovery codes now; they cannot be retrieved later."}


@app.post("/api/v1/mfa/disable")
def mfa_disable(body: MfaDisableBody, response: Response,
                user: User = Depends(current_user),
                db: DBSession = Depends(db_session)):
    if not check_password(body.password, user.password_hash):
        fail(403, "Invalid credentials")
    credential = get_credential(db, user.id)
    if credential is None:
        fail(409, "MFA is not enabled")
    if not verify_factor(credential, body.code):
        fail(403, "Invalid authenticator code")
    db.delete(credential)
    db.execute(delete(Session).where(Session.user_id == user.id))
    db.commit()
    response.delete_cookie("signalharbor_session")
    response.delete_cookie("signalharbor_csrf")
    return {"enabled": False, "reauthenticate": True}


@app.post("/api/v1/logout")
def logout(request: Request, response: Response, user: User = Depends(current_user),
           db: DBSession = Depends(db_session)):
    token = request.cookies.get("signalharbor_session")
    if token:
        s = db.scalar(select(Session).where(Session.token_hash == hash_token(token)))
        if s:
            db.delete(s)
            db.commit()
    response.delete_cookie("signalharbor_session")
    response.delete_cookie("signalharbor_csrf")
    return {"ok": True}


@app.get("/api/v1/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "role": user.role, "teamId": user.team_id}


class TeamBody(BaseModel):
    name: str = Field(min_length=2, max_length=120)


@app.get("/api/v1/teams")
def teams(user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    rows = db.scalars(select(Team).where(
        Team.id == user.team_id if user.role != ROLE_ADMIN else True
    ).order_by(Team.name)).all()
    return [{"id": t.id, "name": t.name} for t in rows]


@app.post("/api/v1/teams", status_code=201)
def create_team(body: TeamBody, user: User = Depends(allow(ROLE_ADMIN)),
                db: DBSession = Depends(db_session)):
    team = Team(name=body.name)
    db.add(team)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        fail(409, "Team already exists")
    return {"id": team.id, "name": team.name}


class UserBody(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128)
    role: str
    teamId: int | None = None

    @field_validator("role")
    @classmethod
    def valid_role(cls, value):
        if value not in ROLES:
            raise ValueError("Unknown role")
        return value


@app.post("/api/v1/users", status_code=201)
def create_user(body: UserBody, user: User = Depends(allow(ROLE_ADMIN)),
                db: DBSession = Depends(db_session)):
    if body.role != ROLE_ADMIN and (not body.teamId or not db.get(Team, body.teamId)):
        fail(400, "Existing team required")
    u = User(email=body.email.lower(), password_hash=hash_password(body.password),
             role=body.role, team_id=body.teamId)
    db.add(u)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        fail(409, "User already exists")
    return {"id": u.id, "email": u.email, "role": u.role, "teamId": u.team_id}


@app.get("/api/v1/users")
def users(user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    if user.role == ROLE_OBSERVER:
        fail(403, "Observer can access status information only")
    q = select(User).where(User.enabled.is_(True))
    if user.role != ROLE_ADMIN:
        q = q.where(User.team_id == user.team_id)
    return [{"id": u.id, "email": u.email, "role": u.role, "teamId": u.team_id}
            for u in db.scalars(q).all()]


class ServiceBody(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    teamId: int


@app.post("/api/v1/services", status_code=201)
def create_service(body: ServiceBody, user: User = Depends(allow(ROLE_ADMIN)),
                   db: DBSession = Depends(db_session)):
    if not db.get(Team, body.teamId):
        fail(404, "Team not found")
    s = Service(name=body.name, team_id=body.teamId)
    db.add(s)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        fail(409, "Service already exists")
    return service_json(s)


@app.get("/api/v1/services")
def services(user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    q = select(Service).order_by(Service.name)
    if user.role != ROLE_ADMIN:
        q = q.where(Service.team_id == user.team_id)
    return [service_json(s) for s in db.scalars(q).all()]


class EnvBody(BaseModel):
    name: str = Field(min_length=2, max_length=60)


@app.post("/api/v1/services/{service_id}/environments", status_code=201)
def create_env(service_id: int, body: EnvBody,
               user: User = Depends(allow(ROLE_ADMIN)), db: DBSession = Depends(db_session)):
    admin_or_team(db, user, service_id)
    env = Environment(service_id=service_id, name=body.name, last_heartbeat_at=utcnow())
    db.add(env)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        fail(409, "Environment already exists")
    return {"id": env.id, "serviceId": service_id, "name": env.name}


@app.get("/api/v1/services/{service_id}/environments")
def environments(service_id: int, user: User = Depends(current_user),
                 db: DBSession = Depends(db_session)):
    admin_or_team(db, user, service_id)
    envs = db.scalars(select(Environment).where(Environment.service_id == service_id)).all()
    return [{"id": e.id, "name": e.name, "lastHeartbeatAt": iso(e.last_heartbeat_at)} for e in envs]


class KeyBody(BaseModel):
    environmentId: int
    name: str = Field(min_length=2, max_length=80)


@app.post("/api/v1/ingest-keys", status_code=201)
def create_key(body: KeyBody, user: User = Depends(allow(ROLE_ADMIN)),
               db: DBSession = Depends(db_session)):
    env = db.get(Environment, body.environmentId)
    if not env:
        fail(404, "Environment not found")
    admin_or_team(db, user, env.service_id)
    raw = "sh_" + secrets.token_urlsafe(35)
    key = IngestKey(environment_id=env.id, token_hash=hash_token(raw), name=body.name)
    db.add(key)
    db.commit()
    return {"id": key.id, "environmentId": env.id, "key": raw,
            "warning": "Shown only once. Store safely."}


@app.get("/api/v1/ingest-keys")
def keys(user: User = Depends(allow(ROLE_ADMIN)), db: DBSession = Depends(db_session)):
    return [{"id": k.id, "name": k.name, "environmentId": k.environment_id, "revoked": k.revoked}
            for k in db.scalars(select(IngestKey)).all()]


@app.post("/api/v1/ingest-keys/{key_id}/revoke")
def revoke_key(key_id: int, user: User = Depends(allow(ROLE_ADMIN)),
               db: DBSession = Depends(db_session)):
    key = db.get(IngestKey, key_id)
    if not key:
        fail(404, "Key not found")
    key.revoked = True
    db.commit()
    return {"ok": True}


class IncomingEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    eventId: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_:\-.]+$")
    serviceId: int
    timestamp: datetime
    severity: Literal["debug", "info", "warning", "error", "critical"]
    type: str = Field(min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9_-]+$")
    labels: dict[str, str] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("labels")
    @classmethod
    def safe_labels(cls, val):
        if len(val) > 12 or any(len(k) > 60 or len(v) > 120 for k, v in val.items()):
            raise ValueError("Too many or too large labels")
        return val


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schemaVersion: Literal[1]
    events: list[IncomingEvent] = Field(min_length=1, max_length=500)


def check_depth(value, depth=0):
    if depth > 8:
        fail(400, "Payload nesting too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            if len(str(key)) > 120:
                fail(400, "Payload key too long")
            check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            check_depth(item, depth + 1)


def ingest_auth(request: Request, db: DBSession) -> IngestKey:
    raw = request.headers.get("x-ingest-key", "")
    if not raw or len(raw) > 150:
        fail(401, "Invalid ingest key")
    key = db.scalar(select(IngestKey).where(
        IngestKey.token_hash == hash_token(raw), IngestKey.revoked.is_(False),
    ))
    if not key:
        fail(401, "Invalid ingest key")
    return key


def quota_check(db: DBSession, key_id: int, units: int):
    if db.bind.dialect.name == "postgresql":
        try:
            reserve_quota(db, key_id, units, QUOTA)
        except HTTPException as exc:
            if exc.status_code == 429:
                _counters["rejected429"] += 1
            raise
        return
    now = time.monotonic()
    if key_id in _buckets:
        start, used = _buckets[key_id]
        if now - start >= 60:
            start, used = now, 0
        _buckets.move_to_end(key_id)
    else:
        start, used = now, 0
    while len(_buckets) >= 4096 and key_id not in _buckets:
        _buckets.popitem(last=False)
    if used + units > QUOTA:
        _counters["rejected429"] += 1
        remaining = max(1, int(60 - (now - start)))
        raise HTTPException(status_code=429, detail="Ingest rate exceeded",
                            headers={"Retry-After": str(remaining)})
    _buckets[key_id] = (start, used + units)


def persist(db: DBSession, key: IngestKey, entries: list[IncomingEvent]):
    env = db.get(Environment, key.environment_id)
    now = utcnow()
    # One multi-row PostgreSQL INSERT instead of hundreds of SAVEPOINT round trips.
    # The RETURNING set is the only source of new IDs, so duplicates have no outbox effect.
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        values = []
        for item in entries:
            if item.serviceId != env.service_id:
                fail(403, "Ingest key cannot write this service")
            if item.timestamp.tzinfo is None:
                fail(400, "timestamp must contain timezone")
            occurred = item.timestamp.astimezone(timezone.utc)
            if occurred > now + timedelta(minutes=2) or occurred < now - timedelta(days=30):
                fail(400, "Timestamp outside permitted range")
            check_depth(item.payload)
            check_depth(item.labels)
            values.append({
                "key_id": key.id, "event_id": item.eventId,
                "service_id": env.service_id, "environment_id": env.id,
                "occurred_at": occurred, "received_at": now,
                "severity": item.severity, "kind": item.type,
                "payload": item.payload, "labels": item.labels,
                "late": (now - occurred) > timedelta(minutes=2),
            })
        stmt = pg_insert(Event).values(values).on_conflict_do_nothing(
            index_elements=["key_id", "event_id"],
        ).returning(Event.id, Event.kind, Event.late, Event.occurred_at)
        inserted_rows = db.execute(stmt).all()
        outbox = [{"kind": "ingest", "subject_id": record.id}
                  for record in inserted_rows
                  if record.kind != "heartbeat" and not record.late]
        if outbox:
            db.execute(pg_insert(Outbox).values(outbox).on_conflict_do_nothing(
                index_elements=["kind", "subject_id"],
            ))
        latest_pulse = max((aware(r.occurred_at) for r in inserted_rows
                            if r.kind == "heartbeat"), default=None)
        if latest_pulse:
            db.execute(update(Environment).where(
                Environment.id == env.id,
                or_(Environment.last_heartbeat_at.is_(None),
                    Environment.last_heartbeat_at < latest_pulse),
            ).values(last_heartbeat_at=latest_pulse))
        db.commit()
        _counters["ingestBatches"] += 1
        _counters["ingestEvents"] += len(inserted_rows)
        return {"accepted": len(inserted_rows),
                "duplicates": len(entries) - len(inserted_rows), "schemaVersion": 1}

    inserted = 0
    duplicates = 0
    for item in entries:
        if item.serviceId != env.service_id:
            fail(403, "Ingest key cannot write this service")
        if item.timestamp.tzinfo is None:
            fail(400, "timestamp must contain timezone")
        occurred = item.timestamp.astimezone(timezone.utc)
        if occurred > now + timedelta(minutes=2) or occurred < now - timedelta(days=30):
            fail(400, "Timestamp outside permitted range")
        check_depth(item.payload)
        check_depth(item.labels)
        event = Event(
            key_id=key.id, event_id=item.eventId, service_id=env.service_id,
            environment_id=env.id, occurred_at=occurred, received_at=now,
            severity=item.severity, kind=item.type, payload=item.payload,
            labels=item.labels, late=(now - occurred) > timedelta(minutes=2),
        )
        try:
            with db.begin_nested():
                db.add(event)
                db.flush()
        except IntegrityError:
            duplicates += 1
            continue
        inserted += 1
        if item.type == "heartbeat":
            if env.last_heartbeat_at is None or aware(env.last_heartbeat_at) < occurred:
                env.last_heartbeat_at = occurred
        elif not event.late:
            db.add(Outbox(kind="ingest", subject_id=event.id))
    db.commit()  # Only after durable DB commit can HTTP success be returned.
    _counters["ingestBatches"] += 1
    _counters["ingestEvents"] += inserted
    return {"accepted": inserted, "duplicates": duplicates, "schemaVersion": 1}


@app.post("/ingest/v1/events")
def ingest(batch: EventBatch, request: Request, db: DBSession = Depends(db_session)):
    key = ingest_auth(request, db)
    quota_check(db, key.id, len(batch.events))
    return persist(db, key, batch.events)


class HeartbeatBody(BaseModel):
    schemaVersion: Literal[1]
    eventId: str = Field(min_length=1, max_length=100)
    serviceId: int
    timestamp: datetime


@app.post("/ingest/v1/heartbeat")
def heartbeat(body: HeartbeatBody, request: Request, db: DBSession = Depends(db_session)):
    key = ingest_auth(request, db)
    quota_check(db, key.id, 1)
    return persist(db, key, [IncomingEvent(
        eventId=body.eventId, serviceId=body.serviceId, timestamp=body.timestamp,
        severity="info", type="heartbeat",
    )])


class RuleBody(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    teamId: int
    serviceId: int | None = None
    environmentId: int | None = None
    kind: Literal["count_error", "error_rate", "heartbeat_missing"]
    windowSeconds: int = Field(default=300, ge=10, le=86400)
    threshold: float = Field(default=20, ge=0)
    cooldownSeconds: int = Field(default=300, ge=0, le=86400)
    recoverySeconds: int = Field(default=180, ge=10, le=86400)
    severity: Literal["low", "medium", "high", "critical"] = "high"
    groupLabels: list[str] = Field(default_factory=list, max_length=5)
    enabled: bool = True


def serialize_rule(r):
    return {
        "id": r.id, "name": r.name, "teamId": r.team_id, "serviceId": r.service_id,
        "environmentId": r.environment_id, "kind": r.kind, "version": r.version,
        "windowSeconds": r.window_seconds, "threshold": r.threshold,
        "cooldownSeconds": r.cooldown_seconds, "recoverySeconds": r.recovery_seconds,
        "severity": r.severity, "groupLabels": r.group_labels, "enabled": r.enabled,
    }


def set_rule(r, body):
    r.name = body.name
    r.team_id = body.teamId
    r.service_id = body.serviceId
    r.environment_id = body.environmentId
    r.kind = body.kind
    r.window_seconds = body.windowSeconds
    r.threshold = body.threshold
    r.cooldown_seconds = body.cooldownSeconds
    r.recovery_seconds = body.recoverySeconds
    r.severity = body.severity
    r.group_labels = body.groupLabels
    r.enabled = body.enabled


def validate_rule(db, body):
    if not db.get(Team, body.teamId):
        fail(404, "Team not found")
    if body.serviceId:
        svc = db.get(Service, body.serviceId)
        if not svc or svc.team_id != body.teamId:
            fail(400, "Service and team do not match")
    if body.environmentId:
        env = db.get(Environment, body.environmentId)
        if not env or (body.serviceId and env.service_id != body.serviceId):
            fail(400, "Environment and service do not match")
        svc = db.get(Service, env.service_id)
        if svc.team_id != body.teamId:
            fail(400, "Environment and team do not match")
    if body.kind == "error_rate" and body.threshold > 100:
        fail(400, "Error-rate threshold must be <= 100")


@app.post("/api/v1/alert-rules", status_code=201)
def create_rule(body: RuleBody, user: User = Depends(allow(ROLE_ADMIN)),
                db: DBSession = Depends(db_session)):
    validate_rule(db, body)
    rule = Rule()
    set_rule(rule, body)
    db.add(rule)
    db.flush()
    db.add(RuleRevision(rule_id=rule.id, version=1, configuration=body.model_dump(),
                        changed_by=user.id))
    db.commit()
    return serialize_rule(rule)


@app.put("/api/v1/alert-rules/{rule_id}")
def edit_rule(rule_id: int, body: RuleBody, expectedVersion: int,
              user: User = Depends(allow(ROLE_ADMIN)), db: DBSession = Depends(db_session)):
    validate_rule(db, body)
    rule = db.scalar(select(Rule).where(Rule.id == rule_id).with_for_update())
    if not rule:
        fail(404, "Rule not found")
    if rule.version != expectedVersion:
        fail(409, "Rule version changed")
    rule.version += 1
    set_rule(rule, body)
    db.add(RuleRevision(rule_id=rule.id, version=rule.version,
                        configuration=body.model_dump(), changed_by=user.id))
    db.commit()
    return serialize_rule(rule)


@app.get("/api/v1/alert-rules")
def rules(user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    if user.role == ROLE_OBSERVER:
        fail(403, "Observer can access status information only")
    q = select(Rule).order_by(Rule.id)
    if user.role != ROLE_ADMIN:
        q = q.where(Rule.team_id == user.team_id)
    return [serialize_rule(r) for r in db.scalars(q).all()]


class MaintenanceBody(BaseModel):
    environmentId: int
    startsAt: datetime
    endsAt: datetime
    reason: str = Field(min_length=3, max_length=200)


@app.post("/api/v1/maintenance", status_code=201)
def add_maintenance(body: MaintenanceBody, user: User = Depends(allow(ROLE_ADMIN)),
                    db: DBSession = Depends(db_session)):
    env = db.get(Environment, body.environmentId)
    if not env:
        fail(404, "Environment not found")
    if aware(body.startsAt) >= aware(body.endsAt):
        fail(400, "End must be after start")
    m = Maintenance(environment_id=env.id, starts_at=body.startsAt,
                    ends_at=body.endsAt, reason=body.reason)
    db.add(m)
    db.commit()
    return {"id": m.id}


class ScheduleBody(BaseModel):
    teamId: int
    timezone: str = "UTC"
    primaryId: int
    backupId: int
    rotationMinutes: int = Field(default=10080, ge=60, le=525600)


@app.post("/api/v1/schedules")
def upsert_schedule(body: ScheduleBody, user: User = Depends(allow(ROLE_ADMIN)),
                    db: DBSession = Depends(db_session)):
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    try:
        ZoneInfo(body.timezone)
    except ZoneInfoNotFoundError:
        fail(400, "Unknown timezone")
    for uid in (body.primaryId, body.backupId):
        u = db.get(User, uid)
        if not u or u.team_id != body.teamId:
            fail(400, "On-call users must belong to schedule team")
    if body.primaryId == body.backupId:
        fail(400, "Primary and backup must be different")
    s = db.scalar(select(Schedule).where(Schedule.team_id == body.teamId).with_for_update())
    if not s:
        s = Schedule(team_id=body.teamId)
        db.add(s)
    s.timezone = body.timezone
    s.primary_id = body.primaryId
    s.backup_id = body.backupId
    s.rotation_minutes = body.rotationMinutes
    s.starts_at = utcnow()
    db.commit()
    return {"id": s.id}


@app.get("/api/v1/schedules")
def schedules(user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    if user.role == ROLE_OBSERVER:
        fail(403, "Observer can access status information only")
    q = select(Schedule)
    if user.role != ROLE_ADMIN:
        q = q.where(Schedule.team_id == user.team_id)
    return [{"id": s.id, "teamId": s.team_id, "timezone": s.timezone,
             "primaryId": s.primary_id, "backupId": s.backup_id,
             "rotationMinutes": s.rotation_minutes} for s in db.scalars(q).all()]


def filtered_events(user, db, service_id=None, environment_id=None):
    q = select(Event).join(Service, Event.service_id == Service.id)
    if user.role != ROLE_ADMIN:
        q = q.where(Service.team_id == user.team_id)
    if service_id:
        q = q.where(Event.service_id == service_id)
    if environment_id:
        q = q.where(Event.environment_id == environment_id)
    return q


@app.get("/api/v1/events")
def events(after: datetime | None = None, before: datetime | None = None,
           serviceId: int | None = None, environmentId: int | None = None,
           severity: str | None = None, fingerprint: str | None = None,
           cursor: str | None = None, limit: int = 50,
           user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    if user.role == ROLE_OBSERVER:
        fail(403, "Observer can access status information only")
    if limit < 1 or limit > 100:
        fail(400, "Limit must be 1..100")
    q = filtered_events(user, db, serviceId, environmentId)
    if after:
        q = q.where(Event.occurred_at >= after)
    if before:
        q = q.where(Event.occurred_at < before)
    if severity:
        q = q.where(Event.severity == severity)
    if fingerprint:
        alert = db.scalar(select(Alert).where(Alert.fingerprint == fingerprint))
        if not alert:
            return {"items": [], "nextCursor": None}
        svc = db.get(Service, alert.service_id)
        require_team(user, svc.team_id)
        q = q.where(Event.service_id == alert.service_id,
                    Event.environment_id == alert.environment_id)
        for label, value in alert.label_values.items():
            q = q.where(Event.labels[label].as_string() == str(value))
    if cursor:
        try:
            raw = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
            t = datetime.fromisoformat(raw[0])
            n = int(raw[1])
            q = q.where(or_(Event.occurred_at < t,
                            and_(Event.occurred_at == t, Event.id < n)))
        except (ValueError, KeyError, TypeError, IndexError):
            fail(400, "Invalid cursor")
    rows = db.scalars(q.order_by(Event.occurred_at.desc(), Event.id.desc()).limit(limit + 1)).all()
    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = items[-1]
        next_cursor = base64.urlsafe_b64encode(json.dumps([iso(last.occurred_at), last.id]).encode()).decode()
    return {"items": [{"id": e.id, "eventId": e.event_id, "serviceId": e.service_id,
                        "environmentId": e.environment_id, "timestamp": iso(e.occurred_at),
                        "severity": e.severity, "type": e.kind, "late": e.late,
                        "labels": e.labels, "payload": e.payload} for e in items],
            "nextCursor": next_cursor}


@app.get("/api/v1/alerts")
def alerts(state: str | None = None, user: User = Depends(current_user),
           db: DBSession = Depends(db_session)):
    if user.role == ROLE_OBSERVER:
        fail(403, "Observer can access status information only")
    q = select(Alert).join(Service, Alert.service_id == Service.id)
    if user.role != ROLE_ADMIN:
        q = q.where(Service.team_id == user.team_id)
    if state:
        q = q.where(Alert.state == state)
    return [alert_json(a) for a in db.scalars(q.order_by(Alert.last_seen_at.desc()).limit(200)).all()]


@app.get("/api/v1/incidents")
def incidents(state: str | None = None, user: User = Depends(current_user),
              db: DBSession = Depends(db_session)):
    q = select(Incident)
    if user.role != ROLE_ADMIN:
        q = q.where(Incident.team_id == user.team_id)
    if state:
        q = q.where(Incident.state == state)
    return [status_json(i) if user.role == ROLE_OBSERVER else incident_json(i)
            for i in db.scalars(q.order_by(Incident.id.desc()).limit(200)).all()]


def get_incident(db, user, id):
    i = db.get(Incident, id)
    if not i:
        fail(404, "Incident not found")
    require_team(user, i.team_id)
    return i


@app.get("/api/v1/incidents/{id}")
def incident(id: int, user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    i = get_incident(db, user, id)
    return status_json(i) if user.role == ROLE_OBSERVER else incident_json(i)


@app.get("/api/v1/incidents/{id}/timeline")
def timeline(id: int, user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    if user.role == ROLE_OBSERVER:
        fail(403, "Observer can access status information only")
    get_incident(db, user, id)
    rows = db.scalars(select(Timeline).where(Timeline.incident_id == id).order_by(Timeline.id)).all()
    return [{"id": t.id, "kind": t.kind, "data": t.data,
             "actorId": t.actor_id, "createdAt": iso(t.created_at)} for t in rows]


@app.post("/api/v1/incidents/{id}/ack")
def ack(id: int, user: User = Depends(allow(ROLE_ENGINEER, ROLE_ONCALL, ROLE_COMMANDER)),
        db: DBSession = Depends(db_session)):
    i = get_incident(db, user, id)
    affected = db.execute(update(Incident).where(
        Incident.id == id, Incident.state == "open"
    ).values(state="acknowledged", owner_id=user.id, acked_at=utcnow(),
             version=Incident.version + 1)).rowcount
    if not affected:
        db.refresh(i)
        if i.state == "acknowledged" and i.owner_id == user.id:
            return incident_json(i)
        fail(409, "Incident is already owned or resolved")
    db.refresh(i)
    emit(db, i, "acknowledged", {"ownerId": user.id}, actor_id=user.id, at=i.acked_at)
    db.execute(update(Alert).where(Alert.incident_id == id, Alert.state == "firing")
               .values(state="acknowledged"))
    db.commit()
    return incident_json(i)


class AssignBody(BaseModel):
    ownerId: int
    expectedVersion: int


@app.post("/api/v1/incidents/{id}/assign")
def assign(id: int, body: AssignBody,
           user: User = Depends(allow(ROLE_ONCALL, ROLE_COMMANDER)),
           db: DBSession = Depends(db_session)):
    i = get_incident(db, user, id)
    target = db.get(User, body.ownerId)
    if not target or target.team_id != i.team_id:
        fail(400, "Owner must belong to incident team")
    if i.state == "resolved":
        fail(409, "Incident resolved")
    affected = db.execute(update(Incident).where(
        Incident.id == id, Incident.version == body.expectedVersion, Incident.state != "resolved",
    ).values(owner_id=body.ownerId, version=Incident.version + 1)).rowcount
    if not affected:
        fail(409, "Incident changed concurrently")
    db.refresh(i)
    emit(db, i, "assigned", {"ownerId": body.ownerId}, actor_id=user.id)
    db.commit()
    return incident_json(i)


class ResolveBody(BaseModel):
    reason: str = Field(min_length=5, max_length=4000)


@app.post("/api/v1/incidents/{id}/resolve")
def resolve(id: int, body: ResolveBody,
            user: User = Depends(allow(ROLE_COMMANDER)), db: DBSession = Depends(db_session)):
    i = get_incident(db, user, id)
    now = utcnow()
    affected = db.execute(update(Incident).where(
        Incident.id == id, Incident.state != "resolved"
    ).values(state="resolved", resolved_at=now, resolution=body.reason,
             version=Incident.version + 1)).rowcount
    db.refresh(i)
    if not affected:
        if i.resolution == body.reason:
            return incident_json(i)
        fail(409, "Already resolved with different reason")
    emit(db, i, "resolved", {"reason": body.reason}, actor_id=user.id, at=now)
    db.execute(update(Alert).where(Alert.incident_id == id).values(state="resolved"))
    db.commit()
    return incident_json(i)


class CommentBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@app.post("/api/v1/incidents/{id}/comments", status_code=201)
def comment(id: int, body: CommentBody,
            user: User = Depends(allow(ROLE_ENGINEER, ROLE_ONCALL, ROLE_COMMANDER)),
            db: DBSession = Depends(db_session)):
    i = get_incident(db, user, id)
    emit(db, i, "comment", {"text": body.text}, actor_id=user.id)
    db.commit()
    return {"ok": True}


class PostmortemBody(BaseModel):
    impact: str = Field(min_length=5, max_length=10000)
    rootCause: str = Field(min_length=5, max_length=10000)
    actionItems: list[dict[str, Any]] = Field(default_factory=list, max_length=50)


@app.put("/api/v1/incidents/{id}/postmortem")
def postmortem(id: int, body: PostmortemBody,
               user: User = Depends(allow(ROLE_COMMANDER)),
               db: DBSession = Depends(db_session)):
    i = get_incident(db, user, id)
    pm = db.scalar(select(Postmortem).where(Postmortem.incident_id == id).with_for_update())
    if not pm:
        pm = Postmortem(incident_id=id, created_by=user.id, impact=body.impact,
                        root_cause=body.rootCause, action_items=body.actionItems)
        db.add(pm)
    for item in body.actionItems:
        owner_id = item.get("ownerId")
        desc = item.get("text")
        owner = db.get(User, owner_id) if isinstance(owner_id, int) else None
        if not owner or owner.team_id != i.team_id or not isinstance(desc, str) or not desc.strip():
            fail(400, "Each action item requires text and an owner from the incident team")
    pm.impact = body.impact
    pm.root_cause = body.rootCause
    pm.action_items = body.actionItems
    pm.updated_at = utcnow()
    emit(db, i, "postmortem_updated", {"actionCount": len(body.actionItems)}, actor_id=user.id)
    db.commit()
    return {"ok": True}


@app.get("/api/v1/incidents/{id}/postmortem")
def get_postmortem(id: int, user: User = Depends(current_user),
                   db: DBSession = Depends(db_session)):
    if user.role == ROLE_OBSERVER:
        fail(403, "Observer can access status information only")
    get_incident(db, user, id)
    p = db.scalar(select(Postmortem).where(Postmortem.incident_id == id))
    if not p:
        fail(404, "Postmortem not found")
    return {"impact": p.impact, "rootCause": p.root_cause, "actionItems": p.action_items,
            "updatedAt": iso(p.updated_at)}


@app.get("/api/v1/notifications")
def inbox(user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    rows = db.scalars(select(Notification).where(
        Notification.recipient_id == user.id
    ).order_by(Notification.id.desc()).limit(100)).all()
    return [{"id": n.id, "incidentId": n.incident_id, "level": n.level,
             "createdAt": iso(n.created_at), "viewedAt": iso(n.viewed_at)} for n in rows]


@app.get("/api/v1/services/{id}/health")
def service_health(id: int, user: User = Depends(current_user),
                   db: DBSession = Depends(db_session)):
    s = admin_or_team(db, user, id)
    envs = db.scalars(select(Environment).where(Environment.service_id == id)).all()
    active = db.scalar(select(func.count(Incident.id)).where(
        Incident.service_id == id, Incident.state != "resolved",
    )) or 0
    return {"service": service_json(s), "activeIncidents": active,
            "environments": [{"id": e.id, "name": e.name,
                              "lastHeartbeatAt": iso(e.last_heartbeat_at)} for e in envs]}


@app.get("/api/v1/dashboard")
def dashboard(user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    sq = select(Service.id)
    iq = select(Incident)
    eq = select(Event.id).join(Service, Event.service_id == Service.id)
    if user.role != ROLE_ADMIN:
        sq = sq.where(Service.team_id == user.team_id)
        iq = iq.where(Incident.team_id == user.team_id)
        eq = eq.where(Service.team_id == user.team_id)
    all_incidents = db.scalars(iq.order_by(Incident.id.desc()).limit(300)).all()
    last_hour = db.scalar(select(func.count()).select_from(eq.where(
        Event.received_at >= utcnow() - timedelta(hours=1)
    ).subquery())) or 0
    return {
        "serviceCount": len(db.scalars(sq).all()), "eventsLastHour": last_hour,
        "activeIncidents": sum(i.state != "resolved" for i in all_incidents),
        "unackedIncidents": sum(i.state == "open" for i in all_incidents),
        "recent": [status_json(i) if user.role == ROLE_OBSERVER else incident_json(i)
                   for i in all_incidents[:10]],
    }


@app.get("/api/v1/metrics")
def metrics(user: User = Depends(current_user), db: DBSession = Depends(db_session)):
    q = select(Incident).where(Incident.state == "resolved")
    if user.role != ROLE_ADMIN:
        q = q.where(Incident.team_id == user.team_id)
    records = db.scalars(q.order_by(Incident.id.desc()).limit(1000)).all()
    mtta, mttr = [], []
    for incident in records:
        timeline = db.scalars(select(Timeline).where(
            Timeline.incident_id == incident.id,
            Timeline.kind.in_(["created", "acknowledged", "resolved"]),
        ).order_by(Timeline.id)).all()
        created = next((x.created_at for x in timeline if x.kind == "created"), None)
        acknowledged = next((x.created_at for x in timeline if x.kind == "acknowledged"), None)
        resolved = next((x.created_at for x in timeline if x.kind == "resolved"), None)
        if created and acknowledged:
            mtta.append((aware(acknowledged) - aware(created)).total_seconds())
        if created and resolved:
            mttr.append((aware(resolved) - aware(created)).total_seconds())
    def mean(values):
        return round(sum(values) / len(values), 2) if values else None
    return {"mttaSeconds": mean(mtta), "mttrSeconds": mean(mttr),
            "ackSampleSize": len(mtta), "resolutionSampleSize": len(mttr),
            "definitions": {
                "MTTA": "Mean seconds from timeline created to first acknowledged, resolved incidents only",
                "MTTR": "Mean seconds from timeline created to resolved, resolved incidents only",
            }}


@app.get("/api/v1/ops")
def operations(user: User = Depends(allow(ROLE_ADMIN)), db: DBSession = Depends(db_session)):
    """Durable queue and detection metrics from PostgreSQL, plus process-local counters."""
    now = utcnow()
    pending_filter = Outbox.processed_at.is_(None)
    backlog, first_pending = db.execute(select(
        func.count(Outbox.id), func.min(Outbox.created_at),
    ).where(pending_filter)).one()
    due_event = exists(select(Event.id).where(
        Event.id == Outbox.subject_id, Event.occurred_at <= now,
    ))
    ready = db.scalar(select(func.count(Outbox.id)).where(
        Outbox.processed_at.is_(None),
        or_(Outbox.kind != "ingest", due_event),
    )) or 0
    processed_hour = db.scalar(select(func.count(Outbox.id)).where(
        Outbox.processed_at >= now - timedelta(hours=1),
    )) or 0
    received_hour = db.scalar(select(func.count(Event.id)).where(
        Event.received_at >= now - timedelta(hours=1),
    )) or 0
    late_hour = db.scalar(select(func.count(Event.id)).where(
        Event.received_at >= now - timedelta(hours=1), Event.late.is_(True),
    )) or 0
    recent = db.scalars(select(Timeline).where(
        Timeline.kind == "alert_fired",
        Timeline.created_at >= now - timedelta(hours=1),
    ).order_by(Timeline.id.desc()).limit(5000)).all()
    lags = sorted([
        float(t.data["detectionLagMs"]) for t in recent
        if isinstance(t.data, dict) and isinstance(t.data.get("detectionLagMs"), (int, float))
    ])
    p95 = lags[max(0, math.ceil(0.95 * len(lags)) - 1)] if lags else None
    oldest_seconds = max(0, round((now - aware(first_pending)).total_seconds(), 2)) if first_pending else None
    alive_since = now - timedelta(seconds=20)
    worker_count = db.scalar(select(func.count(WorkerStatus.id)).where(
        WorkerStatus.last_seen_at >= alive_since,
    )) or 0
    worker_rows = db.scalars(select(WorkerStatus).order_by(
        WorkerStatus.last_seen_at.desc(),
    ).limit(20)).all()
    workers = [
        {
            "id": row.id, "lastSeenAt": iso(row.last_seen_at),
            "startedAt": iso(row.started_at), "lastBatchAt": iso(row.last_batch_at),
            "processedTotal": row.processed_count,
            "errorsTotal": row.errors_count,
            "healthy": aware(row.last_seen_at) >= alive_since,
        }
        for row in worker_rows
    ]
    return {
        "pendingOutbox": backlog, "pendingReady": ready,
        "pendingDeferred": backlog - ready,
        "oldestPendingSeconds": oldest_seconds,
        "activeWorkers": worker_count, "workers": workers,
        "processedOutboxLastHour": processed_hour,
        "eventsReceivedLastHour": received_hour,
        "lateEventsLastHour": late_hour,
        "detectionLagP95Ms": p95, "detectionLagSamples": len(lags),
        "processCounters": dict(_counters),
        "note": "Detection p95 is sampled from up to 5000 firing transitions (last hour), "
                "not a validated end-to-end SLO. Counters reset on API restart.",
    }


def stream_rows(db: DBSession, user: User, after_id: int, limit: int = 100):
    """Read only events in the *current* authorization scope."""
    query = select(StreamEvent).where(StreamEvent.id > after_id)
    if user.role != ROLE_ADMIN:
        query = query.where(StreamEvent.team_id == user.team_id)
    return db.scalars(query.order_by(StreamEvent.id).limit(limit)).all()


@app.get("/stream/incidents")
async def stream(request: Request):
    # Authenticate at connection start and re-check session, role, and team for
    # every poll. Logout or team reassignment cannot leave a stale SSE reader.
    with SessionLocal() as db:
        user_from_request(request, db)
    raw = request.headers.get("last-event-id", request.query_params.get("lastEventId", "0"))
    try:
        cursor = int(raw)
        if cursor < 0 or cursor > 9223372036854775807:
            raise ValueError()
    except (ValueError, TypeError):
        fail(400, "Invalid Last-Event-ID")

    async def generate():
        nonlocal cursor
        yield "retry: 2000\n\n"
        while not await request.is_disconnected():
            with SessionLocal() as db:
                try:
                    user = user_from_request(request, db)
                except HTTPException:
                    return
                rows = stream_rows(db, user, cursor, 100)
                # Materialize before closing the DB session; no query runs
                # while yielding to a slow browser.
                messages = []
                for item in rows:
                    body = json.dumps(
                        {"kind": item.kind, **item.content}, ensure_ascii=False,
                    )
                    messages.append((item.id, "id: " + str(item.id) + "\ndata: " + body + "\n\n"))
            for event_id, payload in messages:
                cursor = event_id
                yield payload
            if len(rows) < 100:
                yield ": heartbeat\n\n"
                await asyncio.sleep(2)
    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# Additional read-only analytics and reporting workflows.
from .extras import router as extras_router  # noqa: E402
app.include_router(extras_router)
