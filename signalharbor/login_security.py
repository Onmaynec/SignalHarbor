"""Database-backed login throttling shared by all API replicas.

Account identifiers are hashed at rest. PostgreSQL advisory transaction locks
serialize even the first failure for a username across concurrent requests.
"""
from __future__ import annotations

import hashlib
import math
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import LoginAttempt, utcnow

MAX_FAILURES = 8
WINDOW = timedelta(minutes=15)
LOCKOUT = timedelta(minutes=15)


def _hash_account(email: str) -> str:
    return hashlib.sha256(("login:" + email).encode("utf-8")).hexdigest()


def begin_login(db: Session, email: str, now: datetime | None = None) -> tuple:
    now = now or utcnow()
    key = _hash_account(email)
    if db.bind.dialect.name == "postgresql":
        lock_key = int.from_bytes(bytes.fromhex(key)[:4], "big", signed=True)
        db.execute(text("SELECT pg_advisory_xact_lock(139724, :key)"), {"key": lock_key})
    record = db.scalar(select(LoginAttempt).where(
        LoginAttempt.key_hash == key,
    ).with_for_update())
    if record and record.locked_until and record.locked_until.replace(
        tzinfo=now.tzinfo,
    ) > now:
        remaining = math.ceil((record.locked_until.replace(
            tzinfo=now.tzinfo,
        ) - now).total_seconds())
        raise HTTPException(
            429, "Login temporarily limited",
            headers={"Retry-After": str(max(1, remaining))},
        )
    if record and now - record.window_started_at.replace(tzinfo=now.tzinfo) >= WINDOW:
        record.failures = 0
        record.window_started_at = now
        record.locked_until = None
    return record, key


def failed_login(db: Session, record: LoginAttempt | None,
                 key: str, now: datetime | None = None) -> None:
    now = now or utcnow()
    if record is None:
        record = LoginAttempt(
            key_hash=key, window_started_at=now, failures=0,
        )
        db.add(record)
    record.failures += 1
    locked = record.failures >= MAX_FAILURES
    if locked:
        record.locked_until = now + LOCKOUT
    db.commit()  # Failed attempts must survive the HTTP 401 response.
    if locked:
        raise HTTPException(
            429, "Login temporarily limited",
            headers={"Retry-After": str(int(LOCKOUT.total_seconds()))},
        )
    raise HTTPException(401, "Invalid credentials")


def successful_login(db: Session, record: LoginAttempt | None) -> None:
    if record:
        db.delete(record)
    # The caller creates a session and commits both changes atomically.
