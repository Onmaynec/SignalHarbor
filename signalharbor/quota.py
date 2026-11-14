"""Shared PostgreSQL ingest quota, transactionally coupled to ingest ACK.

The per-key fixed 60-second window is synchronized across API workers with
advisory locks. On validation/DB failure the reservation rolls back with the
event batch, so it never silently consumes quota without durable acceptance.
"""
from __future__ import annotations

import math
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import IngestQuota, utcnow


def reserve_quota(db: Session, key_id: int, units: int, limit: int) -> None:
    if units < 0 or limit <= 0:
        raise ValueError("Invalid ingest quota parameters")
    now = utcnow()
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(139726, :key)"), {"key": key_id})
    row = db.scalar(select(IngestQuota).where(
        IngestQuota.key_id == key_id,
    ).with_for_update())
    if row is None:
        row = IngestQuota(key_id=key_id, window_started_at=now, used=0)
        db.add(row)
        db.flush()
    elif now - row.window_started_at.replace(tzinfo=now.tzinfo) >= timedelta(seconds=60):
        row.window_started_at = now
        row.used = 0
    if row.used + units > limit:
        remaining = max(1, math.ceil(60 - (
            now - row.window_started_at.replace(tzinfo=now.tzinfo)
        ).total_seconds()))
        raise HTTPException(
            429, "Ingest rate exceeded",
            headers={"Retry-After": str(remaining)},
        )
    row.used += units
