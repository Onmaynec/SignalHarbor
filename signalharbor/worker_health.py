"""Durable worker heartbeat and health metrics.

Status rows are retained across API restarts. A new worker process generates a
new ID; old records are marked stale instead of misleadingly appearing healthy.
"""
from __future__ import annotations

from datetime import datetime

from .models import SessionLocal, WorkerStatus, utcnow


def record_worker(worker_id: str, *, processed: int = 0, failures: int = 0,
                  batch_completed: bool = False, now: datetime | None = None) -> None:
    if not worker_id or len(worker_id) > 64:
        raise ValueError("Invalid worker id")
    if processed < 0 or failures < 0:
        raise ValueError("Counters must not decrease")
    now = now or utcnow()
    with SessionLocal.begin() as db:
        row = db.get(WorkerStatus, worker_id)
        if row is None:
            row = WorkerStatus(
                id=worker_id, started_at=now, last_seen_at=now,
                processed_count=0, errors_count=0,
            )
            db.add(row)
        row.last_seen_at = now
        row.processed_count += processed
        row.errors_count += failures
        if batch_completed:
            row.last_batch_at = now
