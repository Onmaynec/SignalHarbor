"""Durable outbox worker with bounded batches and persistent heartbeats."""
from __future__ import annotations

import logging
import os
import signal
import time
import uuid

from .engine import drain_outbox, retention, scan_escalations, scan_health
from .worker_health import record_worker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("signalharbor.worker")
running = True


def stop(*_):
    global running
    running = False


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    batch_size = min(500, max(1, int(os.getenv("WORKER_BATCH_SIZE", "250"))))
    worker_id = uuid.uuid4().hex
    last_scan = 0.0
    last_retention = 0.0
    last_report = 0.0
    processed_pending = 0
    errors_pending = 0
    completed_batch = False
    logger.info("rule worker started id=%s batch_size=%d", worker_id, batch_size)
    while running:
        try:
            count = drain_outbox(batch_size=batch_size)
            processed_pending += count
            completed_batch = completed_batch or count > 0
            now = time.monotonic()
            if now - last_scan >= 2:
                scan_health()
                scan_escalations()
                last_scan = now
            if now - last_retention >= 60:
                result = retention()
                if any(result.values()):
                    logger.info("retention completed %s", result)
                last_retention = now
            if count == 0:
                time.sleep(0.5)
        except Exception:
            errors_pending += 1
            logger.exception("worker transaction failed, will retry")
            time.sleep(2)
        finally:
            now = time.monotonic()
            if now - last_report >= 5:
                try:
                    record_worker(
                        worker_id, processed=processed_pending,
                        failures=errors_pending, batch_completed=completed_batch,
                    )
                    processed_pending = 0
                    errors_pending = 0
                    completed_batch = False
                except Exception:
                    logger.exception("worker heartbeat could not be persisted")
                last_report = now
    # Best effort only: a forced stop must never prevent outbox recovery.
    try:
        record_worker(
            worker_id, processed=processed_pending, failures=errors_pending,
            batch_completed=completed_batch,
        )
    except Exception:
        logger.exception("final worker heartbeat could not be persisted")
    logger.info("worker stopped id=%s", worker_id)


if __name__ == "__main__":
    main()
