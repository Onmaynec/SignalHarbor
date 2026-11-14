"""Stateless worker: database-backed retry semantics, no in-memory event queue."""
import logging
import os
import signal
import time

from .engine import drain_outbox, retention, scan_escalations, scan_health

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("signalharbor.worker")
running = True


def stop(*_):
    global running
    running = False


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last_scan = 0.0
    last_retention = 0.0
    logger.info("rule worker started")
    while running:
        try:
            count = drain_outbox(batch_size=batch_size)
            now = time.monotonic()
            if now - last_scan >= 2:
                scan_health()
                scan_escalations()
                last_scan = now
            if now - last_retention >= 3600:
                retention()
                last_retention = now
            if count == 0:
                time.sleep(0.5)
        except Exception:
            logger.exception("worker transaction failed, will retry")
            time.sleep(2)
    logger.info("worker stopped")


if __name__ == "__main__":
    main()
