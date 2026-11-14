"""Reproducible 2,000 events/min ingest probe with latency/reject report.

This script needs no external dependencies; run with a dedicated ingest key.
"""
import argparse
import json
import math
import platform
import random
import statistics
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def percentile(values, p):
    if not values:
        return None
    ordered = sorted(values)
    rank = math.ceil((p / 100) * len(ordered)) - 1
    return round(ordered[max(0, rank)], 2)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:8080")
    p.add_argument("--key", required=True)
    p.add_argument("--service", type=int, required=True)
    p.add_argument("--rate", type=int, default=2000)
    p.add_argument("--minutes", type=float, default=30)
    p.add_argument("--batch", type=int, default=500)
    p.add_argument("--output", default="load-report.json")
    p.add_argument("--seed", type=int, default=42)
    opts = p.parse_args()
    if opts.rate < 1 or opts.batch < 1 or opts.batch > 500 or opts.minutes <= 0:
        p.error("rate>0, 0<batch<=500, minutes>0 required")
    random.seed(opts.seed)
    interval = 60.0 * opts.batch / opts.rate
    n_batches = math.ceil(opts.rate * opts.minutes / opts.batch)
    observed = []
    statuses = {}
    accepted = duplicates = 0
    begun = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    for idx in range(n_batches):
        until = begun + idx * interval
        time.sleep(max(0.0, until - time.monotonic()))
        now = datetime.now(timezone.utc).isoformat()
        body = {"schemaVersion": 1, "events": [
            {"eventId": str(uuid.uuid4()), "serviceId": opts.service, "timestamp": now,
             "severity": "error" if random.random() < 0.4 else "info",
             "type": "error" if random.random() < 0.4 else "log",
             "labels": {"zone": "eu"}, "payload": {"batch": idx, "i": j}}
            for j in range(opts.batch)
        ]}
        encoded = json.dumps(body).encode()
        start = time.perf_counter()
        try:
            with urlopen(Request(
                opts.url.rstrip("/") + "/ingest/v1/events",
                data=encoded, headers={"Content-Type": "application/json", "X-Ingest-Key": opts.key},
            ), timeout=30) as resp:
                latency = (time.perf_counter() - start) * 1000
                observed.append(latency)
                statuses["200"] = statuses.get("200", 0) + 1
                result = json.loads(resp.read().decode())
                accepted += result.get("accepted", 0)
                duplicates += result.get("duplicates", 0)
        except HTTPError as exc:
            code = str(exc.code)
            statuses[code] = statuses.get(code, 0) + 1
        except (URLError, TimeoutError) as exc:
            statuses["network_error"] = statuses.get("network_error", 0) + 1
        if idx % 20 == 0:
            print("Batch", idx + 1, "/", n_batches, "accepted", accepted, "errors", statuses)
    runtime = time.monotonic() - begun
    report = {
        "tool": "SignalHarbor load probe v0.1",
        "environment": {"python": platform.python_version(),
                        "os": platform.platform(), "machine": platform.machine(),
                        "processor": platform.processor()},
        "profile": {"rateEventsPerMinute": opts.rate, "minutesRequested": opts.minutes,
                    "batch": opts.batch, "batches": n_batches, "seed": opts.seed,
                    "serviceId": opts.service},
        "startedAt": started_at, "finishedAt": datetime.now(timezone.utc).isoformat(),
        "elapsedSeconds": round(runtime, 2),
        "acceptedEvents": accepted, "duplicates": duplicates, "httpStatuses": statuses,
        "batchLatencyMs": {
            "p50": percentile(observed, 50), "p95": percentile(observed, 95),
            "mean": round(statistics.mean(observed), 2) if observed else None,
            "samples": len(observed),
        },
        "detectionLagMs": None,
        "backlog": None,
        "notes": [
            "Latency is HTTP batch acknowledgement, not end-to-end alert detection.",
            "Use separate DB/worker metrics for backlog and detection lag.",
            "HTTP errors are counted, not silently retried (to preserve load rate).",
        ],
    }
    with open(opts.output, "w", encoding="utf-8") as out:
        json.dump(report, out, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
