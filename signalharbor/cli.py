"""Ingest CLI. Retries 429/503 with exponential backoff and jitter."""
import argparse
import json
import random
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def send(url, key, body, retries=6):
    data = json.dumps(body).encode()
    for attempt in range(retries + 1):
        request = Request(
            url, data=data, headers={"Content-Type": "application/json", "X-Ingest-Key": key},
        )
        try:
            with urlopen(request, timeout=10) as response:
                print(response.read().decode())
                return
        except HTTPError as ex:
            if ex.code not in (429, 503) or attempt == retries:
                raise
            retry_after = float(ex.headers.get("Retry-After", 0))
            delay = max(retry_after, min(30, (2 ** attempt) + random.uniform(0, 1)))
            print("HTTP", ex.code, "- retrying in", round(delay, 1), "seconds")
            time.sleep(delay)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:8080")
    p.add_argument("--key", required=True)
    p.add_argument("--service", required=True, type=int)
    p.add_argument("--count", type=int, default=40)
    p.add_argument("--heartbeat", action="store_true")
    opts = p.parse_args()
    now = datetime.now(timezone.utc).isoformat()
    if opts.heartbeat:
        send(opts.url + "/ingest/v1/heartbeat", opts.key, {
            "schemaVersion": 1, "eventId": str(uuid.uuid4()),
            "serviceId": opts.service, "timestamp": now,
        })
        return
    count = min(max(opts.count, 1), 500)
    send(opts.url + "/ingest/v1/events", opts.key, {
        "schemaVersion": 1,
        "events": [
            {
                "eventId": str(uuid.uuid4()), "serviceId": opts.service,
                "timestamp": now, "severity": "error", "type": "error",
                "labels": {"region": "eu"}, "payload": {"message": "CLI synthetic error"},
            }
            for _ in range(count)
        ],
    })


if __name__ == "__main__":
    main()
