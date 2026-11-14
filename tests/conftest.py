"""Destructive tests are allowed only against a database ending in _test."""
import os
import pytest
from fastapi.testclient import TestClient

url = os.environ.get("DATABASE_URL", "")
if "signalharbor_test" not in url:
    raise RuntimeError("Set DATABASE_URL to a dedicated signalharbor_test database")

from signalharbor.api import app, _buckets  # noqa: E402
from signalharbor.auth import hash_password, hash_token  # noqa: E402
from signalharbor.migrations import migrate  # noqa: E402
from signalharbor.models import (  # noqa: E402
    Base, Environment, IngestKey, Rule, Schedule, Service, SessionLocal, Team, User, engine, utcnow,
)


@pytest.fixture()
def fixture_db():
    Base.metadata.drop_all(engine)
    migrate()
    _buckets.clear()
    with SessionLocal.begin() as db:
        team = Team(name="Infra")
        other = Team(name="Finance")
        db.add_all([team, other])
        db.flush()
        engineer = User(email="engineer@example.test", password_hash=hash_password("secure-password-123"),
                        role="engineer", team_id=team.id)
        other_user = User(email="other@example.test", password_hash=hash_password("secure-password-123"),
                          role="engineer", team_id=other.id)
        backup = User(email="backup@example.test", password_hash=hash_password("secure-password-123"),
                      role="oncall", team_id=team.id)
        commander = User(email="commander@example.test", password_hash=hash_password("secure-password-123"),
                         role="commander", team_id=team.id)
        admin = User(email="admin@example.test", password_hash=hash_password("secure-password-123"),
                     role="admin", team_id=None)
        db.add_all([engineer, other_user, backup, commander, admin])
        db.flush()
        s = Service(name="api", team_id=team.id)
        db.add(s)
        db.flush()
        env = Environment(name="prod", service_id=s.id, last_heartbeat_at=utcnow())
        db.add(env)
        db.flush()
        key = IngestKey(environment_id=env.id, name="fixture", token_hash=hash_token("fixture-key"))
        db.add(key)
        db.add(Rule(team_id=team.id, service_id=s.id, environment_id=env.id,
                    name="Error burst", kind="count_error", window_seconds=300,
                    threshold=20, recovery_seconds=180, cooldown_seconds=0,
                    severity="high", group_labels=[]))
        db.add(Schedule(team_id=team.id, timezone="UTC", primary_id=engineer.id,
                        backup_id=backup.id, rotation_minutes=10080, starts_at=utcnow()))
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture()
def client(fixture_db):
    with TestClient(app) as cli:
        yield cli


def login(client, email):
    r = client.post("/api/v1/login", json={"email": email, "password": "secure-password-123"})
    assert r.status_code == 200, r.text
    # TestClient cookies persist; CSRF token required for all state-changing operations.
    client.headers["x-csrf-token"] = client.cookies.get("signalharbor_csrf")
    return r.json()


def make_events(size=40, service_id=1, prefix="e"):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    return {"schemaVersion": 1, "events": [
        {"eventId": prefix + str(i), "serviceId": service_id, "timestamp": now,
         "severity": "error", "type": "error", "labels": {}, "payload": {"index": i}}
        for i in range(size)
    ]}
