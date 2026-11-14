"""Database bootstrap and deterministic demo data.

Usage: python -m signalharbor.manage migrate|seed|demo [--count 100000]
"""
import argparse
import os
import random
import secrets
from datetime import timedelta

from sqlalchemy import func, select

from .auth import hash_password, hash_token
from .models import (
    Base, Environment, Event, IngestKey, Maintenance, Rule, Schedule, SchemaVersion,
    Service, SessionLocal, Team, User, engine, utcnow,
)


def migrate():
    Base.metadata.create_all(engine)
    with SessionLocal.begin() as db:
        v = db.get(SchemaVersion, 1)
        if not v:
            db.add(SchemaVersion(version=1))
    print("Schema baseline v1 ready")


def seed():
    email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD", "")
    if not email or len(password) < 12 or password.startswith("change-this"):
        raise SystemExit("Set ADMIN_EMAIL and strong ADMIN_PASSWORD before seed")
    with SessionLocal.begin() as db:
        admin = db.scalar(select(User).where(User.email == email))
        if not admin:
            db.add(User(email=email, password_hash=hash_password(password),
                        role="admin", team_id=None))
    print("Admin account ready:", email)


def demo(count: int, seed_value: int):
    if count < 0 or count > 1000000:
        raise SystemExit("count must be between 0 and 1000000")
    rng = random.Random(seed_value)
    now = utcnow()
    with SessionLocal.begin() as db:
        teams = []
        for n in range(1, 5):
            name = "Operations " + str(n)
            t = db.scalar(select(Team).where(Team.name == name))
            if not t:
                t = Team(name=name)
                db.add(t)
                db.flush()
            teams.append(t)
        envs = []
        for i in range(40):
            t = teams[i % len(teams)]
            name = "service-" + str(i + 1).zfill(2)
            s = db.scalar(select(Service).where(Service.name == name, Service.team_id == t.id))
            if not s:
                s = Service(name=name, team_id=t.id)
                db.add(s)
                db.flush()
            e = db.scalar(select(Environment).where(
                Environment.service_id == s.id, Environment.name == "production"))
            if not e:
                e = Environment(service_id=s.id, name="production",
                                last_heartbeat_at=now)
                db.add(e)
                db.flush()
            k = db.scalar(select(IngestKey).where(
                IngestKey.environment_id == e.id, IngestKey.name == "demo-generator"))
            if not k:
                k = IngestKey(environment_id=e.id, name="demo-generator",
                              token_hash=hash_token(secrets.token_urlsafe(40)))
                db.add(k)
                db.flush()
            rule = db.scalar(select(Rule).where(
                Rule.environment_id == e.id, Rule.kind == "count_error"))
            if not rule:
                db.add(Rule(name="Error burst: " + name, team_id=t.id,
                            service_id=s.id, environment_id=e.id, kind="count_error",
                            threshold=20, window_seconds=300, recovery_seconds=180,
                            severity="high", group_labels=[]))
            hb = db.scalar(select(Rule).where(
                Rule.environment_id == e.id, Rule.kind == "heartbeat_missing"))
            if not hb:
                db.add(Rule(name="Heartbeat missing: " + name, team_id=t.id,
                            service_id=s.id, environment_id=e.id, kind="heartbeat_missing",
                            threshold=180, window_seconds=300, recovery_seconds=180,
                            severity="critical", group_labels=[]))
            envs.append((s.id, e.id, k.id))
        for n, t in enumerate(teams, 1):
            for role in ("engineer", "oncall", "commander", "observer"):
                email = role + str(n) + "@signalharbor.local"
                if db.scalar(select(User.id).where(User.email == email)) is None:
                    # Demo accounts use the same operator-supplied secret, not hardcoded test passwords.
                    password = os.getenv("ADMIN_PASSWORD", "")
                    if len(password) < 12:
                        raise SystemExit("ADMIN_PASSWORD required for demo")
                    db.add(User(email=email, password_hash=hash_password(password),
                                team_id=t.id, role=role))
        db.flush()
        for n, t in enumerate(teams, 1):
            oncall = db.scalar(select(User).where(User.email == "oncall" + str(n) + "@signalharbor.local"))
            backup = db.scalar(select(User).where(User.email == "engineer" + str(n) + "@signalharbor.local"))
            schedule = db.scalar(select(Schedule).where(Schedule.team_id == t.id))
            if not schedule and oncall and backup:
                db.add(Schedule(team_id=t.id, timezone="UTC", primary_id=oncall.id,
                                backup_id=backup.id, rotation_minutes=10080, starts_at=now))
        first_env_id = envs[0][1]
        exists = db.scalar(select(Maintenance.id).where(
            Maintenance.environment_id == first_env_id))
        if not exists:
            db.add(Maintenance(environment_id=first_env_id,
                               starts_at=now - timedelta(hours=4),
                               ends_at=now - timedelta(hours=3), reason="Historical maintenance"))
    with SessionLocal() as db:
        total = db.scalar(select(func.count(Event.id)).where(
            Event.event_id.like("demo-" + str(seed_value) + "-%"),
        )) or 0
    while total < count:
        rows = []
        batch = min(1000, count - total)
        for i in range(batch):
            service_id, env_id, key_id = envs[(total + i) % len(envs)]
            age = rng.randrange(60, 60 * 60 * 24 * 20)
            occurred = now - timedelta(seconds=age)
            kind = "heartbeat" if rng.randrange(30) == 0 else "error" if rng.randrange(6) == 0 else "log"
            rows.append(Event(
                key_id=key_id, event_id="demo-" + str(seed_value) + "-" + str(total + i),
                service_id=service_id, environment_id=env_id, occurred_at=occurred,
                received_at=occurred + timedelta(seconds=rng.randrange(0, 240)),
                severity="error" if kind == "error" else "info", kind=kind,
                labels={"region": rng.choice(["eu", "us", "apac"])},
                payload={"synthetic": True, "sequence": total + i},
                late=bool(rng.randrange(15) == 0),
            ))
        with SessionLocal.begin() as db:
            # No outbox is created: historical demo records must never page on-call.
            db.add_all(rows)
        total += batch
        if total % 10000 == 0 or total == count:
            print("Synthetic historical events:", total, "/", count)
    print("Demo ready: 40 services / 4 teams. Historic data is not replayed as live alerts.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["migrate", "seed", "demo"])
    p.add_argument("--count", type=int, default=100000)
    p.add_argument("--seed", type=int, default=42)
    opts = p.parse_args()
    if opts.action == "migrate":
        migrate()
    elif opts.action == "seed":
        seed()
    elif opts.action == "demo":
        demo(opts.count, opts.seed)
