"""v0.6.0 MFA and multi-replica ingest quota integration tests.

All database tests run only against signalharbor_test.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
import base64
import time

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select, text

from signalharbor import api as api_module
from signalharbor.auth import hash_token
from signalharbor.mfa import encrypt_secret, hotp, new_secret, verify_factor
from signalharbor.migrations import migrate
from signalharbor.models import (
    Alert, Event, IngestQuota, MfaCredential, MfaEnrollment, Outbox, SchemaVersion,
    Session, SessionLocal, User, WorkerStatus, engine, utcnow,
)
from signalharbor.quota import reserve_quota
from .conftest import login, make_events


@pytest.fixture()
def mfa_key(monkeypatch):
    key = base64.urlsafe_b64encode(b"m" * 32).decode("ascii")
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", key)
    return key


def test_mfa_setup_enable_recovery_login_and_disable(client, mfa_key):
    login(client, "engineer@example.test")
    assert client.get("/api/v1/mfa/status").json()["enabled"] is False
    wrong = client.post("/api/v1/mfa/setup", json={"password": "incorrect-password"})
    assert wrong.status_code == 403

    setup = client.post("/api/v1/mfa/setup", json={
        "password": "secure-password-123",
    })
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert secret in setup.json()["otpauthUri"]
    with SessionLocal() as db:
        row = db.get(MfaEnrollment, 1)
        assert row is not None
        assert secret not in row.secret_encrypted

    assert client.post("/api/v1/mfa/enable", json={"code": "000000x"}).status_code == 400
    code = hotp(secret, int(time.time() // 30))
    enabled = client.post("/api/v1/mfa/enable", json={"code": code})
    assert enabled.status_code == 200, enabled.text
    recovery = enabled.json()["recoveryCodes"]
    assert len(recovery) == 8
    assert all(len(x) == 20 for x in recovery)
    assert client.get("/api/v1/mfa/status").json()["enabled"] is True
    with SessionLocal() as db:
        assert db.scalar(select(func.count(MfaEnrollment.user_id))) == 0
        cred = db.scalar(select(MfaCredential))
        assert secret not in cred.secret_encrypted
        assert recovery[0] not in str(cred.recovery_hashes)

    assert client.post("/api/v1/logout").status_code == 200
    missing = client.post("/api/v1/login", json={
        "email": "engineer@example.test", "password": "secure-password-123",
    })
    assert missing.status_code == 401
    assert missing.json()["message"] == "MFA code required"
    invalid = client.post("/api/v1/login", json={
        "email": "engineer@example.test", "password": "secure-password-123",
        "mfaCode": "111111",
    })
    assert invalid.status_code == 401
    success = client.post("/api/v1/login", json={
        "email": "engineer@example.test", "password": "secure-password-123",
        "mfaCode": recovery[0],
    })
    assert success.status_code == 200, success.text
    client.headers["x-csrf-token"] = client.cookies.get("signalharbor_csrf")
    assert client.get("/api/v1/me").status_code == 200
    with SessionLocal() as db:
        cred = db.scalar(select(MfaCredential))
        assert len(cred.recovery_hashes) == 7

    assert client.post("/api/v1/logout").status_code == 200
    reused = client.post("/api/v1/login", json={
        "email": "engineer@example.test", "password": "secure-password-123",
        "mfaCode": recovery[0],
    })
    assert reused.status_code == 401
    good = client.post("/api/v1/login", json={
        "email": "engineer@example.test", "password": "secure-password-123",
        "mfaCode": recovery[1],
    })
    assert good.status_code == 200
    client.headers["x-csrf-token"] = client.cookies.get("signalharbor_csrf")
    assert client.post("/api/v1/mfa/disable", json={
        "password": "wrong", "code": recovery[2],
    }).status_code == 403
    disabled = client.post("/api/v1/mfa/disable", json={
        "password": "secure-password-123", "code": recovery[2],
    })
    assert disabled.status_code == 200, disabled.text
    assert client.get("/api/v1/me").status_code == 401
    assert client.post("/api/v1/login", json={
        "email": "engineer@example.test", "password": "secure-password-123",
    }).status_code == 200


def test_totp_replay_and_future_step_are_distinct(mfa_key):
    seed = new_secret()
    credential = MfaCredential(
        user_id=1, secret_encrypted=encrypt_secret(seed),
        last_used_step=-1, recovery_hashes=[],
    )
    step = int(time.time() // 30)
    current = hotp(seed, step)
    assert verify_factor(credential, current, now=step * 30 + 10)
    assert not verify_factor(credential, current, now=step * 30 + 11)
    assert verify_factor(credential, hotp(seed, step + 1), now=(step + 1) * 30 + 10)
    assert not verify_factor(credential, "000000abc", now=(step + 1) * 30 + 10)


def test_missing_encryption_key_rejects_mfa_setup_and_enabled_login(
    client, mfa_key, monkeypatch,
):
    login(client, "engineer@example.test")
    setup = client.post("/api/v1/mfa/setup", json={
        "password": "secure-password-123",
    })
    assert setup.status_code == 200
    code = hotp(setup.json()["secret"], int(time.time() // 30))
    enabled = client.post("/api/v1/mfa/enable", json={"code": code})
    assert enabled.status_code == 200
    recovery = enabled.json()["recoveryCodes"]
    client.post("/api/v1/logout")
    monkeypatch.delenv("MFA_ENCRYPTION_KEY")
    response = client.post("/api/v1/login", json={
        "email": "engineer@example.test", "password": "secure-password-123",
        "mfaCode": recovery[0],
    })
    assert response.status_code == 503
    assert client.get("/api/v1/me").status_code == 401


def test_other_sessions_revoked_when_mfa_enabled(client, mfa_key):
    login(client, "engineer@example.test")
    with SessionLocal.begin() as db:
        user = db.scalar(select(User).where(User.email == "engineer@example.test"))
        db.add(Session(
            user_id=user.id, token_hash=hash_token("old-unprotected-session"),
            expires_at=utcnow() + timedelta(hours=1),
        ))
    setup = client.post("/api/v1/mfa/setup", json={
        "password": "secure-password-123",
    }).json()
    code = hotp(setup["secret"], int(time.time() // 30))
    enabled = client.post("/api/v1/mfa/enable", json={"code": code})
    assert enabled.status_code == 200, enabled.text
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Session.id)).where(
            Session.token_hash == hash_token("old-unprotected-session"),
        )) == 0


def test_shared_quota_rejects_across_requests_without_leaking_usage(client, monkeypatch):
    monkeypatch.setattr(api_module, "QUOTA", 40)
    first = client.post("/ingest/v1/events", json=make_events(30),
                        headers={"x-ingest-key": "fixture-key"})
    assert first.status_code == 200, first.text
    exceeded = client.post("/ingest/v1/events", json=make_events(20, prefix="later"),
                           headers={"x-ingest-key": "fixture-key"})
    assert exceeded.status_code == 429
    assert 1 <= int(exceeded.headers["retry-after"]) <= 60
    allowed = client.post("/ingest/v1/events", json=make_events(10, prefix="last"),
                          headers={"x-ingest-key": "fixture-key"})
    assert allowed.status_code == 200, allowed.text
    with SessionLocal() as db:
        assert db.scalar(select(func.count(Event.id))) == 40
        assert db.scalar(select(IngestQuota.used)) == 40
        assert db.scalar(select(func.count(Outbox.id))) == 40


def test_bad_ingest_payload_rolls_back_quota_reservation(client, monkeypatch):
    monkeypatch.setattr(api_module, "QUOTA", 40)
    denied = client.post("/ingest/v1/events", json=make_events(30, service_id=999),
                         headers={"x-ingest-key": "fixture-key"})
    assert denied.status_code == 403
    accepted = client.post("/ingest/v1/events", json=make_events(40),
                           headers={"x-ingest-key": "fixture-key"})
    assert accepted.status_code == 200, accepted.text
    with SessionLocal() as db:
        assert db.scalar(select(IngestQuota.used)) == 40


def test_parallel_quota_reservations_are_serialized(fixture_db):
    barrier = Barrier(2)

    def reserve():
        with SessionLocal.begin() as db:
            barrier.wait(timeout=10)
            try:
                reserve_quota(db, 1, 10, 15)
            except HTTPException as exc:
                return exc.status_code
            return 200

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda _: reserve(), [1, 2]))
    assert sorted(statuses) == [200, 429]
    with SessionLocal() as db:
        assert db.scalar(select(IngestQuota.used)) == 10


def test_migration_v4_to_v6_preserves_worker_and_alerts(fixture_db):
    with SessionLocal.begin() as db:
        db.add(WorkerStatus(id="old-worker", processed_count=17, errors_count=1))
        legacy_alert = Alert(
            fingerprint="c" * 64, rule_id=1, rule_version=1,
            service_id=1, environment_id=1, state="firing",
            count=3, value=3, fired_at=utcnow(), last_seen_at=utcnow(),
            label_values={},
        )
        db.add(legacy_alert)
        db.flush()
        legacy_alert_id = legacy_alert.id
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE metric_hours"))
        conn.execute(text("DROP TABLE login_attempts"))
        conn.execute(text("DROP TABLE mfa_credentials"))
        conn.execute(text("DROP TABLE mfa_enrollments"))
        conn.execute(text("DROP TABLE ingest_quotas"))
        conn.execute(text("ALTER TABLE alerts DROP COLUMN window_start_at"))
        conn.execute(text("ALTER TABLE alerts DROP COLUMN window_end_at"))
        conn.execute(text("DELETE FROM schema_version WHERE version>=4"))
    assert migrate() == 6
    assert migrate() == 6
    with SessionLocal() as db:
        assert db.get(WorkerStatus, "old-worker").processed_count == 17
        migrated_alert = db.get(Alert, legacy_alert_id)
        assert migrated_alert is not None
        assert migrated_alert.count == 3
        assert migrated_alert.window_start_at is None
        assert migrated_alert.window_end_at is None
        assert db.scalars(select(SchemaVersion.version).order_by(
            SchemaVersion.version,
        )).all() == [1, 2, 3, 4, 5, 6]
