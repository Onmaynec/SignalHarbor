"""Optional TOTP MFA with encrypted secrets and single-use recovery codes.

TOTP follows RFC 6238 (HMAC-SHA1, 30-second steps, six digits).
Application-managed encryption uses Fernet; key is mandatory for MFA and must
remain stable across deployments. No session is issued until MFA succeeds.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import timedelta
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import MfaCredential, MfaEnrollment, utcnow


def cipher() -> Fernet:
    key = os.environ.get("MFA_ENCRYPTION_KEY", "").strip()
    if not key:
        raise HTTPException(503, "MFA encryption key is not configured")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise HTTPException(503, "Invalid MFA encryption key") from exc


def encrypt_secret(secret: str) -> str:
    return cipher().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_secret(value: str) -> str:
    try:
        return cipher().decrypt(value.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise HTTPException(503, "MFA secret could not be decrypted") from exc


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def hotp(secret: str, counter: int) -> str:
    raw = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(raw, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{value % 1000000:06d}"


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    if len(code) != 6 or not code.isascii() or not code.isdecimal():
        return None
    center = int((time.time() if now is None else now) // 30)
    for step in (center, center - 1, center + 1):
        if step >= 0 and hmac.compare_digest(hotp(secret, step), code):
            return step
    return None


def recovery_hash(code: str) -> str:
    return hashlib.sha256(("mfa-recovery:" + code).encode("utf-8")).hexdigest()


def generate_recovery() -> tuple[list[str], list[str]]:
    codes = [secrets.token_hex(10).upper() for _ in range(8)]
    return codes, [recovery_hash(code) for code in codes]


def verify_factor(credential: MfaCredential, code: str, *, now: float | None = None) -> bool:
    """Mutates the locked row; caller must commit with session issuance."""
    secret = decrypt_secret(credential.secret_encrypted)
    step = matching_step(secret, code, now)
    if step is not None:
        if step <= credential.last_used_step:
            return False
        credential.last_used_step = step
        return True
    supplied = recovery_hash(code.strip().upper())
    for value in credential.recovery_hashes:
        if hmac.compare_digest(value, supplied):
            credential.recovery_hashes = [x for x in credential.recovery_hashes if x != value]
            return True
    return False


def get_credential(db: Session, user_id: int) -> MfaCredential | None:
    return db.scalar(select(MfaCredential).where(
        MfaCredential.user_id == user_id,
    ).with_for_update())


def enrollment(db: Session, user_id: int, email: str) -> dict:
    if get_credential(db, user_id) is not None:
        raise HTTPException(409, "MFA is already enabled")
    secret = new_secret()
    row = db.get(MfaEnrollment, user_id)
    if row is None:
        row = MfaEnrollment(user_id=user_id)
        db.add(row)
    row.secret_encrypted = encrypt_secret(secret)
    row.expires_at = utcnow() + timedelta(minutes=10)
    db.commit()
    label = quote(f"SignalHarbor:{email}", safe="")
    uri = f"otpauth://totp/{label}?secret={secret}&issuer=SignalHarbor&digits=6&period=30"
    return {"secret": secret, "otpauthUri": uri, "expiresSeconds": 600}


def enable(db: Session, user_id: int, code: str) -> list[str]:
    if get_credential(db, user_id) is not None:
        raise HTTPException(409, "MFA is already enabled")
    row = db.scalar(select(MfaEnrollment).where(
        MfaEnrollment.user_id == user_id,
    ).with_for_update())
    if row is None or row.expires_at < utcnow():
        raise HTTPException(409, "MFA enrollment expired; start again")
    secret = decrypt_secret(row.secret_encrypted)
    counter = matching_step(secret, code)
    if counter is None:
        raise HTTPException(400, "Invalid authenticator code")
    codes, hashes = generate_recovery()
    db.add(MfaCredential(
        user_id=user_id, secret_encrypted=row.secret_encrypted,
        last_used_step=counter, recovery_hashes=hashes,
    ))
    db.delete(row)
    db.commit()
    return codes
