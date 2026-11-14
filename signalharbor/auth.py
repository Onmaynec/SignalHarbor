"""Authentication and authorization. All entity filters are enforced server side."""
import hashlib
import hmac
import os
import secrets
from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from .models import Session, SessionLocal, User, utcnow

ROLE_ADMIN = "admin"
ROLE_COMMANDER = "commander"
ROLE_ONCALL = "oncall"
ROLE_ENGINEER = "engineer"
ROLE_OBSERVER = "observer"
ROLES = {ROLE_ADMIN, ROLE_COMMANDER, ROLE_ONCALL, ROLE_ENGINEER, ROLE_OBSERVER}


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 390000)
    return salt + ":" + digest.hex()


def check_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split(":", 1)
        return hmac.compare_digest(hash_password(password, salt), stored)
    except (ValueError, TypeError):
        return False


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def db_session():
    with SessionLocal() as db:
        yield db


def user_from_request(request: Request, db: DBSession) -> User:
    token = request.cookies.get("signalharbor_session")
    if not token:
        raise HTTPException(401, "Login required")
    session = db.scalar(
        select(Session).where(Session.token_hash == hash_token(token), Session.expires_at > utcnow())
    )
    if session is None:
        raise HTTPException(401, "Session expired")
    user = db.get(User, session.user_id)
    if user is None or not user.enabled:
        raise HTTPException(401, "Account disabled")
    return user


def current_user(request: Request, db: DBSession = Depends(db_session)) -> User:
    return user_from_request(request, db)


def allow(*roles: str):
    def check(user: User = Depends(current_user)) -> User:
        if user.role not in roles and user.role != ROLE_ADMIN:
            raise HTTPException(403, "Insufficient permissions")
        return user
    return check


def require_team(user: User, team_id: int):
    if user.role != ROLE_ADMIN and user.team_id != team_id:
        raise HTTPException(404, "Resource not found")


def create_login(db: DBSession, user: User) -> str:
    token = secrets.token_urlsafe(40)
    db.add(Session(token_hash=hash_token(token), user_id=user.id, expires_at=utcnow() + timedelta(hours=12)))
    db.commit()
    return token


def session_cookie(response, token: str):
    response.set_cookie(
        "signalharbor_session", token, max_age=43200, httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
        samesite="strict", path="/",
    )
