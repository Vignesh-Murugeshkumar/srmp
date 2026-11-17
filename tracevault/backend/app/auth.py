"""Authentication, RBAC, agent token verification, and audit logging."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import (
    AuditLogModel,
    EndpointAgentModel,
    EndpointModel,
    InvestigationModel,
    UserModel,
    utc_now_str,
)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_agent_token() -> str:
    return secrets.token_urlsafe(32)


def create_access_token(user: UserModel) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role,
        "exp": exp,
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired authentication token: {exc}",
        ) from exc


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> UserModel:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_access_token(token)
    user = db.get(UserModel, payload.get("sub"))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists")
    return user


def get_current_user_ws(
    token: str = Query(default=""),
    db: Session = Depends(get_db),
) -> UserModel:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    payload = decode_access_token(token)
    user = db.get(UserModel, payload.get("sub"))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_write_access(user: UserModel) -> None:
    if user.role not in ("admin", "investigator"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Viewer role cannot modify resources")


def check_investigation_access(db: Session, inv_id: str, user: UserModel, write: bool = False) -> InvestigationModel:
    inv = db.get(InvestigationModel, inv_id)
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    if write:
        require_write_access(user)
    if user.role == "admin" or inv.is_demo:
        return inv
    if inv.created_by == user.username or user.id in (inv.assigned_user_ids or []):
        return inv
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this investigation")


def get_authenticated_agent(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> tuple[EndpointAgentModel, EndpointModel]:
    if not authorization or not authorization.startswith("Agent "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Agent credentials")
    creds = authorization[6:].strip()
    if ":" not in creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed Agent credentials")
    agent_id, raw_token = creds.split(":", 1)
    agent = db.get(EndpointAgentModel, agent_id)
    if not agent or agent.revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent unknown or revoked")
    if not secrets.compare_digest(agent.token_hash, hash_token(raw_token)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")
    endpoint = db.get(EndpointModel, agent.endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Associated endpoint not found")
    return agent, endpoint


def write_audit_log(
    db: Session,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLogModel(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            timestamp=utc_now_str(),
            details=details or {},
        )
    )
