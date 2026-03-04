from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt

from utils.config import load_settings


def _now() -> datetime:
    return datetime.now(timezone.utc)


def issue_access_token(user_id: int | str) -> str:
    settings = load_settings()
    if not settings.jwt_secret_key:
        raise ValueError("JWT_SECRET_KEY is required")

    now = _now()
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "user_id": int(user_id) if str(user_id).isdigit() else str(user_id),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.jwt_access_ttl_seconds)).timestamp()),
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def issue_refresh_token(user_id: int | str) -> str:
    settings = load_settings()
    if not settings.jwt_secret_key:
        raise ValueError("JWT_SECRET_KEY is required")

    now = _now()
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "user_id": int(user_id) if str(user_id).isdigit() else str(user_id),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.jwt_refresh_ttl_seconds)).timestamp()),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def verify_refresh_token(token: str) -> Dict[str, Any]:
    settings = load_settings()
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    if payload.get("type") != "refresh":
        raise jwt.InvalidTokenError("token type is not refresh")
    return payload
