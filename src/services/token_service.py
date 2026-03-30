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


def issue_register_token(provider: str, provider_id: str, email: str | None = None) -> str:
    settings = load_settings()
    if not settings.jwt_secret_key:
        raise ValueError("JWT_SECRET_KEY is required")

    now = _now()
    payload: Dict[str, Any] = {
        "provider": provider,
        "provider_id": provider_id,
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "type": "register",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def verify_access_token(token: str) -> Dict[str, Any]:
    settings = load_settings()
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("token type is not access")
    return payload


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


def verify_register_token(token: str) -> Dict[str, Any]:
    settings = load_settings()
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )
    if payload.get("type") != "register":
        raise jwt.InvalidTokenError("token type is not register")
    return payload


def get_token_exp_unverified(token: str) -> int:
    payload = jwt.decode(token, options={"verify_signature": False})
    exp = payload.get("exp")
    if exp is None:
        raise ValueError("token exp is missing")
    return int(exp)
