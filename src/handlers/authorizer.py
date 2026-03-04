from __future__ import annotations

import jwt

from utils.config import load_settings


def lambda_handler(event, _context):
    # HTTP API Lambda Authorizer(simple response) 형태
    identity_source = event.get("identitySource", [])
    raw = identity_source[0] if identity_source else ""

    if not raw.startswith("Bearer "):
        return {"isAuthorized": False}

    token = raw.split(" ", 1)[1].strip()
    settings = load_settings()

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except jwt.InvalidTokenError:
        return {"isAuthorized": False}

    return {
        "isAuthorized": True,
        "context": {
            "user_id": str(payload.get("user_id", "")),
            "sub": str(payload.get("sub", "")),
            "token_type": str(payload.get("type", "")),
        },
    }
