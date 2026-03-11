from __future__ import annotations

import jwt

from services.session_store import is_access_token_blacklisted
from utils.config import load_settings


def _validate_access_token(token: str):
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
        return None

    if payload.get("type") != "access":
        return None

    if is_access_token_blacklisted(token):
        return None

    return payload


def _extract_bearer_from_http_api(event) -> str:
    identity_source = event.get("identitySource", [])
    raw = identity_source[0] if identity_source else ""

    if not raw.startswith("Bearer "):
        return ""

    return raw.split(" ", 1)[1].strip()


def _extract_bearer_from_rest_api(event) -> str:
    headers = event.get("headers") or {}
    raw = headers.get("Authorization") or headers.get("authorization") or ""

    if not raw.startswith("Bearer "):
        return ""

    return raw.split(" ", 1)[1].strip()


def _rest_policy(method_arn: str, context: dict | None = None) -> dict:
    policy = {
        "principalId": (context or {}).get("user_id", "anonymous"),
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": method_arn,
                }
            ],
        },
    }

    if context:
        policy["context"] = {k: str(v) for k, v in context.items()}

    return policy


def _raise_rest_unauthorized() -> None:
    # API Gateway REST custom authorizer converts this exact error message to 401 UNAUTHORIZED.
    raise Exception("Unauthorized")


def _handle_rest_authorizer(event) -> dict:
    method_arn = event.get("methodArn", "*")
    token = _extract_bearer_from_rest_api(event)

    if not token:
        _raise_rest_unauthorized()

    payload = _validate_access_token(token)
    if payload is None:
        _raise_rest_unauthorized()

    context = {
        "user_id": str(payload.get("user_id", "")),
        "sub": str(payload.get("sub", "")),
        "token_type": str(payload.get("type", "")),
    }
    return _rest_policy(method_arn, context=context)


def _handle_http_authorizer(event) -> dict:
    token = _extract_bearer_from_http_api(event)
    if not token:
        return {"isAuthorized": False}

    payload = _validate_access_token(token)
    if payload is None:
        return {"isAuthorized": False}

    return {
        "isAuthorized": True,
        "context": {
            "user_id": str(payload.get("user_id", "")),
            "sub": str(payload.get("sub", "")),
            "token_type": str(payload.get("type", "")),
        },
    }


def lambda_handler(event, _context):
    # REST API custom authorizer event contains methodArn
    if "methodArn" in event:
        return _handle_rest_authorizer(event)

    # HTTP API v2 Lambda authorizer(simple response)
    return _handle_http_authorizer(event)
