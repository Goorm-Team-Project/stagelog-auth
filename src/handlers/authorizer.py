from __future__ import annotations

import jwt
import logging
import os

from utils.env_loader import load_runtime_env
from services.session_store import is_access_token_blacklisted
from utils.config import load_settings

load_runtime_env()

_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.getLogger().setLevel(getattr(logging, _LOG_LEVEL, logging.INFO))
logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, _LOG_LEVEL, logging.INFO))


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
        logger.warning("authorizer invalid_access_token")
        return None

    if payload.get("type") != "access":
        logger.warning("authorizer wrong_token_type type=%s", payload.get("type"))
        return None

    if is_access_token_blacklisted(token):
        logger.warning("authorizer blacklisted_access_token user_id=%s", payload.get("user_id"))
        return None

    logger.info("authorizer token_valid user_id=%s", payload.get("user_id"))
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
    raise Exception("Unauthorized")


def _handle_rest_authorizer(event) -> dict:
    method_arn = event.get("methodArn", "*")
    token = _extract_bearer_from_rest_api(event)

    if not token:
        logger.warning("authorizer rest_missing_bearer method_arn=%s", method_arn)
        _raise_rest_unauthorized()

    payload = _validate_access_token(token)
    if payload is None:
        logger.warning("authorizer rest_denied method_arn=%s", method_arn)
        _raise_rest_unauthorized()

    context = {
        "user_id": str(payload.get("user_id", "")),
        "sub": str(payload.get("sub", "")),
        "token_type": str(payload.get("type", "")),
    }
    logger.info("authorizer rest_allow user_id=%s method_arn=%s", context["user_id"], method_arn)
    return _rest_policy(method_arn, context=context)


def _handle_http_authorizer(event) -> dict:
    token = _extract_bearer_from_http_api(event)
    if not token:
        logger.warning("authorizer http_missing_bearer")
        return {"isAuthorized": False}

    payload = _validate_access_token(token)
    if payload is None:
        logger.warning("authorizer http_denied")
        return {"isAuthorized": False}

    logger.info("authorizer http_allow user_id=%s", payload.get("user_id"))
    return {
        "isAuthorized": True,
        "context": {
            "user_id": str(payload.get("user_id", "")),
            "sub": str(payload.get("sub", "")),
            "token_type": str(payload.get("type", "")),
        },
    }


def lambda_handler(event, _context):
    if "methodArn" in event:
        return _handle_rest_authorizer(event)

    return _handle_http_authorizer(event)
