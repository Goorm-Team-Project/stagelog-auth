from __future__ import annotations

import logging
import os

from utils.env_loader import load_runtime_env

load_runtime_env()

from handlers.health import handle_health
from handlers.jwks import handle_jwks
from handlers.login import handle_social_login
from handlers.signup import handle_signup
from handlers.refresh import handle_keep, handle_logout, handle_refresh
from utils.response import api_response

_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.getLogger().setLevel(getattr(logging, _LOG_LEVEL, logging.INFO))
logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, _LOG_LEVEL, logging.INFO))

SUPPORTED_PROVIDERS = {"kakao", "google", "naver"}

ROUTES = {
    ("GET", "/health"): handle_health,
    ("GET", "/.well-known/jwks.json"): handle_jwks,
    ("POST", "/auth/login/refresh"): handle_refresh,
    ("POST", "/auth/signup"): handle_signup,
    ("GET", "/auth/keep"): handle_keep,
    ("POST", "/auth/logout"): handle_logout,
}


def _extract_http_method(event: dict) -> str:
    method = event.get("requestContext", {}).get("http", {}).get("method")
    if method:
        return str(method).upper()
    return str(event.get("httpMethod", "")).upper()


def _extract_raw_path(event: dict) -> str:
    raw_path = event.get("rawPath") or event.get("path") or "/"
    stage = event.get("requestContext", {}).get("stage")

    if stage:
        stage_prefix = f"/{stage}"
        if raw_path == stage_prefix:
            return "/"
        if raw_path.startswith(f"{stage_prefix}/"):
            return raw_path[len(stage_prefix) :]

    return raw_path


def _normalize_path(raw_path: str) -> str:
    if not raw_path:
        return "/"

    if raw_path.startswith("/api"):
        normalized = raw_path[4:] or "/"
        return normalized if normalized.startswith("/") else f"/{normalized}"

    return raw_path if raw_path.startswith("/") else f"/{raw_path}"


def lambda_handler(event, _context):
    method = _extract_http_method(event)
    path = _normalize_path(_extract_raw_path(event))

    logger.info("auth_api request method=%s path=%s", method, path)

    handler = ROUTES.get((method, path))
    if handler:
        try:
            logger.info("auth_api route_match method=%s path=%s handler=%s", method, path, getattr(handler, "__name__", "unknown"))
            return handler(event)
        except ValueError as exc:
            logger.warning("auth_api value_error method=%s path=%s error=%s", method, path, exc)
            return api_response(400, False, message=str(exc))
        except Exception:
            logger.exception("auth_api unhandled_exception method=%s path=%s", method, path)
            return api_response(500, False, message="internal server error")

    if method == "POST" and path.startswith("/auth/login/"):
        provider = path.rsplit("/", 1)[-1]
        if provider in SUPPORTED_PROVIDERS:
            logger.info("auth_api social_login_route provider=%s", provider)
            return handle_social_login(event, provider)
        logger.warning("auth_api unsupported_provider path=%s provider=%s", path, provider)
        return api_response(400, False, message="unsupported provider")

    logger.warning("auth_api route_not_found method=%s path=%s", method, path)
    return api_response(404, False, message=f"route not found: {method} {path}")
