from __future__ import annotations

from handlers.health import handle_health
from handlers.jwks import handle_jwks
from handlers.login import handle_social_login
from handlers.refresh import handle_keep, handle_logout, handle_refresh
from utils.response import api_response

SUPPORTED_PROVIDERS = {"kakao", "google", "naver"}

ROUTES = {
    ("GET", "/health"): handle_health,
    ("GET", "/.well-known/jwks.json"): handle_jwks,
    ("POST", "/auth/refresh"): handle_refresh,
    ("GET", "/auth/keep"): handle_keep,
    ("POST", "/auth/logout"): handle_logout,
}


def _normalize_path(raw_path: str) -> str:
    if raw_path.startswith("/api"):
        normalized = raw_path[4:] or "/"
        return normalized if normalized.startswith("/") else f"/{normalized}"
    return raw_path


def lambda_handler(event, _context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    path = _normalize_path(event.get("rawPath", ""))

    if method == "POST" and path.startswith("/auth/login/"):
        provider = path.rsplit("/", 1)[-1]
        if provider in SUPPORTED_PROVIDERS:
            return handle_social_login(event, provider)
        return api_response(400, False, message="unsupported provider")

    handler = ROUTES.get((method, path))
    if not handler:
        return api_response(404, False, message=f"route not found: {method} {path}")

    try:
        return handler(event)
    except ValueError as exc:
        return api_response(400, False, message=str(exc))
    except Exception:
        return api_response(500, False, message="internal server error")
