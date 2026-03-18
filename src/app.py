from __future__ import annotations

from utils.env_loader import load_env_file

load_env_file()

from handlers.health import handle_health
from handlers.jwks import handle_jwks
from handlers.login import handle_social_login
from handlers.signup import handle_signup
from handlers.refresh import handle_keep, handle_logout, handle_refresh
from utils.response import api_response

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

    # REST API proxy event can include stage in path (e.g. /prod/api/auth/keep)
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
