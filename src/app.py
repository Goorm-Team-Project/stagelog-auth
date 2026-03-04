from __future__ import annotations

from handlers.health import handle_health
from handlers.jwks import handle_jwks
from handlers.login import handle_login
from handlers.refresh import handle_refresh
from utils.response import api_response


ROUTES = {
    ("GET", "/health"): handle_health,
    ("GET", "/.well-known/jwks.json"): handle_jwks,
    ("POST", "/auth/login"): handle_login,
    ("POST", "/auth/refresh"): handle_refresh,
}


def lambda_handler(event, _context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    path = event.get("rawPath", "")

    handler = ROUTES.get((method, path))
    if not handler:
        return api_response(404, False, message=f"route not found: {method} {path}")

    try:
        return handler(event)
    except ValueError as exc:
        return api_response(400, False, message=str(exc))
    except Exception:
        return api_response(500, False, message="internal server error")
