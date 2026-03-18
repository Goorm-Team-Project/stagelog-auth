from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional


def _cors_allowed_origin() -> str:
    return os.getenv("AUTH_CORS_ALLOWED_ORIGIN", "https://pearlinvest.click")


def cors_headers() -> Dict[str, str]:
    return {
        "Access-Control-Allow-Origin": _cors_allowed_origin(),
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "Authorization,Content-Type,Origin,Accept,X-Requested-With,X-CSRF-Token",
        "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    }


def api_response(
    status_code: int,
    success: bool,
    message: str = "",
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    body = {
        "success": success,
        "message": message,
        "data": data,
    }

    response_headers = {
        "Content-Type": "application/json",
    }
    response_headers.update(cors_headers())
    if headers:
        response_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": json.dumps(body, ensure_ascii=False),
    }
