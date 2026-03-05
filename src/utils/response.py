from __future__ import annotations

import json
from typing import Any, Dict, Optional


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
    if headers:
        response_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": json.dumps(body, ensure_ascii=False),
    }
