from __future__ import annotations

import json
from typing import Any, Dict, Optional


def api_response(status_code: int, success: bool, message: str = "", data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    body = {
        "success": success,
        "message": message,
        "data": data,
    }
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": json.dumps(body, ensure_ascii=False),
    }
