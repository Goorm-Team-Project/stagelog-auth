from __future__ import annotations

import json

from utils.config import load_settings
from utils.response import cors_headers


def handle_jwks(_event):
    settings = load_settings()
    jwk = settings.public_jwk
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json", **cors_headers()},
        "body": json.dumps({"keys": [jwk] if jwk else []}, ensure_ascii=False),
    }
