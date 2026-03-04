from __future__ import annotations

from utils.config import load_settings


def handle_jwks(_event):
    settings = load_settings()
    jwk = settings.public_jwk
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": __import__("json").dumps({"keys": [jwk] if jwk else []}, ensure_ascii=False),
    }
