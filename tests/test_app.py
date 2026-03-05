from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from app import lambda_handler


def test_health_route():
    event = {
        "rawPath": "/health",
        "requestContext": {"http": {"method": "GET"}},
    }

    result = lambda_handler(event, None)
    assert result["statusCode"] == 200

    body = json.loads(result["body"])
    assert body["success"] is True
    assert body["data"]["service"] == "auth-service"


def test_not_found_route():
    event = {
        "rawPath": "/unknown",
        "requestContext": {"http": {"method": "GET"}},
    }

    result = lambda_handler(event, None)
    assert result["statusCode"] == 404


def test_normalize_api_prefix_not_found_without_handler_match():
    event = {
        "rawPath": "/api/unknown",
        "requestContext": {"http": {"method": "GET"}},
    }

    result = lambda_handler(event, None)
    assert result["statusCode"] == 404
