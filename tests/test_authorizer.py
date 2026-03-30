from __future__ import annotations

import pathlib
import sys
from types import SimpleNamespace

import jwt
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from handlers import authorizer


def _mock_settings():
    return SimpleNamespace(
        jwt_secret_key="secret",
        jwt_algorithm="HS256",
        jwt_audience="stagelog-api",
        jwt_issuer="stagelog-auth",
    )


def test_http_authorizer_allow(monkeypatch):
    monkeypatch.setattr(authorizer, "load_settings", _mock_settings)
    monkeypatch.setattr(authorizer.jwt, "decode", lambda *args, **kwargs: {"user_id": 1, "sub": "1", "type": "access"})
    monkeypatch.setattr(authorizer, "is_access_token_blacklisted", lambda _t: False)

    event = {"identitySource": ["Bearer token"]}
    result = authorizer.lambda_handler(event, None)

    assert result["isAuthorized"] is True
    assert result["context"]["user_id"] == "1"


def test_http_authorizer_deny_on_invalid_token(monkeypatch):
    monkeypatch.setattr(authorizer, "load_settings", _mock_settings)

    def _raise_invalid(*args, **kwargs):
        raise jwt.InvalidTokenError("invalid")

    monkeypatch.setattr(authorizer.jwt, "decode", _raise_invalid)

    event = {"identitySource": ["Bearer token"]}
    result = authorizer.lambda_handler(event, None)

    assert result == {"isAuthorized": False}


def test_rest_authorizer_allow(monkeypatch):
    monkeypatch.setattr(authorizer, "load_settings", _mock_settings)
    monkeypatch.setattr(authorizer.jwt, "decode", lambda *args, **kwargs: {"user_id": 42, "sub": "42", "type": "access"})
    monkeypatch.setattr(authorizer, "is_access_token_blacklisted", lambda _t: False)

    event = {
        "methodArn": "arn:aws:execute-api:ap-northeast-2:123456789012:api-id/prod/GET/api/auth/keep",
        "headers": {"Authorization": "Bearer token"},
    }
    result = authorizer.lambda_handler(event, None)

    stmt = result["policyDocument"]["Statement"][0]
    assert stmt["Effect"] == "Allow"
    assert result["context"]["user_id"] == "42"


def test_rest_authorizer_unauthorized_on_missing_token(monkeypatch):
    monkeypatch.setattr(authorizer, "load_settings", _mock_settings)

    event = {
        "methodArn": "arn:aws:execute-api:ap-northeast-2:123456789012:api-id/prod/GET/api/auth/keep",
        "headers": {},
    }

    with pytest.raises(Exception, match="Unauthorized"):
        authorizer.lambda_handler(event, None)
