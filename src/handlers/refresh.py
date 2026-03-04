from __future__ import annotations

import jwt

from utils.request import parse_json_body
from utils.response import api_response
from services.token_service import issue_access_token, verify_refresh_token


def handle_refresh(event):
    body = parse_json_body(event)
    refresh_token = body.get("refresh_token")

    if not refresh_token:
        return api_response(400, False, message="refresh_token is required")

    try:
        payload = verify_refresh_token(refresh_token)
    except jwt.ExpiredSignatureError:
        return api_response(401, False, message="refresh token expired")
    except jwt.InvalidTokenError:
        return api_response(401, False, message="invalid refresh token")

    access_token = issue_access_token(payload.get("user_id"))
    return api_response(200, True, message="refresh success", data={"access_token": access_token})
