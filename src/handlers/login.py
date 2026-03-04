from __future__ import annotations

from utils.request import parse_json_body
from utils.response import api_response
from services.token_service import issue_access_token, issue_refresh_token


def handle_login(event):
    body = parse_json_body(event)

    # TODO: 실제 소셜 OAuth 코드 교환/유저 조회로 교체
    user_id = body.get("user_id")
    if not user_id:
        return api_response(400, False, message="user_id is required for bootstrap login")

    access_token = issue_access_token(user_id)
    refresh_token = issue_refresh_token(user_id)

    return api_response(
        200,
        True,
        message="login success",
        data={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
        },
    )
