from __future__ import annotations

import jwt
import pymysql

from services.auth_repository import create_user, email_exists, get_bookmark_event_ids, nickname_exists
from services.session_store import store_refresh_session
from services.token_service import get_token_exp_unverified, issue_access_token, issue_refresh_token, verify_register_token
from utils.request import parse_json_body
from utils.response import api_response


def handle_signup(event):
    data = parse_json_body(event)
    register_token = data.get("register_token")
    input_nickname = str(data.get("nickname") or "").strip()
    input_email = str(data.get("email") or "").strip()
    is_email_sub = bool(data.get("is_email_sub", False))
    is_events_notification_sub = bool(data.get("is_events_notification_sub", False))
    is_posts_notification_sub = bool(data.get("is_posts_notification_sub", False))

    if not register_token or not input_nickname or not input_email:
        return api_response(400, False, message="필수 정보가 없습니다.")

    try:
        payload = verify_register_token(str(register_token))
    except jwt.ExpiredSignatureError:
        return api_response(401, False, message="만료된 토큰입니다.")
    except jwt.InvalidTokenError:
        return api_response(401, False, message="유효하지 않은 토큰입니다.")

    provider = str(payload.get("provider") or "").strip()
    provider_id = str(payload.get("provider_id") or "").strip()
    if not provider or not provider_id:
        return api_response(400, False, message="토큰에 필수 정보(provider)가 없습니다.")

    if email_exists(input_email):
        return api_response(409, False, message="이미 가입된 이메일입니다.")
    if nickname_exists(input_nickname):
        return api_response(409, False, message="이미 존재하는 닉네임입니다.")

    try:
        user = create_user(
            email=input_email,
            nickname=input_nickname,
            provider=provider,
            provider_id=provider_id,
            is_email_sub=is_email_sub,
            is_events_notification_sub=is_events_notification_sub,
            is_posts_notification_sub=is_posts_notification_sub,
        )
    except pymysql.IntegrityError:
        return api_response(409, False, message="이미 존재하는 닉네임 혹은 이메일입니다.")
    except Exception:
        return api_response(500, False, message="서버 내부 오류")

    try:
        user_id = int(user["user_id"])
        access_token = issue_access_token(user_id)
        refresh_token = issue_refresh_token(user_id)
        refresh_exp = get_token_exp_unverified(refresh_token)
        store_refresh_session(user_id, refresh_token, expires_at_unix=refresh_exp)
        bookmarks = get_bookmark_event_ids(user_id)
    except Exception:
        return api_response(500, False, message="서버 내부 오류")

    return api_response(
        201,
        True,
        message="가입 완료",
        data={
            "access_token": access_token,
            "user": {
                "id": user_id,
                "nickname": user["nickname"],
                "level": int(user.get("level") or 1),
                "bookmarks": bookmarks,
            },
        },
        headers={
            "Set-Cookie": f"refresh_token={refresh_token}; Max-Age=1209600; Path=/; HttpOnly; SameSite=Lax",
        },
    )
