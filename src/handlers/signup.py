from __future__ import annotations

import jwt
import logging
import pymysql

from services.auth_repository import create_user, email_exists, get_bookmark_event_ids, nickname_exists
from services.session_store import store_refresh_session
from services.token_service import get_token_exp_unverified, issue_access_token, issue_refresh_token, verify_register_token
from utils.request import parse_json_body
from utils.response import api_response

logger = logging.getLogger(__name__)


def handle_signup(event):
    data = parse_json_body(event)
    register_token = data.get("register_token")
    input_nickname = str(data.get("nickname") or "").strip()
    input_email = str(data.get("email") or "").strip()
    is_email_sub = bool(data.get("is_email_sub", False))
    is_events_notification_sub = bool(data.get("is_events_notification_sub", False))
    is_posts_notification_sub = bool(data.get("is_posts_notification_sub", False))

    logger.info(
        "signup start has_register_token=%s has_nickname=%s has_email=%s",
        bool(register_token),
        bool(input_nickname),
        bool(input_email),
    )

    if not register_token or not input_nickname or not input_email:
        logger.warning("signup missing_required_fields")
        return api_response(400, False, message="필수 정보가 없습니다.")

    try:
        payload = verify_register_token(str(register_token))
    except jwt.ExpiredSignatureError:
        logger.warning("signup register_token_expired")
        return api_response(401, False, message="만료된 토큰입니다.")
    except jwt.InvalidTokenError:
        logger.warning("signup register_token_invalid")
        return api_response(401, False, message="유효하지 않은 토큰입니다.")

    provider = str(payload.get("provider") or "").strip()
    provider_id = str(payload.get("provider_id") or "").strip()
    if not provider or not provider_id:
        logger.warning("signup missing_provider_in_token")
        return api_response(400, False, message="토큰에 필수 정보(provider)가 없습니다.")

    if email_exists(input_email):
        logger.info("signup duplicate_email provider=%s", provider)
        return api_response(409, False, message="이미 가입된 이메일입니다.")
    if nickname_exists(input_nickname):
        logger.info("signup duplicate_nickname provider=%s", provider)
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
        logger.warning("signup integrity_error provider=%s", provider)
        return api_response(409, False, message="이미 존재하는 닉네임 혹은 이메일입니다.")
    except Exception:
        logger.exception("signup create_user_failed provider=%s", provider)
        return api_response(500, False, message="서버 내부 오류")

    try:
        user_id = int(user["user_id"])
        access_token = issue_access_token(user_id)
        refresh_token = issue_refresh_token(user_id)
        refresh_exp = get_token_exp_unverified(refresh_token)
        store_refresh_session(user_id, refresh_token, expires_at_unix=refresh_exp)
        bookmarks = get_bookmark_event_ids(user_id)
    except Exception:
        logger.exception("signup token_or_session_setup_failed provider=%s user_id=%s", provider, user.get("user_id"))
        return api_response(500, False, message="서버 내부 오류")

    logger.info("signup success provider=%s user_id=%s", provider, user_id)
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
