from __future__ import annotations

import jwt
import logging

from services.auth_repository import get_bookmark_event_ids, get_user_for_keep, user_exists
from services.session_store import blacklist_access_token, is_refresh_session_active, revoke_refresh_session
from services.token_service import get_token_exp_unverified, issue_access_token, verify_access_token, verify_refresh_token
from utils.response import api_response

logger = logging.getLogger(__name__)


def _extract_cookie_value(event, key: str) -> str:
    headers = event.get("headers") or {}
    raw_cookie = headers.get("cookie") or headers.get("Cookie") or ""
    if not raw_cookie:
        return ""

    for part in raw_cookie.split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        name, value = item.split("=", 1)
        if name.strip() == key:
            return value.strip()
    return ""


def _extract_bearer_token(event):
    headers = event.get("headers") or {}
    raw = headers.get("authorization") or headers.get("Authorization") or ""
    if not raw.startswith("Bearer "):
        return ""
    return raw.split(" ", 1)[1].strip()


def _extract_authorized_user_id(event) -> int | None:
    request_context = event.get("requestContext") or {}
    authorizer = request_context.get("authorizer") or {}

    raw = authorizer.get("user_id")
    if raw is None and isinstance(authorizer.get("lambda"), dict):
        raw = authorizer["lambda"].get("user_id")

    if raw is None:
        return None

    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def _get_refresh_token(event) -> str:
    return _extract_cookie_value(event, "refresh_token")


def handle_refresh(event):
    try:
        refresh_token = _get_refresh_token(event)
        logger.info("refresh start has_cookie=%s", bool(refresh_token))

        if not refresh_token:
            logger.warning("refresh missing_cookie")
            return api_response(400, False, message="토큰이 없습니다.")

        try:
            payload = verify_refresh_token(str(refresh_token))
            user_id = int(payload.get("user_id"))
        except jwt.ExpiredSignatureError:
            logger.warning("refresh token_expired")
            return api_response(401, False, message="만료된 토큰입니다.")
        except jwt.InvalidTokenError:
            logger.warning("refresh token_invalid")
            return api_response(401, False, message="유효하지 않은 토큰입니다.")

        logger.info("refresh token_verified user_id=%s", user_id)

        if not is_refresh_session_active(user_id, refresh_token):
            logger.warning("refresh session_inactive user_id=%s", user_id)
            return api_response(401, False, message="유효하지 않거나 만료된 토큰입니다.")

        if not user_exists(user_id):
            logger.warning("refresh user_not_found user_id=%s", user_id)
            return api_response(404, False, message="존재하지 않는 회원입니다.")

        access_token = issue_access_token(user_id)
        logger.info("refresh success user_id=%s", user_id)
        return api_response(200, True, message="토큰 재발급 완료", data={"access_token": access_token})
    except Exception:
        logger.exception("refresh unhandled_exception")
        return api_response(401, False, message="유효하지 않은 토큰입니다.")


def handle_keep(event):
    user_id = _extract_authorized_user_id(event)

    if user_id is None:
        token = _extract_bearer_token(event)
        if not token:
            logger.warning("keep missing_bearer")
            return api_response(401, False, message="토큰이 없거나 형식이 잘못되었습니다.")

        try:
            payload = verify_access_token(token)
            user_id = int(payload.get("user_id"))
        except jwt.InvalidTokenError:
            logger.warning("keep invalid_access_token")
            return api_response(401, False, message="유효하지 않거나 만료된 토큰입니다.")

    try:
        user = get_user_for_keep(user_id)
        if not user:
            logger.warning("keep user_not_found user_id=%s", user_id)
            return api_response(404, False, message="존재하지 않는 회원입니다.")

        bookmarked_id = get_bookmark_event_ids(user_id)
        logger.info("keep success user_id=%s", user_id)
        return api_response(
            200,
            True,
            message="유저 정보 조회 성공",
            data={
                "user": {
                    "id": user_id,
                    "nickname": user.get("nickname"),
                    "level": user.get("level"),
                    "bookmarks": bookmarked_id,
                }
            },
        )
    except Exception:
        logger.exception("keep unhandled_exception user_id=%s", user_id)
        return api_response(500, False, message="서버 에러 발생")


def handle_logout(event):
    token = _extract_bearer_token(event)
    if not token:
        logger.warning("logout missing_bearer")
        return api_response(401, False, message="토큰이 없거나 형식이 잘못되었습니다.")

    user_id = _extract_authorized_user_id(event)

    if user_id is None:
        try:
            payload = verify_access_token(token)
            user_id = int(payload.get("user_id"))
        except jwt.InvalidTokenError:
            logger.warning("logout invalid_access_token")
            return api_response(401, False, message="유효하지 않거나 만료된 토큰입니다.")

    try:
        access_exp = get_token_exp_unverified(token)
        blacklist_access_token(token, expires_at_unix=access_exp)

        delete_target_token = _get_refresh_token(event)
        if not delete_target_token:
            logger.warning("logout missing_refresh_cookie user_id=%s", user_id)
            return api_response(400, False, message="삭제할 토큰이 없습니다.")

        revoke_refresh_session(user_id, delete_target_token)
        logger.info("logout success user_id=%s", user_id)
        return api_response(
            200,
            True,
            message="로그아웃 성공",
            headers={
                "Set-Cookie": "refresh_token=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
            },
        )
    except Exception:
        logger.exception("logout unhandled_exception user_id=%s", user_id)
        return api_response(200, True, message="로그아웃 처리됨")
