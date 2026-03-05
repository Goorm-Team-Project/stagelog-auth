from __future__ import annotations

import jwt

from services.auth_repository import get_bookmark_event_ids, get_user_for_keep, user_exists
from services.session_store import blacklist_access_token, is_refresh_session_active, revoke_refresh_session
from services.token_service import get_token_exp_unverified, issue_access_token, verify_access_token, verify_refresh_token
from utils.response import api_response


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


def _get_refresh_token(event) -> str:
    # Monolith contract: refresh token is read from cookie only.
    return _extract_cookie_value(event, "refresh_token")


def handle_refresh(event):
    try:
        refresh_token = _get_refresh_token(event)

        if not refresh_token:
            return api_response(400, False, message="토큰이 없습니다.")

        try:
            payload = verify_refresh_token(str(refresh_token))
            user_id = int(payload.get("user_id"))
        except jwt.ExpiredSignatureError:
            return api_response(401, False, message="만료된 토큰입니다.")
        except jwt.InvalidTokenError:
            return api_response(401, False, message="유효하지 않은 토큰입니다.")

        if not is_refresh_session_active(user_id, refresh_token):
            return api_response(401, False, message="유효하지 않거나 만료된 토큰입니다.")

        if not user_exists(user_id):
            return api_response(404, False, message="존재하지 않는 회원입니다.")

        access_token = issue_access_token(user_id)
        return api_response(200, True, message="토큰 재발급 완료", data={"access_token": access_token})
    except Exception:
        return api_response(401, False, message="유효하지 않은 토큰입니다.")


def handle_keep(event):
    token = _extract_bearer_token(event)
    if not token:
        return api_response(401, False, message="토큰이 없거나 형식이 잘못되었습니다.")

    try:
        payload = verify_access_token(token)
        user_id = int(payload.get("user_id"))
    except jwt.InvalidTokenError:
        return api_response(401, False, message="유효하지 않거나 만료된 토큰입니다.")

    try:
        user = get_user_for_keep(user_id)
        if not user:
            return api_response(404, False, message="존재하지 않는 회원입니다.")

        bookmarked_id = get_bookmark_event_ids(user_id)
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
        return api_response(500, False, message="서버 에러 발생")


def handle_logout(event):
    token = _extract_bearer_token(event)
    if not token:
        return api_response(401, False, message="토큰이 없거나 형식이 잘못되었습니다.")

    try:
        payload = verify_access_token(token)
        user_id = int(payload.get("user_id"))
    except jwt.InvalidTokenError:
        return api_response(401, False, message="유효하지 않거나 만료된 토큰입니다.")

    try:
        # access token 즉시 무효화를 위해 블랙리스트 등록
        access_exp = get_token_exp_unverified(token)
        blacklist_access_token(token, expires_at_unix=access_exp)

        delete_target_token = _get_refresh_token(event)
        if not delete_target_token:
            return api_response(400, False, message="삭제할 토큰이 없습니다.")

        revoke_refresh_session(user_id, delete_target_token)
        return api_response(
            200,
            True,
            message="로그아웃 성공",
            headers={
                "Set-Cookie": "refresh_token=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
            },
        )
    except Exception:
        return api_response(200, True, message="로그아웃 처리됨")
