from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict

from services.auth_repository import get_bookmark_event_ids, get_user_by_provider
from services.session_store import store_refresh_session
from services.token_service import get_token_exp_unverified, issue_access_token, issue_refresh_token, issue_register_token
from utils.request import parse_json_body
from utils.response import api_response

logger = logging.getLogger(__name__)

PROVIDER_CONFIG = {
    "kakao": {
        "token_url": "https://kauth.kakao.com/oauth/token",
        "user_info_url": "https://kapi.kakao.com/v2/user/me",
        "client_id_env": "KAKAO_REST_API_KEY",
        "client_secret_env": "KAKAO_ACCESS_TOKEN_CLIENT_SECRET",
        "redirect_uri_env": "KAKAO_REDIRECT_URI",
    },
    "google": {
        "token_url": "https://oauth2.googleapis.com/token",
        "user_info_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "client_id_env": "GOOGLE_REST_API_KEY",
        "client_secret_env": "GOOGLE_ACCESS_TOKEN_CLIENT_SECRET",
        "redirect_uri_env": "GOOGLE_REDIRECT_URI",
    },
    "naver": {
        "token_url": "https://nid.naver.com/oauth2.0/token",
        "user_info_url": "https://openapi.naver.com/v1/nid/me",
        "client_id_env": "NAVER_REST_API_KEY",
        "client_secret_env": "NAVER_ACCESS_TOKEN_CLIENT_SECRET",
        "redirect_uri_env": "NAVER_REDIRECT_URI",
    },
}


@dataclass
class AuthFlowError(Exception):
    status_code: int
    message: str

    def __str__(self) -> str:
        return self.message


def _http_post_form(url: str, data: Dict[str, Any]) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=10) as resp:
        text = resp.read().decode("utf-8")
        return json.loads(text)


def _http_get_json(url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    req = urllib.request.Request(url, method="GET")
    for key, value in headers.items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=10) as resp:
        text = resp.read().decode("utf-8")
        return json.loads(text)


def _extract_provider_id(provider: str, user_info: Dict[str, Any]) -> str:
    if provider == "kakao":
        return str(user_info.get("id", ""))
    if provider == "google":
        return str(user_info.get("id", ""))
    if provider == "naver":
        return str(user_info.get("response", {}).get("id", ""))
    return ""


def _exchange_oauth_code(provider: str, code: str, state: str | None) -> str:
    cfg = PROVIDER_CONFIG[provider]
    client_id = os.getenv(cfg["client_id_env"], "")
    client_secret = os.getenv(cfg["client_secret_env"], "")
    redirect_uri = os.getenv(cfg["redirect_uri_env"], "")

    if not client_id or not client_secret or not redirect_uri:
        logger.error("social_login missing_oauth_config provider=%s", provider)
        raise AuthFlowError(500, "서버 에러")

    data: Dict[str, Any] = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "code": code,
    }
    if provider == "naver":
        if not state:
            logger.warning("social_login missing_state provider=%s", provider)
            raise AuthFlowError(400, "인가 코드 에러.")
        data["state"] = state

    try:
        token_payload = _http_post_form(cfg["token_url"], data)
    except (urllib.error.HTTPError, urllib.error.URLError):
        logger.exception("social_login oauth_token_exchange_failed provider=%s", provider)
        provider_fail_messages = {
            "kakao": "카카오 액세스 토큰 발급 실패",
            "google": "구글 액세스 토큰 발급 실패",
            "naver": "네이버 액세스 토큰 발급 실패",
        }
        raise AuthFlowError(400, provider_fail_messages.get(provider, "액세스 토큰 발급 실패"))

    access_token = token_payload.get("access_token", "")
    if not access_token:
        logger.warning("social_login missing_provider_access_token provider=%s", provider)
        provider_fail_messages = {
            "kakao": "카카오 액세스 토큰 발급 실패",
            "google": "구글 액세스 토큰 발급 실패",
            "naver": "네이버 액세스 토큰 발급 실패",
        }
        raise AuthFlowError(400, provider_fail_messages.get(provider, "액세스 토큰 발급 실패"))

    return str(access_token)


def _fetch_provider_id(provider: str, provider_access_token: str) -> str:
    cfg = PROVIDER_CONFIG[provider]
    try:
        user_info = _http_get_json(
            cfg["user_info_url"],
            headers={"Authorization": f"Bearer {provider_access_token}"},
        )
    except (urllib.error.HTTPError, urllib.error.URLError):
        logger.exception("social_login user_info_fetch_failed provider=%s", provider)
        provider_fail_messages = {
            "kakao": "사용자 정보 조회 실패",
            "google": "사용자 정보 조회 실패",
            "naver": "네이버 사용자 정보 조회 실패",
        }
        raise AuthFlowError(500, provider_fail_messages.get(provider, "사용자 정보 조회 실패"))

    provider_id = _extract_provider_id(provider, user_info)
    if not provider_id:
        logger.warning("social_login missing_provider_id provider=%s", provider)
        provider_fail_messages = {
            "kakao": "사용자 정보 조회 실패",
            "google": "사용자 정보 조회 실패",
            "naver": "네이버 사용자 정보 조회 실패",
        }
        raise AuthFlowError(500, provider_fail_messages.get(provider, "사용자 정보 조회 실패"))

    return provider_id



def handle_social_login(event, provider: str):
    body = parse_json_body(event)
    code = body.get("code")
    state = body.get("state")

    logger.info("social_login start provider=%s has_code=%s has_state=%s", provider, bool(code), bool(state))

    if not code:
        logger.warning("social_login missing_code provider=%s", provider)
        return api_response(400, False, message="인가 코드 에러.")

    try:
        provider_access_token = _exchange_oauth_code(provider, str(code), str(state) if state else None)
        provider_id = _fetch_provider_id(provider, provider_access_token)

        user = get_user_by_provider(provider, provider_id)
        if not user:
            logger.info("social_login signup_required provider=%s provider_id=%s", provider, provider_id)
            try:
                register_token = issue_register_token(provider=provider, provider_id=provider_id, email=None)
            except Exception:
                logger.exception("social_login register_token_issue_failed provider=%s provider_id=%s", provider, provider_id)
                return api_response(500, False, message="등록 토큰 인코딩 실패")
            return api_response(
                202,
                True,
                message="회원가입이 필요합니다.",
                data={"register_token": register_token},
            )

        user_id = int(user["user_id"])
        access_token = issue_access_token(user_id)
        refresh_token = issue_refresh_token(user_id)
        refresh_exp = get_token_exp_unverified(refresh_token)
        store_refresh_session(user_id, refresh_token, expires_at_unix=refresh_exp)

        bookmarks = get_bookmark_event_ids(user_id)
        logger.info("social_login success provider=%s user_id=%s bookmarks=%s", provider, user_id, len(bookmarks))
        return api_response(
            200,
            True,
            message=f"{user['nickname']} 님! 환영합니다!",
            data={
                "access_token": access_token,
                "user": {
                    "id": user_id,
                    "nickname": user["nickname"],
                    "level": user["level"],
                    "bookmarks": bookmarks,
                },
            },
            headers={
                "Set-Cookie": f"refresh_token={refresh_token}; Max-Age=1209600; Path=/; HttpOnly; SameSite=Lax",
            },
        )
    except AuthFlowError as exc:
        logger.warning("social_login auth_flow_error provider=%s status=%s message=%s", provider, exc.status_code, exc.message)
        return api_response(exc.status_code, False, message=exc.message)
    except Exception:
        logger.exception("social_login unhandled_exception provider=%s", provider)
        return api_response(500, False, message="알 수 없는 오류")
