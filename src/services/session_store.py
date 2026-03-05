from __future__ import annotations

import hashlib
import os
import time
from typing import Optional

import redis

from services.auth_repository import delete_refresh_token, has_refresh_token, insert_refresh_token


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _refresh_redis_key(user_id: int, token: str) -> str:
    return f"auth:refresh:{user_id}:{_token_hash(token)}"


def _blacklist_redis_key(token: str) -> str:
    return f"auth:blacklist:access:{_token_hash(token)}"


def _redis_client() -> Optional[redis.Redis]:
    host = os.getenv("REDIS_HOST", "")
    if not host:
        return None

    port = int(os.getenv("REDIS_PORT", "6379"))
    db = int(os.getenv("REDIS_DB", "0"))
    username = os.getenv("REDIS_USERNAME", "") or None
    password = os.getenv("REDIS_PASSWORD", "") or None
    use_ssl = os.getenv("REDIS_SSL", "false").lower() in {"1", "true", "yes"}

    return redis.Redis(
        host=host,
        port=port,
        db=db,
        username=username,
        password=password,
        ssl=use_ssl,
        socket_connect_timeout=1,
        socket_timeout=1,
        decode_responses=True,
    )


def store_refresh_session(user_id: int, refresh_token: str, expires_at_unix: int) -> None:
    # RDS is the durable source.
    insert_refresh_token(user_id, refresh_token)

    ttl = max(int(expires_at_unix - int(time.time())), 1)
    client = _redis_client()
    if not client:
        return

    try:
        client.set(_refresh_redis_key(user_id, refresh_token), "1", ex=ttl)
    except redis.RedisError:
        # Keep service available with RDS-only path.
        return


def is_refresh_session_active(user_id: int, refresh_token: str) -> bool:
    client = _redis_client()
    if client:
        try:
            if client.exists(_refresh_redis_key(user_id, refresh_token)):
                return True
        except redis.RedisError:
            pass

    # Fallback (or source of truth during Redis miss): RDS
    return has_refresh_token(user_id, refresh_token)


def revoke_refresh_session(user_id: int, refresh_token: str) -> None:
    delete_refresh_token(user_id, refresh_token)

    client = _redis_client()
    if not client:
        return
    try:
        client.delete(_refresh_redis_key(user_id, refresh_token))
    except redis.RedisError:
        return


def blacklist_access_token(access_token: str, expires_at_unix: int) -> None:
    ttl = max(int(expires_at_unix - int(time.time())), 1)
    client = _redis_client()
    if not client:
        return

    try:
        client.set(_blacklist_redis_key(access_token), "1", ex=ttl)
    except redis.RedisError:
        return


def is_access_token_blacklisted(access_token: str) -> bool:
    client = _redis_client()
    if not client:
        return False

    try:
        return bool(client.exists(_blacklist_redis_key(access_token)))
    except redis.RedisError:
        # Fail-open to avoid auth outage when Redis is unhealthy.
        return False
