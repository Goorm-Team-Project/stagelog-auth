from __future__ import annotations

from typing import Any, Dict, List, Optional

from services.db import get_mysql_connection


def get_user_by_provider(provider: str, provider_id: str) -> Optional[Dict[str, Any]]:
    query = """
    SELECT user_id, nickname, level
    FROM users
    WHERE provider = %s AND provider_id = %s
    LIMIT 1
    """
    with get_mysql_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (provider, provider_id))
            return cur.fetchone()


def get_user_for_keep(user_id: int) -> Optional[Dict[str, Any]]:
    query = """
    SELECT user_id, nickname, level
    FROM users
    WHERE user_id = %s
    LIMIT 1
    """
    with get_mysql_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            return cur.fetchone()


def user_exists(user_id: int) -> bool:
    query = "SELECT 1 AS ok FROM users WHERE user_id = %s LIMIT 1"
    with get_mysql_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            return cur.fetchone() is not None


def get_bookmark_event_ids(user_id: int) -> List[int]:
    query = """
    SELECT event_id
    FROM bookmark
    WHERE user_id = %s
    ORDER BY bookmark_id DESC
    """
    with get_mysql_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id,))
            rows = cur.fetchall() or []
    return [int(row["event_id"]) for row in rows if row.get("event_id") is not None]


def insert_refresh_token(user_id: int, token: str) -> None:
    query = "INSERT INTO refresh_tokens (user_id, token, created_at) VALUES (%s, %s, NOW())"
    with get_mysql_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id, token))


def has_refresh_token(user_id: int, token: str) -> bool:
    query = "SELECT 1 AS ok FROM refresh_tokens WHERE user_id = %s AND token = %s LIMIT 1"
    with get_mysql_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (user_id, token))
            return cur.fetchone() is not None


def delete_refresh_token(user_id: int, token: str) -> int:
    query = "DELETE FROM refresh_tokens WHERE user_id = %s AND token = %s"
    with get_mysql_connection() as conn:
        with conn.cursor() as cur:
            affected = cur.execute(query, (user_id, token))
    return int(affected or 0)
