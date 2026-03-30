from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import Optional

import pymysql


def _build_ssl_context(ca_path: Optional[str]) -> ssl.SSLContext:
    """
    Build strict TLS context for RDS.

    - If `ca_path` is provided, use that CA bundle file.
    - If omitted, use the runtime's default trust store.
    """
    context = ssl.create_default_context()

    if ca_path:
        resolved = Path(ca_path)
        if resolved.exists():
            context.load_verify_locations(cafile=str(resolved))
        # If the path does not exist, keep runtime default trust store.

    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def get_mysql_connection(
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    database: Optional[str] = None,
    ssl_ca: Optional[str] = None,
) -> pymysql.connections.Connection:
    """Create a MySQL connection to RDS with server cert verification.

    Env fallback:
      - DB_HOST
      - DB_PORT
      - DB_USER
      - DB_PASSWORD
      - DB_NAME
      - DB_SSL_CA (optional; when omitted, runtime default CA store is used)
    """
    resolved_host = host or os.getenv("DB_HOST", "stagelog-db-managed-v2.c922amcmeywm.ap-northeast-2.rds.amazonaws.com")
    resolved_port = int(port or os.getenv("DB_PORT", "3306"))
    resolved_user = user or os.getenv("DB_USER", "admin")
    resolved_password = password or os.getenv("DB_PASSWORD", "")
    resolved_database = database or os.getenv("DB_NAME", "stagelog-db-managed")
    resolved_ssl_ca = (ssl_ca if ssl_ca is not None else os.getenv("DB_SSL_CA", "")).strip() or None

    if not resolved_password:
        raise ValueError("DB_PASSWORD is required")

    connection = pymysql.connect(
        host=resolved_host,
        port=resolved_port,
        user=resolved_user,
        password=resolved_password,
        database=resolved_database,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
        read_timeout=5,
        write_timeout=5,
        ssl=_build_ssl_context(resolved_ssl_ca),
        autocommit=True,
    )
    return connection
