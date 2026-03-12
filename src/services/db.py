from __future__ import annotations

import os
from typing import Optional

import pymysql


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
      - DB_SSL_CA
    """
    resolved_host = host or os.getenv("DB_HOST", "stagelog-db-managed-v2.c922amcmeywm.ap-northeast-2.rds.amazonaws.com")
    resolved_port = int(port or os.getenv("DB_PORT", "3306"))
    resolved_user = user or os.getenv("DB_USER", "admin")
    resolved_password = password or os.getenv("DB_PASSWORD", "")
    resolved_database = database or os.getenv("DB_NAME", "stagelog-db-managed")
    resolved_ssl_ca = ssl_ca or os.getenv("DB_SSL_CA", "/certs/global-bundle.pem")

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
        ssl={
            "ca": resolved_ssl_ca,
            "check_hostname": True,
        },
        autocommit=True,
    )
    return connection
