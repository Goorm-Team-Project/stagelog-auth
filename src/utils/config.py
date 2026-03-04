from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class Settings:
    jwt_issuer: str
    jwt_audience: str
    jwt_algorithm: str
    jwt_access_ttl_seconds: int
    jwt_refresh_ttl_seconds: int
    jwt_secret_key: str
    jwt_public_jwk_raw: str


    @property
    def public_jwk(self) -> Dict[str, Any]:
        if not self.jwt_public_jwk_raw:
            return {}
        try:
            data = json.loads(self.jwt_public_jwk_raw)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
        return {}


def load_settings() -> Settings:
    return Settings(
        jwt_issuer=os.getenv("JWT_ISSUER", "stagelog-auth"),
        jwt_audience=os.getenv("JWT_AUDIENCE", "stagelog-api"),
        jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
        jwt_access_ttl_seconds=int(os.getenv("JWT_ACCESS_TTL_SECONDS", "1800")),
        jwt_refresh_ttl_seconds=int(os.getenv("JWT_REFRESH_TTL_SECONDS", str(14 * 24 * 60 * 60))),
        jwt_secret_key=os.getenv("JWT_SECRET_KEY", ""),
        jwt_public_jwk_raw=os.getenv("JWT_PUBLIC_JWK", ""),
    )
