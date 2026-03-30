from __future__ import annotations

import os
from pathlib import Path

_RUNTIME_ENV_LOADED = False


def _parse_env_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None

    key, value = stripped.split("=", 1)
    key = key.strip()
    if not key:
        return None

    return key, value.strip()


def load_env_file(filename: str = ".env.example") -> None:
    path = Path(__file__).resolve().parents[2] / filename
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_env_line(raw_line)
        if not parsed:
            continue
        key, value = parsed
        os.environ.setdefault(key, value)


def _iter_ssm_parameters(prefixes: list[str]):
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("boto3 is required to load auth lambda config from SSM") from exc

    client = boto3.client("ssm")

    for prefix in prefixes:
        next_token: str | None = None
        while True:
            kwargs = {
                "Path": prefix,
                "Recursive": False,
                "WithDecryption": True,
                "MaxResults": 10,
            }
            if next_token:
                kwargs["NextToken"] = next_token

            response = client.get_parameters_by_path(**kwargs)
            for parameter in response.get("Parameters", []):
                yield parameter

            next_token = response.get("NextToken")
            if not next_token:
                break


def load_ssm_parameters(prefixes_env: str = "AUTH_SSM_PREFIXES") -> None:
    raw_prefixes = os.getenv(prefixes_env, "")
    prefixes = [prefix.strip().rstrip("/") for prefix in raw_prefixes.split(",") if prefix.strip()]
    if not prefixes:
        return

    for parameter in _iter_ssm_parameters(prefixes):
        name = str(parameter["Name"]).rsplit("/", 1)[-1]
        value = str(parameter.get("Value", ""))
        os.environ[name] = value


def load_runtime_env(filename: str = ".env.example") -> None:
    global _RUNTIME_ENV_LOADED

    if _RUNTIME_ENV_LOADED:
        return

    load_env_file(filename)
    load_ssm_parameters()
    _RUNTIME_ENV_LOADED = True
