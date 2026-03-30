from __future__ import annotations

from utils.response import api_response


def handle_health(_event):
    return api_response(200, True, message="ok", data={"service": "auth-service"})
