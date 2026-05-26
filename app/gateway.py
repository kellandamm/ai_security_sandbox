"""Gateway-origin enforcement for deployed orchestrator traffic."""

from __future__ import annotations

import hmac
import os

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

ORCHESTRATOR_GATEWAY_SECRET = os.environ.get("ORCHESTRATOR_GATEWAY_SECRET", "")


class GatewayHeaderMiddleware(BaseHTTPMiddleware):
    _HEADER_NAME = "X-Orchestrator-Gateway-Secret"

    async def dispatch(self, request: Request, call_next):
        if not ORCHESTRATOR_GATEWAY_SECRET:
            return await call_next(request)

        if request.url.path == "/health" or request.url.path.endswith("/approve"):
            return await call_next(request)

        provided_secret = request.headers.get(self._HEADER_NAME, "")
        if not hmac.compare_digest(provided_secret, ORCHESTRATOR_GATEWAY_SECRET):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Requests must enter through API Management."},
            )

        return await call_next(request)
