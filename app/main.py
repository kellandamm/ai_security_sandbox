"""
FastAPI application — the orchestrator.

Middleware stack (outer → inner):
  1. CorrelationIdMiddleware  — generate/propagate X-Correlation-ID
  2. AuditMiddleware          — log every request/response
  3. KillSwitchMiddleware     — global kill switch on every request
  4. RateLimitMiddleware      — token-bucket backstop behind APIM

Routes:
  POST   /runs                    — start a sandboxed agent run
  GET    /runs/{run_id}           — poll run status
  POST   /runs/{run_id}/approve   — Logic App approval callback (internal)
  DELETE /runs/{run_id}           — emergency kill a specific run
  GET    /health                  — liveness probe
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Header, Request, Response, status
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

from agent import resolve_approval, run_agent
from audit import AuditLogger
from kill_switch import KillSwitchClient, KillSwitchError
from models.audit_event import ActionType, Outcome, PolicyDecision
from models.requests import (
    AgentRunRequest, AgentRunResponse, ApprovalCallbackRequest,
    KillRunRequest, RunStatus, RunStatusResponse,
)
from rate_limiter import RateLimiter, RateLimitExceeded
from sandbox import EphemeralWorkspace

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

APPROVAL_WEBHOOK_SECRET = os.environ.get("APPROVAL_WEBHOOK_SECRET", "")

# ── In-memory run registry (replace with distributed cache for multi-replica) ─
_runs: dict[str, dict[str, Any]] = {}
_run_tasks: dict[str, asyncio.Task] = {}

# ── Shared singletons ──────────────────────────────────────────────────────────
_rate_limiter = RateLimiter()
_kill_switch = KillSwitchClient()


# ── Middleware ─────────────────────────────────────────────────────────────────

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "correlation_id": getattr(request.state, "correlation_id", ""),
            },
        )
        return response


class KillSwitchMiddleware(BaseHTTPMiddleware):
    """Block all requests if global kill switch is active. Skips /health."""
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        try:
            _kill_switch.check()
        except KillSwitchError as exc:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": f"Service disabled: {exc.flag_name}"},
                headers={"X-Kill-Switch": exc.flag_name},
            )
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-agent-id token-bucket rate limiter."""
    async def dispatch(self, request: Request, call_next):
        agent_id = request.headers.get("X-Agent-ID", "anonymous")
        try:
            _rate_limiter.check(agent_id)
        except RateLimitExceeded as exc:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded", "retry_after": exc.retry_after},
                headers={"Retry-After": str(int(exc.retry_after) + 1)},
            )
        return await call_next(request)


# ── App factory ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AI Security Sandbox starting")
    yield
    logger.info("AI Security Sandbox shutting down")
    for task in _run_tasks.values():
        task.cancel()


app = FastAPI(
    title="AI Security Sandbox",
    description="Sandboxed AI agent execution with enterprise-grade security controls",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,   # disable public Swagger in production
    redoc_url=None,
)

# Register middleware in reverse order (last added = outermost)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(KillSwitchMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(CorrelationIdMiddleware)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/runs", response_model=AgentRunResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_run(request: AgentRunRequest, req: Request):
    run_id = str(uuid.uuid4())
    correlation_id = getattr(req.state, "correlation_id", run_id)

    # Check agent-type kill switch before even queuing
    try:
        _kill_switch.check(agent_type=request.agent_type.value)
    except KillSwitchError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Agent type disabled: {exc.flag_name}",
        )

    now = datetime.now(timezone.utc).isoformat()
    _runs[run_id] = {
        "run_id": run_id,
        "status": RunStatus.QUEUED,
        "agent_type": request.agent_type.value,
        "result": None,
        "error": None,
        "created_at": now,
        "updated_at": now,
        "correlation_id": correlation_id,
    }

    # Kick off async execution — one task per run
    task = asyncio.create_task(_execute_run(run_id, request, correlation_id))
    _run_tasks[run_id] = task

    return AgentRunResponse(
        run_id=run_id,
        status=RunStatus.QUEUED,
        correlation_id=correlation_id,
    )


async def _execute_run(run_id: str, request: AgentRunRequest, correlation_id: str):
    """Background task: run the agent inside an ephemeral workspace."""
    request.correlation_id = run_id  # use run_id as the correlation anchor
    auditor = AuditLogger(run_id=run_id, agent_type=request.agent_type.value, correlation_id=correlation_id)

    _runs[run_id]["status"] = RunStatus.RUNNING
    _runs[run_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

    try:
        async with EphemeralWorkspace(run_id=run_id, auditor=auditor) as workspace:
            result = await run_agent(request, workspace)
        _runs[run_id]["status"] = RunStatus.COMPLETED
        _runs[run_id]["result"] = result
    except Exception as exc:
        logger.error("Run %s failed: %s", run_id, exc)
        _runs[run_id]["status"] = RunStatus.FAILED
        _runs[run_id]["error"] = str(exc)
    finally:
        _runs[run_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
        _run_tasks.pop(run_id, None)


@app.get("/runs/{run_id}", response_model=RunStatusResponse)
async def get_run(run_id: str):
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    return RunStatusResponse(**run)


@app.post("/runs/{run_id}/approve", status_code=status.HTTP_204_NO_CONTENT)
async def approval_callback(
    run_id: str,
    body: ApprovalCallbackRequest,
    x_callback_token: Optional[str] = Header(None),
):
    """
    Internal endpoint: Logic App posts approval decision here.
    Validates the HMAC callback token to prevent spoofing.
    """
    if not _runs.get(run_id):
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")

    # Validate callback token (HMAC of run_id signed with the webhook secret)
    if APPROVAL_WEBHOOK_SECRET and x_callback_token:
        expected = hmac.new(
            APPROVAL_WEBHOOK_SECRET.encode(),
            run_id.encode(),
            "sha256",
        ).hexdigest()
        if not hmac.compare_digest(expected, x_callback_token or ""):
            raise HTTPException(status_code=401, detail="Invalid callback token")

    resolve_approval(run_id, body.approved)
    _runs[run_id]["status"] = (
        RunStatus.RUNNING if body.approved else RunStatus.FAILED
    )
    _runs[run_id]["updated_at"] = datetime.now(timezone.utc).isoformat()


@app.delete("/runs/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
async def kill_run(run_id: str, body: KillRunRequest):
    """Emergency kill a specific run. Cancels the background task."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")

    task = _run_tasks.get(run_id)
    if task and not task.done():
        task.cancel()

    _runs[run_id]["status"] = RunStatus.KILLED
    _runs[run_id]["error"] = f"Killed by operator: {body.reason}"
    _runs[run_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

    logger.warning("Run %s killed by operator: %s", run_id, body.reason)
