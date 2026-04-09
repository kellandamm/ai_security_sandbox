"""
FastAPI application — the orchestrator.

Middleware stack (outer → inner):
  1. CORSMiddleware          — allow the frontend origin
  2. CorrelationIdMiddleware — generate/propagate X-Correlation-ID
  3. AuditMiddleware         — log every request/response
  4. KillSwitchMiddleware    — global kill switch on every request
  5. RateLimitMiddleware     — token-bucket backstop behind APIM

Routes:
  POST   /runs                     — start a sandboxed agent run (JSON or multipart)
  GET    /runs/{run_id}            — poll run status
  GET    /stream/runs/{run_id}     — SSE stream of live audit events
  GET    /runs/{run_id}/timeline   — query Log Analytics for post-run timeline
  POST   /runs/{run_id}/approve    — Logic App approval callback
  DELETE /runs/{run_id}            — emergency kill a specific run
  GET    /alerts                   — recent Sentinel alerts
  PUT    /kill-switches/{flag}     — toggle an App Configuration feature flag
  GET    /kill-switches            — list current flag states
  GET    /health                   — liveness probe
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, File, Form, HTTPException, Header, Request, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from agent import resolve_approval, run_agent
from audit import AuditLogger
from kill_switch import KillSwitchClient, KillSwitchError
from log_analytics import LogAnalyticsClient
from models.audit_event import ActionType, Outcome, PolicyDecision
from models.requests import (
    AgentRunRequest, AgentRunResponse, ApprovalCallbackRequest,
    AgentType, KillRunRequest, RunStatus, RunStatusResponse,
)
from rate_limiter import RateLimiter, RateLimitExceeded
from sandbox import EphemeralWorkspace

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

APPROVAL_WEBHOOK_SECRET = os.environ.get("APPROVAL_WEBHOOK_SECRET", "")
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "*")

# ── Shared state ──────────────────────────────────────────────────────────────
_runs: dict[str, dict[str, Any]] = {}
_run_tasks: dict[str, asyncio.Task] = {}
_run_event_queues: dict[str, asyncio.Queue] = {}   # SSE queues keyed by run_id

_rate_limiter = RateLimiter()
_kill_switch = KillSwitchClient()
_la_client = LogAnalyticsClient()


# ── SSE helpers ───────────────────────────────────────────────────────────────

def _push_run_event(run_id: str, event: dict) -> None:
    """Called by AuditLogger.on_event — puts event onto the SSE queue."""
    q = _run_event_queues.get(run_id)
    if q:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


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
            "request method=%s path=%s status=%s duration_ms=%s",
            request.method, request.url.path, response.status_code, duration_ms,
        )
        return response


class KillSwitchMiddleware(BaseHTTPMiddleware):
    _EXEMPT = {"/health", "/kill-switches", "/alerts"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self._EXEMPT or request.url.path.startswith("/stream/"):
            return await call_next(request)
        # Allow PUT to kill-switches so operators can re-enable
        if request.method == "PUT" and request.url.path.startswith("/kill-switches/"):
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
    logger.info("Shutting down — cancelling %d active runs", len(_run_tasks))
    for task in list(_run_tasks.values()):
        task.cancel()


app = FastAPI(
    title="AI Security Sandbox",
    description="Sandboxed AI agent execution with enterprise-grade security controls",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(KillSwitchMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(CorrelationIdMiddleware)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/runs", response_model=AgentRunResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_run(
    req: Request,
    # Accept either JSON body or multipart form with optional file upload
    agent_type: str = Form(default="data-analyst"),
    task: str = Form(default=""),
    file: Optional[UploadFile] = File(default=None),
    # JSON body path (raw body parsed below if Content-Type is application/json)
):
    """
    Start a sandboxed agent run.
    Accepts multipart/form-data (with optional file upload) or application/json.
    """
    content_type = req.headers.get("content-type", "")

    # JSON path
    if "application/json" in content_type:
        body = await req.json()
        run_request = AgentRunRequest(**body)
    else:
        # Multipart path
        try:
            agent_type_enum = AgentType(agent_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown agent_type: {agent_type!r}")
        run_request = AgentRunRequest(agent_type=agent_type_enum, task=task or "Analyse the uploaded document.")

    run_id = str(uuid.uuid4())
    correlation_id = getattr(req.state, "correlation_id", run_id)
    run_request.correlation_id = run_id

    # Check agent-type kill switch before queuing
    try:
        _kill_switch.check(agent_type=run_request.agent_type.value)
    except KillSwitchError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Agent type disabled: {exc.flag_name}",
        )

    # Store uploaded file content for the agent to use
    uploaded_bytes: Optional[bytes] = None
    uploaded_filename: Optional[str] = None
    if file and file.filename:
        uploaded_bytes = await file.read()
        uploaded_filename = file.filename

    now = datetime.now(timezone.utc).isoformat()
    _runs[run_id] = {
        "run_id": run_id,
        "status": RunStatus.QUEUED,
        "agent_type": run_request.agent_type.value,
        "result": None,
        "error": None,
        "created_at": now,
        "updated_at": now,
        "correlation_id": correlation_id,
        "uploaded_filename": uploaded_filename,
    }

    # Create SSE queue before spawning the task so no events are missed
    _run_event_queues[run_id] = asyncio.Queue(maxsize=500)

    task_obj = asyncio.create_task(
        _execute_run(run_id, run_request, correlation_id, uploaded_bytes, uploaded_filename)
    )
    _run_tasks[run_id] = task_obj

    return AgentRunResponse(run_id=run_id, status=RunStatus.QUEUED, correlation_id=correlation_id)


async def _execute_run(
    run_id: str,
    request: AgentRunRequest,
    correlation_id: str,
    uploaded_bytes: Optional[bytes],
    uploaded_filename: Optional[str],
):
    """Background task: run the agent inside an ephemeral workspace."""

    def push_event(event: dict):
        _push_run_event(run_id, event)

    auditor = AuditLogger(
        run_id=run_id,
        agent_type=request.agent_type.value,
        correlation_id=correlation_id,
        on_event=push_event,
    )

    _runs[run_id]["status"] = RunStatus.RUNNING
    _runs[run_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

    try:
        async with EphemeralWorkspace(run_id=run_id, auditor=auditor) as workspace:
            # Stage uploaded file into the sandbox read area
            if uploaded_bytes and uploaded_filename:
                import mimetypes
                ct, _ = mimetypes.guess_type(uploaded_filename)
                ct = ct or "text/plain"
                # Place in write area so the agent can read it back
                vpath = f"/workspace/{run_id}/write/{uploaded_filename}"
                workspace.write_file(vpath, uploaded_bytes, ct)
                # Augment task with file context
                request.task = (
                    f"{request.task}\n\nA file has been staged at: {vpath}"
                )

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
        # Signal SSE consumers that the run is over
        q = _run_event_queues.get(run_id)
        if q:
            await q.put({"type": "run_complete", "run_id": run_id,
                         "status": _runs[run_id]["status"].value})


@app.get("/runs/{run_id}", response_model=RunStatusResponse)
async def get_run(run_id: str):
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    return RunStatusResponse(**run)


@app.get("/stream/runs/{run_id}")
async def stream_run_events(run_id: str):
    """
    Server-Sent Events stream of live audit events for a specific run.
    The browser connects here immediately after POST /runs and receives
    every OPA decision, sandbox check, and tool call result in real time.
    """
    if run_id not in _runs:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")

    q = _run_event_queues.get(run_id)
    if q is None:
        # Run already completed — return empty stream
        async def empty():
            yield "data: {\"type\": \"run_complete\"}\n\n"
        return StreamingResponse(empty(), media_type="text/event-stream")

    async def event_generator():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=25)
                except asyncio.TimeoutError:
                    # Keepalive ping
                    yield "data: {\"type\":\"ping\"}\n\n"
                    continue

                yield f"data: {json.dumps(event, default=str)}\n\n"

                # Sentinel: run finished
                if event.get("type") == "run_complete":
                    break
        except asyncio.CancelledError:
            pass
        finally:
            _run_event_queues.pop(run_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/runs/{run_id}/timeline")
async def get_run_timeline(run_id: str):
    """
    Query Log Analytics for the full post-run audit timeline.
    Returns the KQL query used alongside the results so the UI can display both.
    """
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")

    events = _la_client.query_run_timeline(run_id)
    kql = _la_client.get_kql_for_run(run_id)

    # Fall back to in-memory audit events if Log Analytics isn't wired up
    if not events:
        events = [
            {k: str(v) for k, v in e.items()}
            for e in _get_in_memory_events(run_id)
        ]

    return {"run_id": run_id, "events": events, "kql_query": kql}


# Simple in-memory event store as fallback (populated by SSE push)
_in_memory_events: dict[str, list[dict]] = {}

def _get_in_memory_events(run_id: str) -> list[dict]:
    return _in_memory_events.get(run_id, [])


@app.get("/alerts")
async def get_alerts():
    """Return recent Sentinel analytics rule alerts."""
    alerts = _la_client.get_recent_sentinel_alerts(limit=10)
    return {"alerts": alerts}


@app.get("/kill-switches")
async def list_kill_switches():
    """Return current state of all feature flags."""
    flags = [
        "agent-execution-enabled",
        "file-write-enabled",
        "network-egress-enabled",
        "openai-calls-enabled",
        "agent-data-analyst-enabled",
        "agent-web-researcher-enabled",
    ]
    result = {}
    for flag in flags:
        result[flag] = _kill_switch.is_enabled() if flag == "agent-execution-enabled" \
            else _kill_switch._read_flag(flag)
    return {"flags": result}


@app.put("/kill-switches/{flag_name}", status_code=status.HTTP_204_NO_CONTENT)
async def toggle_kill_switch(flag_name: str, req: Request):
    """
    Toggle an App Configuration feature flag from the UI.
    Body: {"enabled": true|false}
    """
    allowed_flags = {
        "agent-execution-enabled", "file-write-enabled", "network-egress-enabled",
        "openai-calls-enabled", "agent-data-analyst-enabled", "agent-web-researcher-enabled",
    }
    if flag_name not in allowed_flags:
        raise HTTPException(status_code=400, detail=f"Unknown flag: {flag_name!r}")

    body = await req.json()
    enabled = bool(body.get("enabled", True))

    try:
        from azure.appconfiguration import AzureAppConfigurationClient, ConfigurationSetting
        from azure.identity import DefaultAzureCredential
        endpoint = os.environ.get("APP_CONFIG_ENDPOINT", "")
        if endpoint:
            client = AzureAppConfigurationClient(base_url=endpoint, credential=DefaultAzureCredential())
            value = json.dumps({"id": flag_name, "enabled": enabled, "conditions": {"client_filters": []}})
            client.set_configuration_setting(ConfigurationSetting(
                key=f".appconfig.featureflag/{flag_name}",
                label="production",
                value=value,
                content_type="application/vnd.microsoft.appconfig.ff+json;charset=utf-8",
            ))
            # Invalidate local cache
            _kill_switch._cache.pop(flag_name, None)
    except Exception as exc:
        logger.warning("Could not update App Configuration flag %s: %s", flag_name, exc)
        # In demo mode without App Configuration, just update the local cache
        import time
        _kill_switch._cache[flag_name] = (enabled, time.monotonic() + 30)


@app.post("/runs/{run_id}/approve", status_code=status.HTTP_204_NO_CONTENT)
async def approval_callback(
    run_id: str,
    body: ApprovalCallbackRequest,
    x_callback_token: Optional[str] = Header(None),
):
    if not _runs.get(run_id):
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")

    if APPROVAL_WEBHOOK_SECRET and x_callback_token:
        expected = hmac.new(
            APPROVAL_WEBHOOK_SECRET.encode(), run_id.encode(), "sha256"
        ).hexdigest()
        if not hmac.compare_digest(expected, x_callback_token or ""):
            raise HTTPException(status_code=401, detail="Invalid callback token")

    resolve_approval(run_id, body.approved)
    _runs[run_id]["status"] = RunStatus.RUNNING if body.approved else RunStatus.FAILED
    _runs[run_id]["updated_at"] = datetime.now(timezone.utc).isoformat()


@app.delete("/runs/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
async def kill_run(run_id: str, body: KillRunRequest):
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")

    task = _run_tasks.get(run_id)
    if task and not task.done():
        task.cancel()

    _runs[run_id]["status"] = RunStatus.KILLED
    _runs[run_id]["error"] = f"Killed by operator: {body.reason}"
    _runs[run_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
    logger.warning("Run %s killed: %s", run_id, body.reason)
