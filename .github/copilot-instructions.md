# Copilot Instructions — AI Security Sandbox

## Build, Test & Lint

```bash
# Backend unit tests (no Azure credentials needed)
pip install -r app/requirements.txt pytest
pytest tests/unit/ -v --tb=short

# Single test file or test case
pytest tests/unit/test_sandbox.py -v
pytest tests/unit/test_policy.py::TestOPAClientDeny::test_deny_is_cached_for_30_seconds -v

# Python lint
ruff check . --select E,W,F,I

# OPA policy validation and tests
opa check policies/
opa test policies/ -v

# Bicep lint
bicep lint infra/main.bicep
bicep lint infra/modules/*.bicep

# Frontend
cd frontend && npm install && npm run lint && npm run build

# Run app locally (empty env vars prevent import failures)
cd app
APP_CONFIG_ENDPOINT="" WORKSPACE_STORAGE_ACCOUNT="" \
AUDIT_STORAGE_ACCOUNT="" AZURE_OPENAI_ENDPOINT="" \
  uvicorn main:app --reload --port 8000
```

Tests mock all Azure services — they run fully offline.

## Architecture

This is an Azure-hosted sandbox for running AI agents with enterprise security controls. Two containers — an always-on **Orchestrator** (FastAPI) and ephemeral **Agent Runner** jobs (Container Apps Jobs) — sit inside a VNet-injected Container Apps Environment, fronted by Azure API Management.

**Request flow:** APIM (rate limit + JWT) → Orchestrator receives `POST /runs` → spawns `_execute_run()` as `asyncio.Task` → creates `EphemeralWorkspace` (blob container per run) → runs agent loop → each tool call gated by OPA sidecar + capability manifest → cleanup.

**Security layers enforced at every tool call:**
1. Kill switch check (Azure App Configuration feature flags)
2. Capability manifest check (per-agent-type tool allowlist in `capability_manifest.py`)
3. OPA policy check (Rego sidecar at `localhost:8181`)
4. Sandbox validation (path canonicalization, magic bytes, quotas in `sandbox.py`)
5. Audit logging (structured events → Log Analytics + WORM append blob)

**Two agent types** with different capabilities:
- `data-analyst` — file ops + OpenAI only, no network egress, 50k token cap, 3 min limit
- `web-researcher` — adds `http_get` to `api.github.com` and `api.wikipedia.org`, 100k tokens, 5 min limit

**Frontend** is a React 18 + Vite + Tailwind SPA with a SOC console aesthetic. It streams audit events in real time via SSE (`useSSE` hook with exponential backoff reconnection). Nginx reverse-proxies `/api/*` to the orchestrator.

## Key Conventions

### Fail-Closed Design

Every external dependency defaults to DENY when unreachable:
- OPA sidecar down → `PolicyDenyError` (deny all tool calls)
- App Configuration unreachable → kill switch returns `False` (block execution)
- Audit logging failure → log warning but don't crash the agent

This is the most critical convention. Never add a code path that defaults to ALLOW on error.

### Defense in Depth

Capability restrictions are enforced in two independent systems: the Python `capability_manifest.py` and OPA policies (`policies/data/allowed_tools.json`). Both must agree. When adding a new agent type or capability, update both.

### Async Patterns (Backend)

- All FastAPI route handlers are `async def`
- `EphemeralWorkspace` is an async context manager (`__aenter__`/`__aexit__`)
- Agent runs execute as `asyncio.Task` background tasks (API returns 202 immediately)
- Approval flow uses `asyncio.Future` with 24-hour timeout
- SSE streaming uses `asyncio.Queue` for event delivery

### Type Hints & Models

- Full type annotations on all functions including return types
- Pydantic v2 models for all request/response types and audit events (`app/models/`)
- Enums for `AgentType`, `RunStatus`, `ActionType`, `PolicyDecision`, `Outcome`
- `AuditEvent.to_log_analytics_row()` converts to camelCase for Azure DCR ingestion

### Error Hierarchy

```
SandboxError
  ├── PathTraversalError
  ├── ForbiddenFileTypeError
  ├── QuotaExceededError
  └── ReadOnlyPathError
PolicyDenyError
ApprovalRequiredError
KillSwitchError
RateLimitExceeded
```

### OPA Policies (Rego)

Four policy files enforce different concerns:
- `agent_actions.rego` — primary allow/deny/requires_approval decisions
- `filesystem.rego` — path traversal prevention, filename validation, content-type whitelist
- `network.rego` — egress FQDN allowlist, SSRF prevention (blocks `169.254.169.254`, private ranges)
- `secrets.rego` — credential leak detection in agent output (AWS keys, Azure SAS, GitHub PATs, PEM keys)

Policy data lives in `policies/data/*.json`. High-risk actions (POST/PUT/DELETE/PATCH) require human approval via Logic App webhook.

### Audit Trail

Every file operation and tool call emits an `AuditEvent` with SHA-256 content hash. Events go to three sinks: stdout (container logs), Log Analytics custom table (`AiAgentAudit_CL`), and WORM append-only blob. Audit failures must never crash the agent.

### Infrastructure (Bicep)

Modules deploy in dependency order: networking → security → storage → monitoring → compute → apim → approvals → killSwitch. Resource naming uses `{abbreviation}-{resourceToken}` pattern from `infra/abbreviations.json`. All inter-service auth uses Managed Identity — no API keys or passwords.

### Frontend Conventions

- State management via React hooks only (no Redux) — centralized in `App.tsx`
- Custom `soc-*` Tailwind color palette for the dark SOC console theme
- Component CSS uses `@layer` classes: `.panel`, `.badge-*`, `.btn-*`, `.event-row`
- Attack templates defined in `frontend/src/data/attackTemplates.ts`
