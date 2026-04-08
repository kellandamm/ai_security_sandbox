# AI Security Sandbox

An Azure-hosted AI agent sandbox that demonstrates **enterprise-grade containment** for AI workloads. Every security control is wired to a concrete Azure service and enforced in code — not just documented.

---

## Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  Azure API Management (rate limiting, JWT validation)           │
└────────────────────────┬────────────────────────────────────────┘
                         │ VNet-internal only
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  Container Apps Environment (VNet-injected, internal-only)      │
│                                                                 │
│  ┌─────────────────────┐     ┌───────────────────────────────┐ │
│  │  Orchestrator App   │────▶│  Agent Runner Job (ephemeral) │ │
│  │  (always-on)        │     │  ┌───────────┐ ┌───────────┐  │ │
│  │  • Kill switch gate │     │  │ agent.py  │ │ OPA       │  │ │
│  │  • Rate limiter     │     │  │ sandbox.py│ │ sidecar   │  │ │
│  │  • Run registry     │     │  │ audit.py  │ │ :8181     │  │ │
│  └─────────────────────┘     └───────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
         │                              │
         │ Private Endpoints            │ Private Endpoints
         ▼                              ▼
┌──────────────────┐        ┌──────────────────────────────────┐
│  Azure Key Vault │        │  Azure Storage (two accounts)    │
│  Azure App Config│        │  • Workspace SA (ephemeral ADLS) │
│  App Insights    │        │  • Audit SA (WORM, 365-day lock) │
└──────────────────┘        └──────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  Azure Firewall (DNS proxy, egress allow-list, force-tunnel) │
│  → only *.openai.azure.com, *.monitor.azure.com, etc.        │
└──────────────────────────────────────────────────────────────┘
```

---

## Security Controls

### 1. Least Privilege Access
- Two separate **User-Assigned Managed Identities**: `id-orchestrator` and `id-agent-runner`
- No standing Contributor/Owner roles — all RBAC scoped to exact resources
- `id-agent-runner` gets only: `Storage Blob Data Contributor` on workspace SA, `Cognitive Services OpenAI User` on OpenAI
- Key Vault: RBAC mode only, no legacy access policies, purge-protected
- No API keys or passwords stored anywhere — Managed Identity everywhere

### 2. Human-in-the-Loop Approvals
- **Azure Logic Apps** workflow: HTTP trigger → Teams/email adaptive card → 24h wait → callback
- Agent async-awaits the approval callback via `POST /runs/{run_id}/approve`
- Auto-deny on timeout; HMAC-signed callback tokens prevent spoofing
- OPA policy marks actions as `requires_approval` based on `high_risk_actions.json`

### 3. Policy-as-Code (OPA)
- **Open Policy Agent** runs as a sidecar container in every agent job replica
- Rego bundle loaded from Blob Storage at job start (updatable without redeploy)
- Policy files:
  - `agent_actions.rego` — primary authorization: allow / deny / requires_approval
  - `filesystem.rego` — path validation, filename safety
  - `network.rego` — egress FQDN allow-list, SSRF prevention (IMDS endpoints blocked)
  - `secrets.rego` — credential leak detection in agent output
- OPA unreachable → **fail closed** (deny all)

### 4. Sandboxing (9 Filesystem Rules)
All rules from the article are implemented in `app/sandbox.py`:

| Rule | Implementation |
|---|---|
| 1. Ephemeral workspaces | `EphemeralWorkspace` async context manager — auto-deleted on exit |
| 2. Separate read/write/audit paths | Three virtual path prefixes → separate storage accounts |
| 3. Canonicalize paths | `canonicalize()` with `posixpath.normpath` + ancestry check |
| 4. Ban symlink following | Azure Blob has no symlinks; local ops use `O_NOFOLLOW` |
| 5. noexec/nodev/nosuid | ACA seccomp profile + non-root container user |
| 6. Reject special files | Content-type whitelist + magic byte scan + filename regex |
| 7. Hard quotas | 100 files / 500 MB per run enforced before every write |
| 8. Virtual paths | Agent never sees blob URLs — only `/workspace/{run_id}/write/...` |
| 9. Full audit trail | Every file op emits `AuditEvent` before + after with SHA-256 hash |

### 5. Observability and Logging
- **Log Analytics Workspace** — 90-day retention, 5 GB/day cap, CanNotDelete lock
- **Application Insights** — APM, request tracing
- Custom table `AiAgentAudit_CL` via Data Collection Rule — queryable structured events
- **Microsoft Sentinel** onboarded with 4 analytics rules:
  - Frequent OPA denials (>5 in 10 min)
  - File write outside sandbox path
  - Token spike (>10k tokens/min per run)
  - Kill switch activated
- All audit events also written to WORM append-only blob (tamper-evident)

### 6. Rate Limiting
- **Azure API Management**: `rate-limit-by-key` (100 req/60s per agent-id) + `quota-by-key` (10k/day)
- In-process token bucket (`rate_limiter.py`) as backstop — same 100/60s limit
- Per-run **token budget** enforced by `TokenBudget` class — caps OpenAI spend per agent run

### 7. Capability Isolation
- `capability_manifest.py` defines per-agent-type tool allowlists, egress FQDNs, token budgets, time limits
- `data-analyst` — no network egress, 50k token cap, 3-minute limit
- `web-researcher` — only `api.github.com` + `api.wikipedia.org`, 100k tokens, 5 minutes
- OPA enforces the same constraints independently (defense-in-depth)
- Separate Container App Job per run — each gets a fresh container image layer

### 8. Kill Switches
- **Azure App Configuration** feature flags (fail-closed: unreachable → deny all):
  - `agent-execution-enabled` — global halt
  - `file-write-enabled`, `network-egress-enabled`, `openai-calls-enabled` — capability-level
  - `agent-{type}-enabled` — per-agent-type halt
- Checked on every API request (middleware) and every tool call (agent loop)
- 10-second TTL cache — near-realtime response to flag changes

---

## Containment Layer Mapping

| Layer | Azure / Code |
|---|---|
| Namespaces + OverlayFS | Container Apps Linux namespaces; each Job = fresh image layer |
| seccomp-BPF + Landlock | ACA seccomp profile + `PR_SET_NO_NEW_PRIVS`; `O_NOFOLLOW` in sandbox.py |
| MicroVM (Firecracker) | Container App Jobs on dedicated `D4` workload profiles |
| Network Isolation + DNS Filter | Azure Firewall (DNS proxy) + NSGs + force-tunnel route table |
| Behavioral Monitoring + Secrets | Sentinel analytics rules + `secrets.rego` + structured audit trail |

---

## Repository Structure

```
ai_security_sandbox/
├── infra/
│   ├── main.bicep              # Orchestration entry point (subscription scope)
│   ├── main.bicepparam         # Environment parameters
│   ├── abbreviations.json      # Azure naming conventions
│   └── modules/
│       ├── networking.bicep    # VNet, NSG, Firewall, DNS zones, Private Endpoints
│       ├── security.bicep      # Managed Identities, Key Vault, RBAC
│       ├── storage.bicep       # Ephemeral workspace SA + WORM audit SA
│       ├── monitoring.bicep    # Log Analytics, App Insights, Sentinel, analytics rules
│       ├── compute.bicep       # ACR, Container Apps Env, Orchestrator App, Agent Job
│       ├── apim.bicep          # API Management (rate limiting, JWT, routing)
│       ├── approvals.bicep     # Logic App HITL workflow
│       └── kill_switch.bicep   # App Configuration + feature flags
│
├── app/
│   ├── main.py                 # FastAPI app + 4-layer middleware stack
│   ├── agent.py                # Agent loop with OPA-gated tool dispatch
│   ├── sandbox.py              # 9 filesystem sandboxing rules
│   ├── policy.py               # OPA sidecar client (fail-closed)
│   ├── audit.py                # Structured JSON → Log Analytics + WORM blob
│   ├── kill_switch.py          # App Configuration feature flag client (fail-closed)
│   ├── capability_manifest.py  # Per-agent-type tool + egress allowlists
│   ├── rate_limiter.py         # Token-bucket rate limiter + token budget
│   ├── models/                 # Pydantic models (AuditEvent, requests)
│   ├── Dockerfile
│   └── requirements.txt
│
├── policies/
│   ├── agent_actions.rego      # Primary OPA authorization policy
│   ├── filesystem.rego         # Path + filename validation
│   ├── network.rego            # Egress FQDN allow-list + SSRF prevention
│   ├── secrets.rego            # Credential leak detection
│   └── data/
│       ├── allowed_tools.json  # Per-agent capability manifests
│       └── high_risk_actions.json
│
├── tests/unit/
│   ├── test_sandbox.py         # Path traversal, file type, quota tests
│   ├── test_policy.py          # OPA client allow/deny/approval/fail-closed tests
│   └── test_kill_switch.py     # Feature flag + fail-closed + cache tests
│
├── .github/workflows/
│   ├── ci.yml                  # Lint, unit tests, OPA check, Bicep lint, Docker build
│   └── deploy.yml              # Bicep deploy → build/push images → push OPA bundle
│
└── scripts/
    └── bootstrap.sh            # One-shot OIDC setup for GitHub Actions
```

---

## Deployment

### Prerequisites
- Azure CLI (`az`)
- Bicep CLI (`bicep`)
- Azure subscription with Owner access
- GitHub repository with Actions enabled

### 1. Bootstrap (once)

```bash
export AZURE_SUBSCRIPTION_ID="<your-sub>"
export GITHUB_ORG="kellandamm"
export GITHUB_REPO="ai_security_sandbox"
export ENVIRONMENT="dev"
bash scripts/bootstrap.sh
```

The script outputs 4 secrets to configure in GitHub Actions.

### 2. Deploy

```bash
# Push to main triggers the deploy workflow automatically
git push origin main

# Or trigger manually:
# GitHub → Actions → Deploy → Run workflow → select environment
```

### 3. Test the deployment

```bash
APIM_URL=$(az deployment sub show -n ai-sandbox-1 \
  --query properties.outputs.APIM_GATEWAY_URL.value -o tsv)

# Health check
curl -s ${APIM_URL}/sandbox/health

# Start an agent run
curl -X POST ${APIM_URL}/sandbox/runs \
  -H "Authorization: Bearer <aad-token>" \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: test-agent-001" \
  -d '{"agent_type": "data-analyst", "task": "Summarize any uploaded CSV files."}'

# Poll status
curl ${APIM_URL}/sandbox/runs/<run_id> \
  -H "Authorization: Bearer <aad-token>"
```

### 4. Verify security controls

```bash
# Flip global kill switch OFF
az appconfig kv set --name <appconfig-name> \
  --key ".appconfig.featureflag/agent-execution-enabled" \
  --label production \
  --value '{"id":"agent-execution-enabled","enabled":false,"conditions":{}}'
# Next API call returns HTTP 503 within ~10 seconds

# Re-enable
az appconfig kv set --name <appconfig-name> \
  --key ".appconfig.featureflag/agent-execution-enabled" \
  --label production \
  --value '{"id":"agent-execution-enabled","enabled":true,"conditions":{}}'
```

---

## Local Development

```bash
# Unit tests — no Azure connection needed
pip install -r app/requirements.txt pytest
pytest tests/unit/ -v

# OPA policy checks
opa check policies/
opa test policies/ -v

# Run the app locally
cd app
APP_CONFIG_ENDPOINT="" WORKSPACE_STORAGE_ACCOUNT="" \
AUDIT_STORAGE_ACCOUNT="" AZURE_OPENAI_ENDPOINT="" \
  uvicorn main:app --reload --port 8000
```

---

## Minimum Viable Sandbox

The article's MVS — `Landlock + seccomp + PR_SET_NO_NEW_PRIVS + non-root + cgroups` — maps to:

| MVS Component | This Sandbox |
|---|---|
| Landlock (FS access control) | Blob virtual path enforcement in `sandbox.py` |
| seccomp | ACA workload profile seccomp + `libseccomp-dev` in Dockerfile |
| PR_SET_NO_NEW_PRIVS | Non-root container user (`appuser`, uid 10001) |
| cgroups | ACA job resource limits: `0.5 CPU / 1Gi` per replica |
| non-root | `USER appuser` in Dockerfile, `chmod 700 /app` |
