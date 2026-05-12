# AI Security Sandbox Solution Accelerator Guide

## What This Accelerator Does

AI Security Sandbox is a reference implementation for running AI agents with enterprise security controls. It shows how to place an agent workflow behind gateway protection, policy-as-code, isolated execution, kill switches, and auditable evidence so security teams can evaluate agent behavior before adopting similar patterns in production.

The accelerator is intentionally opinionated. It favors fail-closed behavior, managed identity, per-agent capability isolation, and repeatable demo scenarios over a broad general-purpose agent framework.

## Who It Is For

- Security architects who need a concrete AI workload containment pattern.
- Platform engineers designing governed agent hosting on Azure.
- SOC and detection teams that need audit events, policy denials, and kill-switch scenarios to test response workflows.
- Application teams that want a starting point for safe agent tools, workspace isolation, and human approval.

## Core Capabilities

| Capability | What It Demonstrates |
|---|---|
| Agent orchestration | FastAPI orchestrator accepts run requests, tracks status, and streams audit events. |
| Ephemeral workspaces | Each run gets isolated workspace storage with cleanup and quota enforcement. |
| Capability manifests | Agent types get explicit tool allowlists, egress allowlists, token budgets, and time limits. |
| OPA policy checks | Every tool call is authorized by Open Policy Agent before execution. |
| Filesystem sandboxing | Paths are canonicalized, file types are validated, and writes are quota-limited. |
| Network containment | Network policy prevents unauthorized egress and blocks SSRF targets. |
| Secret leak prevention | Rego policy detects credential-shaped content before output is written or sent. |
| Human approval | High-risk actions can be routed through a Logic App callback approval flow. |
| Kill switches | Azure App Configuration feature flags can stop all runs or specific capabilities. |
| Audit trail | Structured audit events are emitted for runtime decisions, tool calls, and file activity. |
| SOC console | React frontend provides run launch, attack templates, traces, and event streaming. |

## Architecture At A Glance

1. A user starts an agent run from the frontend or API.
2. API Management validates gateway policy such as JWT, CORS, and rate limits.
3. The orchestrator validates the request, checks kill switches, creates a run record, and starts the agent workflow.
4. The agent runner uses an ephemeral workspace and dispatches each tool call through the security gates.
5. Capability manifest and OPA must both allow an action before the tool executes.
6. Sandbox validation checks paths, file types, quotas, and secret-shaped output.
7. Audit events are emitted to runtime logs, Log Analytics, and append-only storage.
8. The frontend streams status and audit events for operator visibility.

## Security Model

The accelerator uses defense in depth. The same high-level decision is intentionally enforced in more than one place.

- Gateway controls: API Management applies authentication, rate limiting, and public API policy.
- Runtime controls: the orchestrator checks feature flags and per-request limits.
- Capability controls: Python manifests define what each agent type can do.
- Policy controls: OPA independently authorizes actions from Rego policy and policy data.
- Sandbox controls: file paths, content types, quotas, and output content are checked close to execution.
- Identity controls: Azure resources use managed identity rather than application secrets where possible.
- Detection controls: audit events are shaped for Log Analytics and Sentinel analytics rules.

Fail-closed behavior is the most important design rule. If OPA or App Configuration cannot be reached, execution is blocked rather than allowed by default.

## Included Agent Types

| Agent Type | Intended Use | Default Constraints |
|---|---|---|
| `data-analyst` | Local file analysis and controlled OpenAI calls. | No network egress, 50k token cap, 3-minute limit. |
| `web-researcher` | Controlled public research against approved hosts. | `api.github.com` and `api.wikipedia.org`, 100k token cap, 5-minute limit. |

When adding a new agent type, update both the Python capability manifest and OPA policy data so both enforcement layers agree.

## Demo And Validation Scenarios

The frontend includes attack and workspace templates for repeatable security demonstrations:

- Allowed run: a normal data-analysis or research workflow completes and records audit evidence.
- Tool denial: an agent attempts a tool outside its capability manifest and OPA denies it.
- Path traversal: unsafe file paths are blocked by sandbox canonicalization.
- Secret detection: credential-shaped output is blocked before it leaves the sandbox.
- Kill switch: App Configuration disables global execution or a capability and the runtime blocks the next action.
- Human approval: a high-risk action pauses until an approval callback is received or the request times out.
- OPA failure: policy engine unavailability is treated as deny-all.

Use [../DEMO_PLAYBOOK.md](../DEMO_PLAYBOOK.md) for a live demo script and SOC storytelling flow.

## What Is Production-Ready Versus Reference Code

Production-oriented patterns included:

- Managed identity and least-privilege RBAC.
- Fail-closed dependency behavior.
- Structured audit events.
- Policy-as-code separation from application logic.
- Infrastructure-as-code modules for repeatable deployment.
- Offline unit tests for sandbox, policy client, and kill-switch behavior.

Areas to adapt before production use:

- Agent prompts, model choices, and tool implementations.
- Organization-specific network egress lists and approval rules.
- Sentinel analytics thresholds and incident routing.
- Data retention, WORM policies, and regulatory settings.
- Frontend authentication and tenant-specific app registration values.
- Load, resiliency, and chaos testing for your target scale.

## Repository Map

| Path | Purpose |
|---|---|
| [../app](../app) | FastAPI orchestrator, agent loop, sandbox, audit, policy, and kill-switch code. |
| [../frontend](../frontend) | React SOC console and security workflow UI. |
| [../infra](../infra) | Bicep modules for Azure deployment. |
| [../policies](../policies) | Rego policies and policy data used by OPA. |
| [../scripts](../scripts) | Bootstrap, auth setup, smoke test, and local validation scripts. |
| [../tests/unit](../tests/unit) | Offline Python unit tests. |
| [../docs](../docs) | Architecture notes, solution guidance, and release documentation. |

## Recommended Next Steps

1. Run the local validation script in [testing-guide.md](testing-guide.md).
2. Review [public-release-checklist.md](public-release-checklist.md) before publishing.
3. Deploy into a non-production Azure subscription.
4. Run the smoke test against the deployed APIM and frontend endpoints.
5. Walk through the demo playbook with security and platform stakeholders.
