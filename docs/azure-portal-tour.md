# Azure Portal Tour — AI Security Sandbox

What you can see, query, and react to in the Azure Portal once the sandbox is
deployed. Examples below use the placeholder resource group `<rg>`, resource
token `<token>`, and subscription `<sub>` — substitute your own values from
`azd env get-values` (use the `AZURE_RESOURCE_GROUP`, `RESOURCE_TOKEN`, and
`AZURE_SUBSCRIPTION_ID` keys).

---

## 1. Resource Group dashboard

**[Open <rg>](https://portal.azure.com/#@/resource/subscriptions/<sub>/resourceGroups/<rg>/overview)**

~30 resources grouped by service: APIM, Container App, two App Services, ACR,
App Configuration (kill switches), Key Vault, two Storage accounts, Log
Analytics, App Insights, OpenAI, Logic App, Cosmos, VNet + private endpoints
and DNS zones.

---

## 2. Microsoft Sentinel — the SOC pane

The Log Analytics workspace `log-<token>` is Sentinel-onboarded.
Go to **Sentinel → Analytics rules** to see the 9 deployed scheduled rules
(defined in [infra/modules/monitoring.bicep](../infra/modules/monitoring.bicep)):

| Rule | Severity | Fires when |
|---|---|---|
| Prompt or Upload Blocked by Policy | High | `policy_decision==deny` from prompt-shield or OPA |
| Sandbox Path Traversal Attempt | High | `path_traversal_or_sensitive_path` or write outside `/workspace/<run-id>/write/` |
| Token Abuse or Runaway Request | Medium | `token_bomb_instruction` OR >10k tokens in 1 min |
| **Kill Switch Blocked Execution** | High | `action_type=="kill_switch_check"` AND `outcome=="blocked"` |
| Unsafe Egress / Exfiltration Attempt | High | IMDS / localhost / disallowed FQDN |
| Repeated Identity Signature Failures | High | ≥3 sig failures in 5 min |
| Cross-Tenant Run Probing | High | ≥3 cross-tenant access attempts in 5 min |
| Rate-Limit Spike | Medium | ≥5 rate-limit blocks in 5 min |
| Privileged Admin Action Performed | Medium | kill-switch toggle, run delete, DSAR export |

When a rule fires you get an **Incident** in *Sentinel → Incidents* with the
offending `run_id`, `correlation_id`, `agent_type`, and the audit row(s) that
triggered it.

---

## 3. Live audit query

**Log Analytics → Logs**, paste:

```kusto
AiAgentAudit_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, run_id, agent_type, action_type, policy_decision, outcome, error_code, risk_score, destination, path
| order by TimeGenerated desc
```

Useful follow-ups:

```kusto
// Kill switch hits
AiAgentAudit_CL | where action_type == "kill_switch_check" and outcome == "blocked"

// Anything denied in the last 24h
AiAgentAudit_CL | where policy_decision == "deny"
| summarize count() by error_code, agent_type

// Token spend per run
AiAgentAudit_CL | where action_type == "openai_call"
| summarize tokens=sum(token_count) by run_id | order by tokens desc
```

---

## 4. Kill switch — flip it live

**[App Configuration `appcs-<token>` → Feature manager](https://portal.azure.com/#@/resource/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.AppConfiguration/configurationStores/appcs-<token>/featureManager)**

Six flags under label `production`:

- `agent-execution-enabled` — global stop
- `file-write-enabled`, `network-egress-enabled`, `openai-calls-enabled` — capability scope
- `agent-data-analyst-enabled`, `agent-web-researcher-enabled` — per agent type

Toggle one OFF → next agent run emits a `kill_switch_check` audit row with
`outcome=blocked` → the **Kill Switch Blocked Execution** Sentinel rule fires
within 5 min → Incident appears.

---

## 5. SOC Workbook (richer dashboards)

Not deployed by `azd up`. Run once:

```pwsh
./scripts/deploy-sentinel-workbook.ps1 -ResourceGroup <rg>
```

Then find it under **Sentinel → Workbooks → My workbooks →
"AI Security Sandbox - SOC Workbook"**.

The workbook definition is checked in at [infra/workbooks/soc-workbook.json](../infra/workbooks/soc-workbook.json) so both the PowerShell and shell deploy scripts render the same panels. The current layout includes:

- **Filters** — Time Range, Agent Type (multi-select), Action Type (multi-select), Run ID substring; every panel honors them.
- **Headline KPIs** — events, distinct runs, denies, blocked tool calls, prompt-shield blocks, anomaly hits, cost-threshold breaches, approval requests.
- **Activity Over Time** — timecharts for policy decisions and top action types.
- **Policy & Capability Enforcement** — posture by action type (with block-rate heatmap), top blocked destinations/paths, approval flow, and `excessive_agency_block` rows (LLM08).
- **Content Safety & DLP** — DLP interceptions and Content Safety blocks.
- **Prompt Shield (LLM01)** — `prompt_shield_scan` and `retrieved_content_scan` with `injection_score` heatmap.
- **Agent Trust & Delegation** — spawn / delegation events, `signature_verification_failure` and `cross_tenant_access_attempt` rollups.
- **MCP Tooling** — calls and discovery grouped by `tool_namespace`.
- **Anomalies, Cost & Loops** — `anomaly_ml_score` heatmap, cost per run, `loop_detected` rows, token consumption per run, and a run-level anomaly-candidate query.
- **Operational Health** — run lifecycle (start / complete / abort), kill-switch toggles, rate-limit hits, DSAR / admin actions.

To update the dashboard, edit `infra/workbooks/soc-workbook.json` and re-run the script; it upserts in place using the `hidden-title` tag, so the workbook ID does not change.

---

## 6. Approvals (high-risk action flow)

**[Logic App `logic-approval-<token>`](https://portal.azure.com/#@/resource/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/logic-approval-<token>/logicApp)** → *Run history* shows every approval-required tool
call (e.g. demo prompt #11 DELETE github).

---

## 7. APIM gateway

**[apim-<token>](https://portal.azure.com/#@/resource/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ApiManagement/service/apim-<token>/overview)** — *Analytics* tab shows request volume,
throttling, 4xx/5xx breakdown. JWT validation + rate limit policies live here.

---

## 8. Container App / App Service logs

- `ca-orchestrator-<token>` → **Log stream** for live stdout (every audit event prints here too)
- `app-<token>-orchestrator` → **Log stream** for the APIM-fronted instance
- `appi-<token>` → **Failures / Performance** for exceptions and latency

---

## Quick demo loop to see it end-to-end

1. Open **Sentinel → Incidents** in one tab and **Log Analytics → Logs** in another.
2. In the SPA, run prompt #3 (IMDS) and prompt #5 (path traversal) from [docs/demo-prompts.md](demo-prompts.md).
3. Within ~10 sec: rows appear in `AiAgentAudit_CL` with `policy_decision=deny`.
4. Within 5 min: Sentinel rules `Unsafe Egress` and `Sandbox Path Traversal` create Incidents.
5. Flip `agent-execution-enabled` OFF in App Config, try any prompt → `Kill Switch Blocked Execution` Incident fires. Flip back ON.
