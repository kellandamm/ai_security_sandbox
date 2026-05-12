# Secure AI Operations Demo Playbook

## Purpose
This playbook gives you a clear, repeatable way to demonstrate:
- Risky AI workflow behavior.
- How Azure services enforce controls.
- How Security.microsoft.com supports SOC triage and response.

Use this for live demos with leadership, security teams, and architecture stakeholders.

---

## 1. Demo Storyline (Problem -> Detection -> Containment -> Evidence)

### A. Trigger a controlled bad event
Examples:
- Intentionally trigger a policy deny.
- Run a workflow that previously failed due to model or policy settings.
- Simulate repeated denied tool attempts.

### B. Show enforcement in app/runtime
- Execution trace in the app (run start, policy check, openai call, run status).
- OPA decision behavior (allow/deny).
- APIM route and policy protection.

### C. Show raw evidence in Azure
- Log Analytics query proving event details and timing.
- Correlated operational logs in Web App or Application Insights.

### D. Show SOC workflow in Security.microsoft.com
- Incident created from Sentinel analytics rule.
- Alert details and timeline.
- Owner assignment, triage notes, status transitions.

### E. Show containment and recovery
- Toggle kill switch in App Configuration.
- Re-run flow and prove containment.
- Re-enable and prove controlled recovery.

---

## 2. Azure Services to Show (And Why)

### 1) Azure API Management (APIM)
Show:
- JWT and subscription key protection.
- Inbound policy and rate limiting.
- API operation traces.

Why it matters:
- Gateway-level control and consistent policy enforcement.

### 2) Orchestrator Web App
Show:
- Runtime config (AZURE_OPENAI_ENDPOINT, OPENAI_MODEL, OPA_URL).
- Managed identity configuration.
- Health checks and logs.

Why it matters:
- Controlled execution plane for agent runs.

### 3) OPA Web App
Show:
- Policy runtime health and logs.
- Policy evaluation responses.

Why it matters:
- Policy-as-code with fail-closed behavior.

### 4) Azure AI Foundry resource (Cognitive Services)
Show:
- Model deployment (for example gpt-5.4).
- Endpoint configuration.
- Role assignments (Cognitive Services OpenAI User).

Why it matters:
- Governed model access and least privilege.

### 5) Azure App Configuration
Show:
- Feature flags/kill switches.
- Controlled enable/disable of capabilities.

Why it matters:
- Fast containment for active incidents.

### 6) Azure Key Vault
Show:
- Secret references and access model.

Why it matters:
- Secret hygiene and controlled runtime access.

### 7) Azure Container Registry (ACR)
Show:
- Image tags and recent pushes.

Why it matters:
- Release traceability and software supply chain confidence.

### 8) Azure Monitor + Log Analytics
Show:
- Query-level evidence for policy decisions and run outcomes.

Why it matters:
- Forensic proof and detection source for SOC tooling.

---

## 3. Security.microsoft.com: What To Demonstrate

Security.microsoft.com is best for incident-centric SOC storytelling.

Show these pages:
- Incidents queue.
- Alerts queue.
- Incident timeline/attack story.
- Assignment, comments, and closure workflow.

Important caveat:
- Use Azure Log Analytics/Sentinel Logs for deep raw KQL analysis.
- Use Security.microsoft.com for triage, analyst actions, and incident lifecycle.

---

## 4. Sentinel Analytics Rules (Recommended)

Create these in Microsoft Sentinel using the workspace that stores your agent audit data.

## Rule 1: Repeated Policy Denies
Purpose:
- Detect repeated denied actions (possible prompt injection, abuse, or broken permission model).

Suggested settings:
- Run frequency: 5 minutes
- Lookback: 15 minutes
- Threshold: denyCount >= 5
- Severity: Medium or High

KQL:
```kusto
AiAgentAudit_CL
| extend actionType = tostring(column_ifexists("action_type", column_ifexists("action_type_s",""))),
         policyDecision = tostring(column_ifexists("policy_decision", column_ifexists("policy_decision_s",""))),
         reason = tostring(column_ifexists("error_code", column_ifexists("error_code_s",""))),
         runId = tostring(column_ifexists("run_id", column_ifexists("run_id_s","")))
| where tolower(policyDecision) == "deny"
| summarize denyCount=count(), reasons=make_set(reason, 10), runs=make_set(runId, 20) by bin(TimeGenerated, 5m)
| where denyCount >= 5
```

## Rule 2: OPA Unreachable / Policy Engine Availability
Purpose:
- Detect fail-closed policy disruptions when OPA is unreachable or policy checks fail repeatedly.

Suggested settings:
- Run frequency: 5 minutes
- Lookback: 15 minutes
- Threshold: events >= 2
- Severity: High

KQL:
```kusto
AiAgentAudit_CL
| extend actionType = tostring(column_ifexists("action_type", column_ifexists("action_type_s",""))),
         outcome = tostring(column_ifexists("outcome", column_ifexists("outcome_s",""))),
         errorCode = tostring(column_ifexists("error_code", column_ifexists("error_code_s","")))
| where tolower(actionType) == "policy_check"
| where tolower(outcome) in ("failure","blocked") or errorCode has_cs "unreachable" or errorCode has_cs "opa"
| summarize events=count(), samples=make_set(errorCode, 10) by bin(TimeGenerated, 5m)
| where events >= 2
```

## Rule 3: Run Failure Spike
Purpose:
- Detect broad workflow degradation or active campaign behavior.

Suggested settings:
- Run frequency: 5 minutes
- Lookback: 15 minutes
- Threshold: failedRuns >= 5
- Severity: High

KQL:
```kusto
AiAgentAudit_CL
| extend outcome = tostring(column_ifexists("outcome", column_ifexists("outcome_s",""))),
         runId = tostring(column_ifexists("run_id", column_ifexists("run_id_s",""))),
         actionType = tostring(column_ifexists("action_type", column_ifexists("action_type_s","")))
| where tolower(outcome) == "failure" or tolower(actionType) == "run_complete"
| summarize failedRuns=dcountif(runId, tolower(outcome) == "failure") by bin(TimeGenerated, 5m)
| where failedRuns >= 5
```

---

## 5. Suggested 8-10 Minute Demo Script

### Minute 0-2: Context
- "We are running a real workflow under strict controls: gateway policy, runtime policy, and audit logging."

### Minute 2-4: Trigger + Runtime Control
- Launch controlled bad or risky run.
- Show trace event sequence and deny/allow outcomes.

### Minute 4-6: Evidence
- Pivot to Log Analytics.
- Run KQL query and show exact event fields and timestamps.

### Minute 6-8: SOC Operations
- Open Security.microsoft.com incident generated by Sentinel.
- Show alert, incident timeline, assign owner, add note.

### Minute 8-10: Containment and Recovery
- Toggle kill switch in App Configuration.
- Re-run and show containment behavior.
- Re-enable and show safe recovery.

---

## 6. Business Outcome Messages (Close Strong)

Use these exact outcomes in executive wrap-up:
- "Risky behavior is detected quickly and consistently."
- "Policy enforcement is fail-closed and auditable."
- "SOC can triage and contain without engineering intervention."
- "We preserve delivery speed while improving control and evidence quality."

---

## 7. Optional Prep Checklist Before Live Demo

- Confirm APIM health endpoint returns 200.
- Confirm orchestrator and OPA health endpoints return expected status.
- Confirm kill switches are visible and togglable.
- Confirm Sentinel rules are enabled and incident creation is on.
- Confirm Security.microsoft.com permissions for incident triage account.
- Keep one known good run and one known failing run ID handy for comparison.

---

## 8. Notes

- If your custom table schema differs from the sample KQL field names, adapt the column_ifexists mappings.
- Keep one fallback demo path that uses previously generated incidents in case live generation is delayed.

---

## 9. Workspace Test Documents (Upload Pack)

Use the test-doc pack for repeatable, control-specific demo runs:

- [frontend/public/templates/workspace-tests/README.md](frontend/public/templates/workspace-tests/README.md)
- [frontend/public/templates/workspace-tests/deny-tool-not-allowed.md](frontend/public/templates/workspace-tests/deny-tool-not-allowed.md)
- [frontend/public/templates/workspace-tests/kill-switch-validation.md](frontend/public/templates/workspace-tests/kill-switch-validation.md)
- [frontend/public/templates/workspace-tests/opa-unreachable-simulation.md](frontend/public/templates/workspace-tests/opa-unreachable-simulation.md)
- [frontend/public/templates/workspace-tests/approval-high-risk-http-post.md](frontend/public/templates/workspace-tests/approval-high-risk-http-post.md)

Recommended order:
1. deny-tool-not-allowed
2. kill-switch-validation
3. opa-unreachable-simulation
4. approval-high-risk-http-post

Important note for approval demo:
- Current policy data does not allow mutating HTTP tools for any agent type, so the approval flow needs temporary demo configuration as documented in [frontend/public/templates/workspace-tests/approval-high-risk-http-post.md](frontend/public/templates/workspace-tests/approval-high-risk-http-post.md).
