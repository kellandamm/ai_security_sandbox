# Portal Demo Talk Track and Motion

This guide provides an end-to-end executive and technical demo flow using Azure portals and the sandbox UI.

## Audience and Duration

- Audience: Security leaders, SOC analysts, platform engineers, app owners
- Duration: 35-45 minutes
- Format: 10-minute architecture context + 20-minute live controls + 10-minute incident/compliance evidence

## Demo Storyline

1. Start with "why": unsafe agents create blind spots and uncontrolled data movement.
2. Show "control plane": APIM, orchestrator, OPA, kill switches, and immutable audit.
3. Show "detection and response": Sentinel alerts, Log Analytics timeline, and runbook actions.
4. Show "governance": retention policy, DSAR export path, and compliance query pack.

## Pre-Demo Checklist

1. Deploy latest backend and infra changes.
2. Ensure at least one admin Entra test account and one non-admin account.
3. Prepare APIM URL and frontend URL.
4. Verify Log Analytics has recent `AiAgentAudit_CL` events.
5. Keep these docs open:
   - [incident-response-runbook.md](incident-response-runbook.md)
   - [data-retention-policy.md](data-retention-policy.md)

## Demo Motion (Portal + UI)

### Segment 1: Architecture and Trust Boundary (5 min)

1. Azure Portal: API Management -> APIs -> inbound policy.
2. Narrate that APIM validates JWT and reissues signed `X-Auth-*` headers.
3. Show that direct orchestrator calls are blocked without trusted headers.
4. Emphasize defense-in-depth: APIM + app authz + OPA + sandbox.

### Segment 2: Controlled Execution (8 min)

1. Open sandbox frontend and submit a normal run.
2. Show run status progression and SSE audit feed.
3. Open Container Apps logs (or app logs) and point out structured audit events.
4. Explain that all runs are tied to `run_id` + `correlation_id`.

### Segment 3: Security Block and Detection (10 min)

1. Run an attack template (prompt injection/path traversal).
2. Show blocked outcome in UI.
3. Azure Portal: Microsoft Sentinel -> Incidents / Analytics.
4. Highlight triggered detections:
   - signature failures
   - cross-tenant probing
   - rate-limit spikes
   - admin control actions
5. Azure Portal: Log Analytics -> run KQL from workbook query pack.

### Segment 4: Kill Switch and Incident Response (7 min)

1. Azure Portal: App Configuration -> feature flags.
2. Disable `agent-execution-enabled`.
3. Re-run request and show fail-closed block.
4. Re-enable flag and show recovery.
5. Walk runbook steps from [incident-response-runbook.md](incident-response-runbook.md).

### Segment 5: Governance and Compliance (8 min)

1. Show [data-retention-policy.md](data-retention-policy.md).
2. Explain retention windows and immutable storage controls.
3. Invoke DSAR metadata export endpoint:
   - `GET /compliance/dsar/subject/{subject}?tenant_id=<tenant>` (admin only)
4. Show compliance query pack endpoint:
   - `GET /compliance/reporting/queries` (admin only)
5. In Log Analytics, run:
   - `compliance_processing_basis`
   - `compliance_classification_posture`
   - `compliance_dsar_exports`

## Suggested Script Prompts

- "We assume breach and default-deny every uncertain decision path."
- "The same action must pass both capability manifests and OPA policy."
- "Every meaningful action is auditable and correlated for SOC timelines."
- "Governance is built in: retention, DSAR workflow support, and compliance query surfaces."

## Q&A Anchor Points

- "How do you prove tenant isolation?"
  - Show cross-tenant denied events + Sentinel rule + 404 anti-enumeration behavior.
- "How do you stop unsafe operation quickly?"
  - Show kill switch in App Configuration + immediate blocked runs.
- "How do you support compliance evidence requests?"
  - Show DSAR export metadata + immutable audit and Log Analytics queries.

## Post-Demo Artifacts

1. Export relevant Sentinel incident IDs and KQL results.
2. Capture run IDs and correlation IDs from demo runs.
3. Share links to runbook, retention policy, and release checklist.
4. Record follow-up action items for policy threshold tuning.
