# Incident Response Runbook

This runbook covers SOC triage and containment for security events emitted by the AI Security Sandbox.

## Scope

- Identity signature validation failures
- Cross-tenant run access probing
- Rate-limit spikes and API flooding
- Privileged admin control actions
- Existing policy, exfiltration, and kill-switch alerts

## Alert Mapping

- Signature failures: `action_type == "signature_verification_failure"`
- Cross-tenant probing: `action_type == "cross_tenant_access_attempt"`
- Rate-limit spikes: `action_type == "rate_limit_exceeded"`
- Admin actions: `action_type in ("admin_kill_switch_toggle", "admin_run_delete")`
- Policy denials and exfiltration: existing Sentinel scheduled rules

## First 15 Minutes

1. Confirm alert validity in Log Analytics using `correlation_id` and `run_id`.
2. Pull related events from `AiAgentAudit_CL` for +/- 15 minutes.
3. Classify incident severity:
   - High: signature brute force, cross-tenant probing, confirmed exfiltration intent.
   - Medium: rate-limit spike, unusual admin actions.
4. If active abuse is ongoing, disable `agent-execution-enabled` via kill switch immediately.

## Playbook A: Signature Verification Failures

1. Query clustered failures by `error_code` and `correlation_id`.
2. Determine if failures are due to deployment mismatch:
   - Check APIM named value for signing secret.
   - Check orchestrator app setting `APIM_IDENTITY_SIGNING_SECRET`.
3. If mismatch is confirmed, perform coordinated APIM + backend redeploy.
4. If mismatch is not confirmed, treat as hostile probing:
   - Tighten APIM rate limits temporarily.
   - Block suspicious source identities/IPs in upstream controls.

## Playbook B: Cross-Tenant Access Probing

1. Confirm repeated `AUTHZ_DENY_CROSS_TENANT_ACCESS` events.
2. Correlate with subject/tenant identity in APIM and Entra logs.
3. If probing pattern persists:
   - Rotate affected credentials.
   - Increase alerting severity and suppression window reductions.
   - Temporarily throttle suspected caller identity.

## Playbook C: Rate-Limit Spikes

1. Aggregate by `error_code` (`RATE_LIMIT_EXCEEDED:<agent-id>`), path, and 5-minute bins.
2. Validate whether traffic is expected load testing.
3. If malicious or unknown:
   - Reduce APIM quota/rate thresholds for impacted keys.
   - Trigger temporary global or per-agent kill switch if service health degrades.

## Playbook D: Admin Action Review

1. Review `ADMIN_ACTION_KILL_SWITCH_TOGGLE:*` and `ADMIN_ACTION_RUN_KILL:*` events.
2. Validate operator identity and change ticket.
3. If unauthorized or unexplained:
   - Revoke affected admin role assignments.
   - Rotate signing/credential material as appropriate.
   - Open incident and preserve immutable audit evidence.

## Evidence Collection

1. Export relevant `AiAgentAudit_CL` rows keyed by `run_id` and `correlation_id`.
2. Preserve WORM append-blob records under `audit-logs/<run_id>/`.
3. Capture APIM diagnostics and Entra sign-in logs for the same window.

## Recovery and Post-Incident

1. Restore normal kill-switch states after containment.
2. Verify smoke tests for `/sandbox/runs` and admin APIs.
3. Record root cause, impacted controls, and follow-up actions.
4. Update detection queries/rules if any blind spots were identified.
