# Data Retention Policy

## Purpose

Define retention, immutability, and deletion behavior for sandbox data and audit artifacts in production.

## Data Classes

- Workspace data: ephemeral run-scoped files in workspace storage
- Audit events: structured events in Log Analytics and immutable append blobs
- Application telemetry: App Insights and Sentinel-derived security signals

## Retention Schedule

1. Workspace storage (ephemeral): 24-hour lifecycle deletion
2. Log Analytics (`AiAgentAudit_CL`): 90 days
3. Audit append blobs (WORM): 365 days immutable retention
4. Storage version/change feed on audit account: 365 days

## Immutability and Tamper Resistance

1. Audit storage uses append-only logging and immutability policies.
2. Log Analytics workspace has CanNotDelete lock enabled.
3. Audit event failures do not block execution, but all failures are logged for operator review.

## Deletion and Disposal

1. Workspace artifacts are automatically deleted by lifecycle policy.
2. Audit data is retained to satisfy security and forensic requirements for the configured retention period.
3. After retention expiry, platform-managed purge applies according to configured policies.

## DSAR Workflow Support

1. The orchestrator provides an admin-only metadata export endpoint for subject requests:
	- `GET /compliance/dsar/subject/{subject}?tenant_id=<tenant>`
2. The endpoint returns run metadata keys (`run_id`, `correlation_id`) that operators can use to retrieve audit evidence.
3. Immutable audit artifacts remain subject to configured security retention obligations.

## Compliance Notes

- Purpose limitation: audit records are used for security monitoring, incident response, and compliance evidence.
- Data minimization: avoid unnecessary personal data in prompts and outputs.
- Right-to-erasure requests should be evaluated against legal/security retention obligations.

## Data Residency Controls

1. Deploy data-plane resources in approved geography and paired-region strategy defined by your compliance boundary.
2. Validate that Log Analytics, Storage, and App Insights regions align with organizational residency requirements.
3. Restrict cross-region export workflows unless explicitly approved by compliance/security owners.

## Key Management and Rotation

1. Prefer customer-managed key (CMK) patterns where required by policy.
2. Define key rotation cadence (for example, every 180 days) and owner responsibilities.
3. Validate key rotation procedures in non-production before production execution.
4. Record key rotation evidence with change ticket IDs and post-rotation verification artifacts.

## Operational Ownership

- Security operations owner: monitors Sentinel analytics and incident triage.
- Platform owner: maintains retention settings and immutability controls in IaC.
- Release gate: retention controls must be validated in deployment review before production rollout.

## Verification Checklist

1. Confirm storage lifecycle rules for workspace containers.
2. Confirm Log Analytics retention and daily cap.
3. Confirm immutability and soft-delete settings on audit storage.
4. Confirm policy and runbook links are present in release documentation.
