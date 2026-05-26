# Audit Pipeline Operational Guide

> Audit evidence in this sandbox MUST originate from the orchestrator process
> that actually enforces policy. Any "direct ingestion" tooling (such as
> `scripts/seed-demo-data.ps1 -Mode direct`) is **for demo/test environments
> only** and bypasses the security controls the platform is meant to demonstrate.

## Common failure modes

If `POST /sandbox/runs` returns HTTP 202 but no rows land in
`AiAgentAudit_CL`, work through the checks below.

### 1. OPA sidecar unreachable
The orchestrator image expects an OPA sidecar at `http://localhost:8181`.
Multi-container sidecars only work in the Container Apps deployment, not in
the App Service plan. With `OPA_URL` unset or unreachable, `policy.py`
fail-closes and every tool call is denied.

- **Fix (preferred):** Run the orchestrator on the Container Apps
  Environment provisioned by `infra/modules/compute.bicep`.
- **Fix (alternative):** Run OPA as a separate service in the same VNet and
  set `OPA_URL` on the orchestrator to that endpoint.

### 2. Audit RBAC missing on the orchestrator managed identity
Even when OPA is healthy, the WORM append-blob audit sink raises
`AuthorizationFailure` if the orchestrator UAMI lacks
`Storage Blob Data Contributor` on the audit storage account. The Bicep
RBAC module assigns this role to the Container App identity; an App Service
orchestrator uses a different identity and needs an explicit assignment.

### 3. Container Apps Environment is internal-only
`vnetConfiguration.internal=true` makes the public FQDN unresolvable from
the internet. APIM must reach the orchestrator over the VNet
(`serviceUrl` in `infra/modules/apim.bicep` should be the CAE internal
ingress, e.g. `https://ca-orchestrator-<token>.internal.<defaultDomain>`),
and the APIM subnet must have line of sight to the CAE infrastructure
subnet (NSG + UDR review).

## Validating end-to-end after a fix

Fire a real run through APIM (NOT the direct-ingestion mode):

```pwsh
./scripts/seed-demo-data.ps1 `
    -Mode runs `
    -ApimUrl "https://apim-<token>.azure-api.net" `
    -AadClientId "<client>"
```

Then within ~3 minutes:

```kusto
AiAgentAudit_CL
| where TimeGenerated > ago(10m)
| summarize Rows=count(), Latest=max(TimeGenerated),
            ByDecision=make_set(policy_decision)
```

The result must be non-zero AND include `allow` and `deny` decisions
actually produced by OPA.

## Recommended smoke-test extension

`scripts/smoke-test.ps1` checks `/health` today. Extend it to issue a real
run and assert that `AiAgentAudit_CL` receives at least one row within 90
seconds, then wire that into the `azd up` postdeploy hook so broken
deployments never reach a user.
