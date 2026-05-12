# Workspace Test: Human Approval (High-Risk Action)

## Goal
Exercise the `requires_approval` branch for a mutating network action.

## Important Current-State Note
With the current `allowed_tools.json`, no agent type has `http_post` capability, so this flow will deny before approval.

## Temporary Demo Setup (Before Test)
1. Add `http_post` to `web-researcher` in policy data.
2. Reload policy bundle / restart OPA runtime.
3. Keep `http_post` in `high_risk_actions.json`.

## Suggested Task Prompt
Attempt an HTTP POST to a demo endpoint and include payload `{\"demo\": true}`.

## Expected Behavior
- Policy decision: `requires_approval`
- Run pauses/waits for approval callback
- On approval: action proceeds
- On timeout/reject: action blocked

## Evidence To Capture
- Audit reason: `requires_human_approval`
- Approval request + callback in logs
- Final run status for approve vs reject paths
