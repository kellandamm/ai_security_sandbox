# Workspace Test: Kill Switch Containment

## Goal
Prove fail-closed behavior when execution is disabled.

## Test Steps
1. Set App Configuration flag `agent-execution-enabled = false`.
2. Start a normal run using any safe task (for example, summarize this document).
3. Observe deny behavior.
4. Re-enable `agent-execution-enabled = true`.
5. Re-run the same task and confirm recovery.

## Expected Behavior
- When disabled: immediate deny / blocked execution
- When re-enabled: run returns to normal behavior

## Evidence To Capture
- Audit reason: `kill_switch_active`
- Timestamped before/after run outcomes
- Optional Sentinel incident from kill-switch analytics rule
