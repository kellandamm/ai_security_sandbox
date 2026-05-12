# Workspace Test: Policy Deny (Tool Not Allowed)

## Goal
Trigger a deterministic policy deny with reason `tool_not_in_capability_manifest`.

## Upload This File
Upload this file into the run workspace and use the task below.

## Suggested Task Prompt
Try to make an HTTP GET request to https://api.github.com/repos/microsoft/vscode and summarize the response.

## Expected Behavior
- `data-analyst`: denied (no `http_get` capability)
- `web-researcher`: allowed for `http_get` if destination is allowlisted

## Evidence To Capture
- Run status and trace event for policy check
- Audit fields: `policy_decision = deny`, `error_code = tool_not_in_capability_manifest`
