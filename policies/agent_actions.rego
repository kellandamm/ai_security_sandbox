package agent.actions

import future.keywords.in

# ── Primary authorization policy ──────────────────────────────────────────────
#
# Decision hierarchy:
#   allow            → caller may proceed immediately
#   requires_approval → caller must gate on human approval first
#   (neither)        → DENY — caller must not proceed
#
# All three rules are evaluated from agent.py via POST /v1/data/agent/actions

default allow = false
default requires_approval = false
default reason = "policy_default_deny"

# ── ALLOW: all conditions must pass ───────────────────────────────────────────

allow {
    not global_kill_switch_active
    not agent_type_kill_switch_active
    tool_is_allowed_for_agent_type
    not is_high_risk_action
    path_is_in_allowed_prefix
    egress_destination_is_allowed
}

# ── REQUIRES_APPROVAL ─────────────────────────────────────────────────────────

requires_approval {
    not global_kill_switch_active
    not agent_type_kill_switch_active
    tool_is_allowed_for_agent_type
    is_high_risk_action
    path_is_in_allowed_prefix
    egress_destination_is_allowed
}

# ── Kill switch checks ────────────────────────────────────────────────────────
# data.kill_switches is updated by the policy-loader init container reading
# App Configuration feature flags at job start.

global_kill_switch_active {
    data.data.kill_switches["agent-execution-enabled"] == false
}

agent_type_kill_switch_active {
    flag := sprintf("agent-%s-enabled", [input.agent_type])
    data.data.kill_switches[flag] == false
}

# ── Capability manifest check ─────────────────────────────────────────────────

tool_is_allowed_for_agent_type {
    input.action_type in data.data.allowed_tools[input.agent_type]
}

# ── High-risk action check ────────────────────────────────────────────────────

is_high_risk_action {
    input.action_type in data.data.high_risk_actions
}

# ── Path prefix enforcement ───────────────────────────────────────────────────
# File operations must target the agent's own run directory only.

path_is_in_allowed_prefix {
    input.action_type in {"file_read", "file_write", "file_delete"}
    run_write_prefix := sprintf("/workspace/%s/write/", [input.run_id])
    startswith(input.path, run_write_prefix)
}

# Non-file actions pass path check
path_is_in_allowed_prefix {
    not input.action_type in {"file_read", "file_write", "file_delete"}
}

# Empty path also passes for non-file actions
path_is_in_allowed_prefix {
    input.path == ""
    not input.action_type in {"file_read", "file_write", "file_delete"}
}

# ── Egress FQDN enforcement ───────────────────────────────────────────────────
# HTTP calls must target an allowed FQDN from the agent's capability manifest.

egress_destination_is_allowed {
    input.action_type in {"http_get", "network_call"}
    some fqdn in data.data.allowed_egress_fqdns[input.agent_type]
    endswith(input.destination, fqdn)
}

# Non-network actions pass egress check
egress_destination_is_allowed {
    not input.action_type in {"http_get", "network_call"}
}

# Azure OpenAI calls go through private endpoint — always allowed if not killed
egress_destination_is_allowed {
    input.action_type == "openai_call"
}

<<<<<<< HEAD
# ── MCP tool calls (Phase 6) ──────────────────────────────────────────────────
# When the orchestrator invokes a tool exposed by an EXTERNAL MCP server,
# the action_type is the literal string "mcp_tool_call" and the calling
# agent must have the target server in its `mcp_allowed_servers` allowlist.
# The server identity is passed via `input.tool_namespace` (the server
# `name` field, NOT the full URI — keeps the policy data file small).
tool_is_allowed_for_agent_type {
    input.action_type == "mcp_tool_call"
    some server in data.data.mcp_allowed_servers[input.agent_type]
    server == input.tool_namespace
}

# Egress is implicit for mcp_tool_call (the destination FQDN is enforced
# in-process by the MCP client against the same allowlist).
egress_destination_is_allowed {
    input.action_type == "mcp_tool_call"
}

path_is_in_allowed_prefix {
    input.action_type == "mcp_tool_call"
}

=======
>>>>>>> origin/main
# ── Reason string ─────────────────────────────────────────────────────────────

reason = "kill_switch_active" {
    global_kill_switch_active
}

reason = "agent_type_kill_switch_active" {
    agent_type_kill_switch_active
}

reason = "tool_not_in_capability_manifest" {
    not tool_is_allowed_for_agent_type
}

reason = "path_escapes_run_sandbox" {
    input.action_type in {"file_read", "file_write", "file_delete"}
    not path_is_in_allowed_prefix
}

reason = "egress_fqdn_not_allowed" {
    input.action_type in {"http_get", "network_call"}
    not egress_destination_is_allowed
}

reason = "requires_human_approval" {
    requires_approval
}

# ── required_approvals metadata ──────────────────────────────────────────────

required_approvals = ["security-team@example.com"] {
    requires_approval
}

required_approvals = [] {
    not requires_approval
}
