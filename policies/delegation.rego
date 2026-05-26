package delegation

# Phase 2 — agent-to-agent delegation policy.
#
# Input shape:
# {
#   "parent_agent_type": "web-researcher",
#   "child_agent_type": "data-analyst",
#   "requested_tools": ["file_read", "openai_call"],
#   "call_depth": 2,
#   "call_chain": ["run-a", "run-b"]
# }
#
# Data shape (policies/data/delegation_rules.json):
# {
#   "max_call_depth": 3,
#   "allowed_child_agent_types": { "web-researcher": ["data-analyst"] },
#   "allowed_delegation_scopes": { "web-researcher": ["file_read", "openai_call"] }
# }

import future.keywords.in
import future.keywords.if

default allow := false
default deny_reasons := []

# Composite allow rule — every gate must pass.
allow if {
	child_type_allowed
	scope_is_subset
	depth_within_limit
	not chain_contains_cycle
}

# ── child agent type allowlist ──────────────────────────────────────────────
child_type_allowed if {
	allowed := data.data.delegation_rules.allowed_child_agent_types[input.parent_agent_type]
	input.child_agent_type in allowed
}

# ── requested scope must be a subset of parent's allowed scopes ─────────────
scope_is_subset if {
	allowed := {tool | tool := data.data.delegation_rules.allowed_delegation_scopes[input.parent_agent_type][_]}
	requested := {tool | tool := input.requested_tools[_]}
	count(requested - allowed) == 0
}

# ── depth cap ──────────────────────────────────────────────────────────────
depth_within_limit if {
	max := data.data.delegation_rules.max_call_depth
	input.call_depth <= max
}

# ── cycle detection — child cannot re-enter an ancestor in the chain ───────
chain_contains_cycle if {
	input.parent_agent_type == input.child_agent_type
	count(input.call_chain) > 1
}

# ── structured deny reasons for audit ──────────────────────────────────────
deny_reasons contains "child_type_not_allowed" if {
	not child_type_allowed
}

deny_reasons contains "scope_not_subset" if {
	not scope_is_subset
}

deny_reasons contains "call_depth_exceeded" if {
	not depth_within_limit
}

deny_reasons contains "cycle_detected" if {
	chain_contains_cycle
}
