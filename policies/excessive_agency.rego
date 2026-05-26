package excessive_agency

# Phase 7 — LLM08: Excessive Agency
#
# This policy provides defense-in-depth on top of capability_manifest's
# high_risk_actions list. The orchestrator already routes
# high_risk_actions through human approval; this rule layers a
# **risk-score-based escalation** so that any action whose computed
# risk_score >= 0.7 also requires confirmation, regardless of static
# action category.
#
# Input shape:
# {
#   "agent_type": "web-researcher",
#   "tool_name": "http_post",
#   "risk_score": 0.85,
#   "tool_namespace": "local://web-researcher/http_post",
#   "confirmation_token": "<opaque>"
# }
#
# Data: policies/data/high_risk_actions.json — already lists hard-deny tools.

import future.keywords.in
import future.keywords.if

default decision := "allow"

# A confirmation_token presented means the human approval round-tripped;
# the orchestrator should validate the token signature elsewhere.
decision := "allow" if {
	input.confirmation_token
}

decision := "requires_approval" if {
	not input.confirmation_token
	risk_above_threshold
}

decision := "requires_approval" if {
	not input.confirmation_token
	tool_is_high_risk
}

risk_above_threshold if {
	to_number(input.risk_score) >= 0.7
}

tool_is_high_risk if {
	some action in data.data.high_risk_actions.high_risk_actions
	action == input.tool_name
}
