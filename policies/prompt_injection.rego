package agent.prompt_injection

# ── Prompt-injection escalation policy (Phase 1) ──────────────────────────────
#
# Secondary enforcement layer that consumes injection_score values produced by
# the Prompt Shields layer in app/main.py and app/agent.py. The Python layer
# is the primary block; this rego policy ensures the **same** decision is
# auditable independently and enforced even if a future code path attempts to
# downgrade enforcement mode in-process (defense-in-depth).
#
# Inputs (provided by app/policy.py when evaluating a run-scoped check):
#   input.run_id            string
#   input.agent_type        string
#   input.injection_score   number in [0, 1]
#   input.source            string ("user_prompt" | "uploaded_file" |
#                                    "http_get"   | "file_read")
#   input.confirmed_by      string (optional human approver subject)
#
# Data:
#   data.injection.deny_score       — score at or above which we deny
#   data.injection.approval_score   — score at or above which a human
#                                      approver may unblock the run
#   data.injection.always_block_sources — sources where no approver override
#                                          is permitted (e.g. "user_prompt")

import future.keywords.if
import future.keywords.in

default decision := "allow"

# Hard deny if the source is on the always-block list and any attack was scored.
decision := "deny" if {
    input.source in data.injection.always_block_sources
    input.injection_score >= data.injection.deny_score
}

# Otherwise, deny by default once we cross the deny threshold ...
decision := "deny" if {
    input.injection_score >= data.injection.deny_score
    not input.source in data.injection.always_block_sources
    not _human_approved
}

# ... unless a sufficiently privileged approver has confirmed the run.
decision := "requires_approval" if {
    input.injection_score >= data.injection.approval_score
    input.injection_score < data.injection.deny_score
    not _human_approved
}

_human_approved if {
    input.confirmed_by != ""
    input.confirmed_by != null
}

# Reason strings surfaced back to the orchestrator for audit error_code.
reason := sprintf(
    "prompt_injection score=%.2f source=%s",
    [input.injection_score, input.source],
) if {
    decision != "allow"
}
