"""
Per-agent-type capability manifests.

Each agent type has a fixed set of allowed tools, allowed virtual path prefixes,
permitted egress FQDNs, token budget, and max run duration.

These values are the source of truth. They are also exported to
policies/data/allowed_tools.json so OPA can enforce the same constraints
independently (defense-in-depth: two separate enforcement points).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentCapabilities:
    """Immutable capability set for one agent type."""

    allowed_tools: list[str]
    allowed_egress_fqdns: list[str]
    max_tokens_per_run: int
    max_run_duration_seconds: int
    description: str = ""
    # High-risk actions for this type that require human approval
    high_risk_actions: list[str] = field(default_factory=list)


# ── Capability registry ────────────────────────────────────────────────────────

AGENT_CAPABILITIES: dict[str, AgentCapabilities] = {
    "data-analyst": AgentCapabilities(
        description=(
            "Reads structured data files, performs analysis, writes result reports."
        ),
        allowed_tools=["file_read", "file_write", "openai_call"],
        allowed_egress_fqdns=[],  # zero network egress needed
        max_tokens_per_run=50_000,
        max_run_duration_seconds=180,
        high_risk_actions=[],
    ),
    "web-researcher": AgentCapabilities(
        description="Fetches content from approved external APIs, summarises findings.",
        allowed_tools=["file_read", "file_write", "openai_call", "http_get"],
        allowed_egress_fqdns=["api.github.com", "api.wikipedia.org"],
        max_tokens_per_run=100_000,
        max_run_duration_seconds=300,
        high_risk_actions=["http_post"],  # HTTP POST requires human approval
    ),
}


def get_capabilities(agent_type: str) -> AgentCapabilities:
    caps = AGENT_CAPABILITIES.get(agent_type)
    if caps is None:
        raise ValueError(
            f"Unknown agent type: {agent_type!r}. "
            f"Valid types: {list(AGENT_CAPABILITIES)}"
        )
    return caps


def is_tool_allowed(agent_type: str, tool_name: str) -> bool:
    try:
        caps = get_capabilities(agent_type)
        return tool_name in caps.allowed_tools
    except ValueError:
        return False


def is_egress_allowed(agent_type: str, fqdn: str) -> bool:
    try:
        caps = get_capabilities(agent_type)
        return any(
            fqdn == allowed or fqdn.endswith("." + allowed)
            for allowed in caps.allowed_egress_fqdns
        )
    except ValueError:
        return False
