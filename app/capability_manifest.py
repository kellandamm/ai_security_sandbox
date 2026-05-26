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
    # ── Foundry Shield uplift (phases 2, 6, 7) ────────────────────────────────
    # Phase 3 — reference to the model card JSON in app/governance/model_cards/
    model_card_version: str = "1.0.0"
    # Phase 6 — external MCP server URIs this agent may consume tools from
    mcp_endpoints: list[str] = field(default_factory=list)
    # Phase 7 — estimated-cost ceiling (USD) per run
    cost_budget_usd: float = 1.0
    # Phase 7 — sliding-window cap on repeated identical tool calls
    max_loop_depth: int = 5
    # Phase 2 — may this agent spawn child agents?
    delegation_allowed: bool = False
    # Phase 2 — subset of allowed_tools the agent may delegate to a child
    delegation_scopes: list[str] = field(default_factory=list)
    # Phase 2 — child agent types this agent may spawn (empty = none)
    allowed_child_agent_types: list[str] = field(default_factory=list)


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
        model_card_version="1.0.0",
        mcp_endpoints=[],
        cost_budget_usd=0.50,
        max_loop_depth=5,
        delegation_allowed=False,
        delegation_scopes=[],
        allowed_child_agent_types=[],
    ),
    "web-researcher": AgentCapabilities(
        description="Fetches content from approved external APIs, summarises findings.",
        allowed_tools=["file_read", "file_write", "openai_call", "http_get"],
        allowed_egress_fqdns=["api.github.com", "api.wikipedia.org"],
        max_tokens_per_run=100_000,
        max_run_duration_seconds=300,
        high_risk_actions=["http_post"],  # HTTP POST requires human approval
        model_card_version="1.0.0",
        mcp_endpoints=[],
        cost_budget_usd=1.50,
        max_loop_depth=5,
        delegation_allowed=True,
        delegation_scopes=["file_read", "openai_call"],
        allowed_child_agent_types=["data-analyst"],
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
