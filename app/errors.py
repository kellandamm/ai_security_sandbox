"""
Consolidated error types introduced by the Foundry Shield uplift.

Pre-existing errors continue to live in their original modules
(``policy.py``, ``kill_switch.py``, ``rate_limiter.py``, ``sandbox.py``)
to keep import surfaces stable. New errors used by phases 1–7 of the
seven-gap uplift are defined here so callers have a single import point.

All errors are designed to be raised in a **fail-closed** path: code paths
that catch them should default to DENY / ABORT, never ALLOW.
"""

from __future__ import annotations


class FoundryShieldError(Exception):
    """Base class for all Foundry Shield uplift errors."""


# ── Phase 1: Prompt injection defense ──────────────────────────────────────────


class PromptInjectionError(FoundryShieldError):
    """Raised when input or retrieved content is classified as a prompt-injection
    or jailbreak attempt and the enforcement mode is ``block``.

    Attributes:
        score: Confidence score in [0, 1] returned by the detector.
        categories: Detector category labels (e.g. ``["jailbreak"]``).
        source: Where the offending text came from
            (``"user_prompt"``, ``"uploaded_file"``, ``"http_get"``, ``"file_read"``).
    """

    def __init__(
        self,
        message: str,
        *,
        score: float,
        categories: list[str] | None = None,
        source: str = "user_prompt",
    ) -> None:
        super().__init__(message)
        self.score = score
        self.categories = categories or []
        self.source = source


# ── Phase 2: Agent-to-agent delegation ─────────────────────────────────────────


class DelegationDeniedError(FoundryShieldError):
    """Raised when a parent agent's request to spawn a child agent is denied
    (over-scoped, exceeds call depth, expired token, or signature mismatch).
    """


# ── Phase 4: Behavioural anomaly detection ─────────────────────────────────────


class AnomalyHaltError(FoundryShieldError):
    """Raised when the live anomaly scorer crosses the per-agent halt threshold."""

    def __init__(self, message: str, *, anomaly_score: float) -> None:
        super().__init__(message)
        self.anomaly_score = anomaly_score


# ── Phase 6: MCP layer ─────────────────────────────────────────────────────────


class MCPToolError(FoundryShieldError):
    """Raised when an MCP tool call cannot be routed, discovered, or executed
    under the current capability manifest / policy set.
    """


# ── Phase 7: Additional OWASP / agentic guardrails ─────────────────────────────


class ExcessiveAgencyError(FoundryShieldError):
    """Raised when a high-risk action is invoked without the required
    human confirmation (LLM08 — Excessive Agency).
    """


class LoopDetectedError(FoundryShieldError):
    """Raised when the agent repeats the same tool call signature beyond the
    configured window.
    """

    def __init__(self, message: str, *, tool_name: str, repetitions: int) -> None:
        super().__init__(message)
        self.tool_name = tool_name
        self.repetitions = repetitions


class CostBudgetExceededError(FoundryShieldError):
    """Raised when the estimated USD cost of a run exceeds the per-agent budget."""

    def __init__(
        self,
        message: str,
        *,
        estimated_cost_usd: float,
        budget_usd: float,
    ) -> None:
        super().__init__(message)
        self.estimated_cost_usd = estimated_cost_usd
        self.budget_usd = budget_usd


__all__ = [
    "FoundryShieldError",
    "PromptInjectionError",
    "DelegationDeniedError",
    "AnomalyHaltError",
    "MCPToolError",
    "ExcessiveAgencyError",
    "LoopDetectedError",
    "CostBudgetExceededError",
]
