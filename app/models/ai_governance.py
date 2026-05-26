"""
ISO 42001 / NIST AI RMF governance metadata models.

These models back the per-agent **model card** files in
``app/governance/model_cards/`` and the structured governance metadata that
Phase 3 attaches to every emitted :class:`AuditEvent` via
``governance_metadata_ref``.

The intent is to give regulated-industry buyers (financial services, healthcare)
a single audit artifact that maps each policy enforcement point in the sandbox
to the ISO 42001 control and NIST AI RMF function it satisfies.
"""

from __future__ import annotations

from datetime import date
from enum import Enum

from pydantic import BaseModel, Field


class RiskTier(str, Enum):
    """Residual-risk classification after sandbox controls are applied.

    Aligned to ISO 42001 risk-treatment categories. A run inherits the agent
    type's tier unless overridden at runtime by an elevated data classification.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class NISTAIRMFFunction(str, Enum):
    """Top-level functions of the NIST AI Risk Management Framework."""

    GOVERN = "govern"
    MAP = "map"
    MEASURE = "measure"
    MANAGE = "manage"


class ModelCard(BaseModel):
    """Per-agent-type model card — public-facing AI governance artifact.

    Loaded from ``app/governance/model_cards/{agent_type}.json`` at startup.
    Surfaced via ``GET /compliance/model-cards/{agent_type}``.
    """

    agent_type: str
    model_card_version: str
    review_date: date

    # Model identity
    model_name: str
    model_version: str
    model_provider: str
    training_data_cutoff: date | None = None

    # Intended use & limits
    intended_use: str
    out_of_scope_uses: list[str] = Field(default_factory=list)
    known_limitations: list[str] = Field(default_factory=list)

    # Risk posture
    residual_risk_class: RiskTier
    human_oversight_required: bool = False

    # Data lineage
    data_sources: list[str] = Field(default_factory=list)

    # Compliance mappings
    iso_42001_controls: list[str] = Field(
        default_factory=list,
        description=(
            "Control IDs (e.g. '8.2', '8.3.1') this agent's enforcement "
            "set satisfies."
        ),
    )
    nist_ai_rmf_map: dict[NISTAIRMFFunction, str] = Field(
        default_factory=dict,
        description=(
            "Maps NIST AI RMF function \u2192 version of the practice "
            "satisfying it."
        ),
    )

    # Evaluation summary
    evaluation_summary: str = ""


class AIGovernanceMetadata(BaseModel):
    """Lightweight pointer attached to every audit event.

    Full model cards are heavyweight and tenanted; events carry only the
    composite reference that lets an auditor reconstruct the full card and
    control mapping in effect at the time of the action.
    """

    agent_type: str
    model_card_version: str
    residual_risk_class: RiskTier
    iso_42001_controls: list[str] = Field(default_factory=list)
    policy_bundle_hash: str | None = Field(
        default=None,
        description="SHA-256 of the rego policy bundle in force at event time.",
    )

    def reference(self) -> str:
        """Compact reference string for ``AuditEvent.governance_metadata_ref``."""
        return (
            f"{self.agent_type}@{self.model_card_version}"
            f"/{self.residual_risk_class.value}"
        )


__all__ = [
    "RiskTier",
    "NISTAIRMFFunction",
    "ModelCard",
    "AIGovernanceMetadata",
]
