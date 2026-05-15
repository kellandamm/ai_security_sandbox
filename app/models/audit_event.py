"""Typed schema for all audit events emitted by the sandbox."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK_CALL = "network_call"
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    OPENAI_CALL = "openai_call"
    POLICY_CHECK = "policy_check"
    DLP_SCAN = "dlp_scan"
    DATA_CLASSIFICATION = "data_classification"
    CONTENT_SAFETY_CHECK = "content_safety_check"
    GROUNDING_CHECK = "grounding_check"
    DELEGATION_CHECK = "delegation_check"
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_RESPONSE = "approval_response"
    KILL_SWITCH_CHECK = "kill_switch_check"
    RUN_START = "run_start"
    RUN_COMPLETE = "run_complete"
    RUN_ABORT = "run_abort"
    SIGNATURE_VERIFICATION_FAILURE = "signature_verification_failure"
    CROSS_TENANT_ACCESS_ATTEMPT = "cross_tenant_access_attempt"
    ADMIN_KILL_SWITCH_TOGGLE = "admin_kill_switch_toggle"
    ADMIN_RUN_DELETE = "admin_run_delete"
    ADMIN_DSAR_EXPORT = "admin_dsar_export"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"
    PENDING = "pending"


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"


class AuditEvent(BaseModel):
    """Structured audit event — every agent action emits one of these."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    run_id: str
    agent_type: str
    action_type: ActionType
    policy_decision: PolicyDecision = PolicyDecision.PENDING
    path: str | None = None  # canonicalized virtual path
    destination: str | None = None  # FQDN for network calls
    content_hash: str | None = None  # SHA-256 of content written/read
    token_count: int | None = None  # for openai_call actions
    risk_score: float = 0.0
    outcome: Outcome = Outcome.SUCCESS
    error_code: str | None = None
    classification_label: str | None = None
    dlp_patterns: list[str] = Field(default_factory=list)
    content_safety_category: str | None = None
    grounding_score: float | None = None
    data_processing_basis: str = "security_monitoring"
    consent_status: str = "not_required"
    parent_run_id: str | None = None
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    def to_log_analytics_row(self) -> dict:
        """Serialize for Log Analytics DCR ingestion."""
        return {
            "TimeGenerated": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "run_id": self.run_id,
            "agent_type": self.agent_type,
            "action_type": self.action_type.value,
            "policy_decision": self.policy_decision.value,
            "path": self.path or "",
            "destination": self.destination or "",
            "content_hash": self.content_hash or "",
            "token_count": self.token_count or 0,
            "risk_score": self.risk_score,
            "outcome": self.outcome.value,
            "error_code": self.error_code or "",
            "classification_label": self.classification_label or "",
            "dlp_patterns": ",".join(self.dlp_patterns),
            "content_safety_category": self.content_safety_category or "",
            "grounding_score": self.grounding_score if self.grounding_score is not None else 0.0,
            "data_processing_basis": self.data_processing_basis,
            "consent_status": self.consent_status,
            "parent_run_id": self.parent_run_id or "",
            "correlation_id": self.correlation_id,
        }
