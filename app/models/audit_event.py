"""Typed schema for all audit events emitted by the sandbox."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class ActionType(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK_CALL = "network_call"
    OPENAI_CALL = "openai_call"
    POLICY_CHECK = "policy_check"
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_RESPONSE = "approval_response"
    KILL_SWITCH_CHECK = "kill_switch_check"
    RUN_START = "run_start"
    RUN_COMPLETE = "run_complete"
    RUN_ABORT = "run_abort"


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

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    run_id: str
    agent_type: str
    action_type: ActionType
    policy_decision: PolicyDecision = PolicyDecision.PENDING
    path: Optional[str] = None           # canonicalized virtual path
    destination: Optional[str] = None    # FQDN for network calls
    content_hash: Optional[str] = None   # SHA-256 of content written/read
    token_count: Optional[int] = None    # for openai_call actions
    risk_score: float = 0.0
    outcome: Outcome = Outcome.SUCCESS
    error_code: Optional[str] = None
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    def to_log_analytics_row(self) -> dict:
        """Serialize for Log Analytics DCR ingestion (camelCase TimeGenerated required)."""
        return {
            "TimeGenerated": self.timestamp.isoformat(),
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
            "correlation_id": self.correlation_id,
        }
