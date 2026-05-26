"""Pydantic input/output models for the FastAPI routes."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AgentType(str, Enum):
    DATA_ANALYST = "data-analyst"
    WEB_RESEARCHER = "web-researcher"


class RunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    KILLED = "killed"


class AgentRunRequest(BaseModel):
    agent_type: AgentType
    task: str = Field(..., min_length=1, max_length=4096)
    input_data: Optional[dict[str, Any]] = None
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class AgentRunResponse(BaseModel):
    run_id: str
    status: RunStatus
    correlation_id: str


class RunStatusResponse(BaseModel):
    run_id: str
    status: RunStatus
    agent_type: str
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str
    updated_at: str
    correlation_id: str


class ApprovalCallbackRequest(BaseModel):
    approved: bool
    reason: Optional[str] = None
    approver: str
    timestamp: str


class KillRunRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=512)
<<<<<<< HEAD


class SpawnRunRequest(BaseModel):
    """Body for ``POST /runs/{parent_run_id}/spawn`` — agent-to-agent delegation."""

    child_agent_type: AgentType
    allowed_tools: list[str] = Field(default_factory=list, max_length=64)
    task: str = Field(..., min_length=1, max_length=4096)
    input_data: Optional[dict[str, Any]] = None


class SpawnRunResponse(BaseModel):
    run_id: str
    parent_run_id: str
    status: RunStatus
    call_depth: int
    call_chain: list[str]
    correlation_id: str
    delegation_nonce: str
    delegation_expires_at: int
=======
>>>>>>> origin/main
