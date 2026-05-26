"""
Structured audit logger.

Every agent action emits an AuditEvent that flows to:
  1. Azure Monitor Log Analytics (via DCR/DCE) — queryable, Sentinel-visible
  2. Append-only audit blob SA as JSONL — tamper-evident, WORM-protected

Rule 9: every file action observable and replayable.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Callable, Optional

import requests
from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobClient, BlobServiceClient
<<<<<<< HEAD

from governance import derive_consent_status, governance_reference
=======
>>>>>>> origin/main
from models.audit_event import ActionType, AuditEvent, Outcome, PolicyDecision

logger = logging.getLogger(__name__)

# ── Configuration from environment ────────────────────────────────────────────
DCE_ENDPOINT = os.environ.get("DCE_ENDPOINT", "")  # Data Collection Endpoint
DCR_IMMUTABLE_ID = os.environ.get("DCR_IMMUTABLE_ID", "")  # Data Collection Rule ID
AUDIT_STORAGE_ACCOUNT = os.environ.get("AUDIT_STORAGE_ACCOUNT", "")
AUDIT_CONTAINER = "audit-logs"
LOG_ANALYTICS_STREAM = "Custom-AiAgentAudit_CL"

_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CARD]"),
    (
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        "[REDACTED_EMAIL]",
    ),
    (
        re.compile(r"\b(?:\+?\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}\b"),
        "[REDACTED_PHONE]",
    ),
    (
        re.compile(r"(?i)AccountKey\s*=\s*[A-Za-z0-9+/]{32,}={0,2}"),
        "AccountKey=[REDACTED_KEY]",
    ),
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]+"), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_PAT]"),
]


def redact_sensitive_text(value: str | None) -> str | None:
    if not value:
        return value
    redacted = value
    for pattern, replacement in _REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_audit_event_dict(event_dict: dict) -> dict:
    sanitized = dict(event_dict)
    for key in ["path", "destination", "error_code", "parent_run_id"]:
        if isinstance(sanitized.get(key), str):
            sanitized[key] = redact_sensitive_text(sanitized[key])
    return sanitized


class AuditLogger:
    """
    Thread-safe audit logger. Sends every event to Log Analytics and the
    append-only audit blob storage simultaneously.

    Usage:
        auditor = AuditLogger(
            run_id="...",
            agent_type="data-analyst",
            correlation_id="...",
        )
        event = auditor.log(
            action_type=ActionType.FILE_WRITE,
            path="/workspace/.../write/out.json",
            outcome=Outcome.SUCCESS,
        )
    """

    def __init__(
        self,
        run_id: str,
        agent_type: str,
        correlation_id: str,
        on_event: Optional[Callable[[dict], None]] = None,
    ):
        self.run_id = run_id
        self.agent_type = agent_type
        self.correlation_id = correlation_id
        self._credential = DefaultAzureCredential()
        self._blob_client: Optional[BlobClient] = None
        date_suffix = datetime.now(timezone.utc).strftime("%Y%m%d")
        self._blob_name = f"{run_id}/{date_suffix}.jsonl"
        # Optional callback — used by the SSE endpoint to stream events to the browser
        self._on_event = on_event

    def _get_blob_client(self) -> BlobClient:
        if self._blob_client is None and AUDIT_STORAGE_ACCOUNT:
            account_url = f"https://{AUDIT_STORAGE_ACCOUNT}.blob.core.windows.net"
            service = BlobServiceClient(
                account_url=account_url, credential=self._credential
            )
            container = service.get_container_client(AUDIT_CONTAINER)
            self._blob_client = container.get_blob_client(self._blob_name)
            # Ensure append blob exists (create if first write for this run)
            try:
                self._blob_client.create_append_blob()
            except Exception:
                pass  # already exists
        return self._blob_client  # type: ignore[return-value]

    def log(
        self,
        action_type: ActionType,
        *,
        policy_decision: PolicyDecision = PolicyDecision.ALLOW,
        path: Optional[str] = None,
        destination: Optional[str] = None,
        content_hash: Optional[str] = None,
        token_count: Optional[int] = None,
        risk_score: float = 0.0,
        outcome: Outcome = Outcome.SUCCESS,
        error_code: Optional[str] = None,
        classification_label: Optional[str] = None,
        dlp_patterns: Optional[list[str]] = None,
        content_safety_category: Optional[str] = None,
        grounding_score: Optional[float] = None,
        data_processing_basis: str = "security_monitoring",
<<<<<<< HEAD
        consent_status: Optional[str] = None,
        parent_run_id: Optional[str] = None,
        # ── Foundry Shield uplift (phases 1-7) ────────────────────────────────
        parent_agent_id: Optional[str] = None,
        call_chain: Optional[list[str]] = None,
        governance_metadata_ref: Optional[str] = None,
        injection_score: Optional[float] = None,
        tool_namespace: Optional[str] = None,
        confirmation_token: Optional[str] = None,
        estimated_cost_usd: Optional[float] = None,
        anomaly_score: Optional[float] = None,
    ) -> AuditEvent:
        # ── Phase 3: auto-attach ISO 42001 / NIST AI RMF governance metadata.
        # Explicit overrides win; otherwise look up the agent's model card.
        if governance_metadata_ref is None:
            governance_metadata_ref = governance_reference(self.agent_type)
        # ── Phase 3: derive consent_status from classification when caller
        # did not assert it explicitly. Preserves backwards-compatibility
        # because the previous default was "not_required".
        if consent_status is None:
            consent_status = derive_consent_status(classification_label)
=======
        consent_status: str = "not_required",
        parent_run_id: Optional[str] = None,
    ) -> AuditEvent:
>>>>>>> origin/main
        event = AuditEvent(
            run_id=self.run_id,
            agent_type=self.agent_type,
            action_type=action_type,
            policy_decision=policy_decision,
            path=path,
            destination=destination,
            content_hash=content_hash,
            token_count=token_count,
            risk_score=risk_score,
            outcome=outcome,
            error_code=error_code,
            classification_label=classification_label,
            dlp_patterns=dlp_patterns or [],
            content_safety_category=content_safety_category,
            grounding_score=grounding_score,
            data_processing_basis=data_processing_basis,
            consent_status=consent_status,
            parent_run_id=parent_run_id,
            correlation_id=self.correlation_id,
<<<<<<< HEAD
            parent_agent_id=parent_agent_id,
            call_chain=call_chain or [],
            governance_metadata_ref=governance_metadata_ref,
            injection_score=injection_score,
            tool_namespace=tool_namespace,
            confirmation_token=confirmation_token,
            estimated_cost_usd=estimated_cost_usd,
            anomaly_score=anomaly_score,
=======
>>>>>>> origin/main
        )

        redacted_payload = redact_audit_event_dict(event.model_dump(mode="json"))
        redacted_event = event.model_copy(update=redacted_payload)

        # Always log to stdout for container log capture
        logger.info("audit", extra={"event": redacted_payload})

        # Push to SSE queue if a frontend listener is connected
        if self._on_event:
            try:
                self._on_event(redacted_payload)
            except Exception:
                pass

        # Non-blocking: fire and forget to Log Analytics + blob
        self._send_to_log_analytics(redacted_event)
        self._append_to_blob(redacted_event)

        return event

    def _send_to_log_analytics(self, event: AuditEvent) -> None:
        if not DCE_ENDPOINT or not DCR_IMMUTABLE_ID:
            return
        try:
            token = self._credential.get_token("https://monitor.azure.com/.default")
            url = (
                f"{DCE_ENDPOINT}/dataCollectionRules/{DCR_IMMUTABLE_ID}/streams/"
                f"{LOG_ANALYTICS_STREAM}?api-version=2023-01-01"
            )
            resp = requests.post(
                url,
                json=[event.to_log_analytics_row()],
                headers={
                    "Authorization": f"Bearer {token.token}",
                    "Content-Type": "application/json",
                },
                timeout=5,
            )
            if resp.status_code not in (200, 204):
                logger.warning(
                    "Log Analytics ingestion failed: %s %s",
                    resp.status_code,
                    resp.text,
                )
        except Exception as exc:
            # Audit logging failure must never crash the agent — but must be visible
            logger.error("Failed to send audit event to Log Analytics: %s", exc)

    def _append_to_blob(self, event: AuditEvent) -> None:
        if not AUDIT_STORAGE_ACCOUNT:
            return
        try:
            blob = self._get_blob_client()
            if blob:
                line = json.dumps(event.model_dump(mode="json"), default=str) + "\n"
                blob.append_block(line.encode())
        except AzureError as exc:
            logger.error("Failed to append audit event to blob: %s", exc)
