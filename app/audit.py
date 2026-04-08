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
from datetime import datetime, timezone
from typing import Optional

import requests
from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, AppendBlobClient

from models.audit_event import AuditEvent, ActionType, Outcome, PolicyDecision

logger = logging.getLogger(__name__)

# ── Configuration from environment ────────────────────────────────────────────
DCE_ENDPOINT = os.environ.get("DCE_ENDPOINT", "")          # Data Collection Endpoint
DCR_IMMUTABLE_ID = os.environ.get("DCR_IMMUTABLE_ID", "")  # Data Collection Rule ID
AUDIT_STORAGE_ACCOUNT = os.environ.get("AUDIT_STORAGE_ACCOUNT", "")
AUDIT_CONTAINER = "audit-logs"
LOG_ANALYTICS_STREAM = "Custom-AiAgentAudit_CL"


class AuditLogger:
    """
    Thread-safe audit logger. Sends every event to Log Analytics and the
    append-only audit blob storage simultaneously.

    Usage:
        auditor = AuditLogger(run_id="...", agent_type="data-analyst", correlation_id="...")
        event = auditor.log(action_type=ActionType.FILE_WRITE, path="/workspace/.../write/out.json",
                            outcome=Outcome.SUCCESS)
    """

    def __init__(self, run_id: str, agent_type: str, correlation_id: str):
        self.run_id = run_id
        self.agent_type = agent_type
        self.correlation_id = correlation_id
        self._credential = DefaultAzureCredential()
        self._blob_client: Optional[AppendBlobClient] = None
        self._blob_name = f"{run_id}/{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"

    def _get_blob_client(self) -> AppendBlobClient:
        if self._blob_client is None and AUDIT_STORAGE_ACCOUNT:
            account_url = f"https://{AUDIT_STORAGE_ACCOUNT}.blob.core.windows.net"
            service = BlobServiceClient(account_url=account_url, credential=self._credential)
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
    ) -> AuditEvent:
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
            correlation_id=self.correlation_id,
        )

        # Always log to stdout for container log capture
        logger.info("audit", extra={"event": event.model_dump(mode="json")})

        # Non-blocking: fire and forget to Log Analytics + blob
        self._send_to_log_analytics(event)
        self._append_to_blob(event)

        return event

    def _send_to_log_analytics(self, event: AuditEvent) -> None:
        if not DCE_ENDPOINT or not DCR_IMMUTABLE_ID:
            return
        try:
            token = self._credential.get_token("https://monitor.azure.com/.default")
            url = f"{DCE_ENDPOINT}/dataCollectionRules/{DCR_IMMUTABLE_ID}/streams/{LOG_ANALYTICS_STREAM}?api-version=2023-01-01"
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
                logger.warning("Log Analytics ingestion failed: %s %s", resp.status_code, resp.text)
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
