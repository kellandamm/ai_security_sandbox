"""
Log Analytics query client.

Provides post-run timeline queries against AiAgentAudit_CL and
Sentinel incident listing so the frontend can show what actually
happened inside Azure after a run completes.
"""

from __future__ import annotations

import logging
import os
from datetime import timedelta
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

logger = logging.getLogger(__name__)

LOG_ANALYTICS_WORKSPACE_ID = os.environ.get("LOG_ANALYTICS_WORKSPACE_ID", "")
SENTINEL_WORKSPACE_ID = LOG_ANALYTICS_WORKSPACE_ID  # same workspace


class LogAnalyticsClient:
    def __init__(self):
        self._credential = DefaultAzureCredential()
        self._client: LogsQueryClient | None = None

    def _get_client(self) -> LogsQueryClient:
        if self._client is None:
            self._client = LogsQueryClient(self._credential)
        return self._client

    def query_run_timeline(self, run_id: str) -> list[dict[str, Any]]:
        """
        Return all audit events for a specific run from Log Analytics.
        Used by the frontend's "Audit Timeline" panel after a run completes.
        """
        if not LOG_ANALYTICS_WORKSPACE_ID:
            return []

        # Sanitise run_id — must be a UUID
        import re

        if not re.match(r"^[0-9a-f\-]{36}$", run_id):
            raise ValueError(f"Invalid run_id: {run_id!r}")

        query = f"""
AiAgentAudit_CL
| where run_id_s == "{run_id}"
| order by TimeGenerated asc
| project
    timestamp      = TimeGenerated,
    action_type    = action_type_s,
    policy_decision = policy_decision_s,
    path           = path_s,
    destination    = destination_s,
    outcome        = outcome_s,
    error_code     = error_code_s,
    risk_score     = risk_score_d,
    token_count    = token_count_d,
    content_hash   = content_hash_s,
    correlation_id = correlation_id_s
"""
        try:
            result = self._get_client().query_workspace(
                LOG_ANALYTICS_WORKSPACE_ID,
                query,
                timespan=timedelta(hours=24),
            )
            if result.status == LogsQueryStatus.SUCCESS and result.tables:
                table = result.tables[0]
                cols = [c.name for c in table.columns]
                return [dict(zip(cols, row)) for row in table.rows]
        except Exception as exc:
            logger.warning("Log Analytics query failed: %s", exc)
        return []

    def get_kql_for_run(self, run_id: str) -> str:
        """Return the KQL query string so the frontend can display it."""
        return f"""// Paste into Log Analytics → AiAgentAudit_CL
AiAgentAudit_CL
| where run_id_s == "{run_id}"
| order by TimeGenerated asc
| project TimeGenerated, action_type_s, policy_decision_s,
          path_s, outcome_s, error_code_s, risk_score_d"""

    def get_recent_sentinel_alerts(self, limit: int = 10) -> list[dict[str, Any]]:
        """
        Query Sentinel SecurityAlert table for recent AI sandbox incidents.
        """
        if not LOG_ANALYTICS_WORKSPACE_ID:
            return _mock_sentinel_alerts()

        query = f"""
SecurityAlert
| where ProviderName == "Azure Sentinel"
| where AlertName contains "AI Agent"
| order by TimeGenerated desc
| take {limit}
| project
    id             = SystemAlertId,
    name           = AlertName,
    severity       = AlertSeverity,
    description    = Description,
    timestamp      = TimeGenerated,
    status         = Status,
    tactics        = Tactics,
    entities       = Entities
"""
        try:
            result = self._get_client().query_workspace(
                LOG_ANALYTICS_WORKSPACE_ID,
                query,
                timespan=timedelta(hours=24),
            )
            if result.status == LogsQueryStatus.SUCCESS and result.tables:
                table = result.tables[0]
                cols = [c.name for c in table.columns]
                return [dict(zip(cols, row)) for row in table.rows]
        except Exception as exc:
            logger.warning("Sentinel alert query failed: %s", exc)

        # Fall back to mock data so the UI is always demonstrable
        return _mock_sentinel_alerts()


def _mock_sentinel_alerts() -> list[dict[str, Any]]:
    """
    Return illustrative mock alerts when Sentinel isn't wired up.
    These match the analytics rules defined in monitoring.bicep.
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "id": "alert-001",
            "name": "AI Agent: Frequent OPA Policy Denials",
            "severity": "Medium",
            "description": (
                "More than 5 OPA deny decisions detected in 10 minutes — "
                "possible policy bypass probing."
            ),
            "timestamp": now,
            "status": "New",
            "tactics": "DefenseEvasion",
            "entities": "[]",
        },
        {
            "id": "alert-002",
            "name": "AI Agent: File Write Outside Sandbox Path",
            "severity": "High",
            "description": (
                "A file write was attempted to a path outside "
                "/workspace/{run_id}/write/ — possible sandbox escape."
            ),
            "timestamp": now,
            "status": "New",
            "tactics": "Impact,Persistence",
            "entities": "[]",
        },
    ]
