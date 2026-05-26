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
    classification_label = classification_label_s,
    dlp_patterns   = dlp_patterns_s,
    content_safety_category = content_safety_category_s,
    grounding_score = grounding_score_d,
    data_processing_basis = data_processing_basis_s,
    consent_status = consent_status_s,
    parent_run_id  = parent_run_id_s,
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
          path_s, outcome_s, error_code_s, risk_score_d,
          classification_label_s, dlp_patterns_s, content_safety_category_s,
          data_processing_basis_s, consent_status_s"""

    def get_workbook_queries(self) -> dict[str, str]:
        """Return query pack for Sentinel workbook and security dashboard creation."""
        return {
            "posture_overview": """
AiAgentAudit_CL
<<<<<<< HEAD
| summarize events=count(), blocks=countif(
    policy_decision_s == \"deny\" or outcome_s == \"blocked\")
    by action_type_s
=======
| summarize events=count(), blocks=countif(policy_decision_s == \"deny\" or outcome_s == \"blocked\") by action_type_s
>>>>>>> origin/main
| order by blocks desc, events desc
""".strip(),
            "agent_risk_heatmap": """
AiAgentAudit_CL
<<<<<<< HEAD
| summarize avg_risk=avg(risk_score_d), max_risk=max(risk_score_d),
    events=count()
    by agent_type_s, action_type_s
=======
| summarize avg_risk=avg(risk_score_d), max_risk=max(risk_score_d), events=count() by agent_type_s, action_type_s
>>>>>>> origin/main
| order by avg_risk desc
""".strip(),
            "dlp_interceptions": """
AiAgentAudit_CL
| where action_type_s == \"dlp_scan\"
<<<<<<< HEAD
| where policy_decision_s == \"deny\"
    or outcome_s == \"blocked\"
    or dlp_patterns_s != \"\"
| project TimeGenerated, run_id_s, agent_type_s, dlp_patterns_s,
    classification_label_s, risk_score_d, error_code_s, correlation_id_s
=======
| where policy_decision_s == \"deny\" or outcome_s == \"blocked\" or dlp_patterns_s != \"\"
| project TimeGenerated, run_id_s, agent_type_s, dlp_patterns_s, classification_label_s, risk_score_d, error_code_s, correlation_id_s
>>>>>>> origin/main
| order by TimeGenerated desc
""".strip(),
            "content_safety_blocks": """
AiAgentAudit_CL
| where action_type_s == \"content_safety_check\"
| where policy_decision_s == \"deny\" or outcome_s == \"blocked\"
<<<<<<< HEAD
| project TimeGenerated, run_id_s, agent_type_s,
    content_safety_category_s, risk_score_d, error_code_s, correlation_id_s
=======
| project TimeGenerated, run_id_s, agent_type_s, content_safety_category_s, risk_score_d, error_code_s, correlation_id_s
>>>>>>> origin/main
| order by TimeGenerated desc
""".strip(),
            "kill_switch_activity": """
AiAgentAudit_CL
| where action_type_s == \"kill_switch_check\"
<<<<<<< HEAD
| summarize checks=count(), blocked=countif(outcome_s == \"blocked\")
    by run_id_s, agent_type_s
=======
| summarize checks=count(), blocked=countif(outcome_s == \"blocked\") by run_id_s, agent_type_s
>>>>>>> origin/main
| order by blocked desc, checks desc
""".strip(),
            "token_budget": """
AiAgentAudit_CL
| where action_type_s == \"openai_call\"
<<<<<<< HEAD
| summarize total_tokens=sum(token_count_d),
    avg_tokens=avg(token_count_d), calls=count()
    by run_id_s, agent_type_s
=======
| summarize total_tokens=sum(token_count_d), avg_tokens=avg(token_count_d), calls=count() by run_id_s, agent_type_s
>>>>>>> origin/main
| order by total_tokens desc
""".strip(),
            "anomaly_candidates": """
let per_run = AiAgentAudit_CL
<<<<<<< HEAD
| summarize total_events=count(), total_tokens=sum(token_count_d),
    max_risk=max(risk_score_d)
    by run_id_s, agent_type_s;
let baselines = per_run
| summarize avg_events=avg(total_events), avg_tokens=avg(total_tokens);
per_run
| join kind=inner baselines on 1==1
| where total_events > (avg_events * 3.0)
    or total_tokens > (avg_tokens * 3.0)
    or max_risk >= 0.8
| project run_id_s, agent_type_s, total_events, total_tokens,
    max_risk, avg_events, avg_tokens
=======
| summarize total_events=count(), total_tokens=sum(token_count_d), max_risk=max(risk_score_d) by run_id_s, agent_type_s;
let baselines = per_run | summarize avg_events=avg(total_events), avg_tokens=avg(total_tokens);
per_run
| join kind=inner baselines on 1==1
| where total_events > (avg_events * 3.0) or total_tokens > (avg_tokens * 3.0) or max_risk >= 0.8
| project run_id_s, agent_type_s, total_events, total_tokens, max_risk, avg_events, avg_tokens
>>>>>>> origin/main
| order by max_risk desc, total_events desc
        """.strip(),
                "auth_failure_timeline": """
        AiAgentAudit_CL
<<<<<<< HEAD
        | where action_type_s in (
            "signature_verification_failure", "policy_check")
        | where outcome_s == "blocked"
        | summarize failures=count()
            by error_code_s, correlation_id_s, bin(TimeGenerated, 1m)
=======
        | where action_type_s in ("signature_verification_failure", "policy_check")
        | where outcome_s == "blocked"
        | summarize failures=count() by error_code_s, correlation_id_s, bin(TimeGenerated, 1m)
>>>>>>> origin/main
        | order by TimeGenerated desc
        """.strip(),
                "admin_action_timeline": """
        AiAgentAudit_CL
<<<<<<< HEAD
        | where action_type_s in (
            "admin_kill_switch_toggle",
            "admin_run_delete",
            "admin_dsar_export")
        | project TimeGenerated, action_type_s, error_code_s,
            path_s, correlation_id_s
=======
            | where action_type_s in ("admin_kill_switch_toggle", "admin_run_delete", "admin_dsar_export")
        | project TimeGenerated, action_type_s, error_code_s, path_s, correlation_id_s
>>>>>>> origin/main
        | order by TimeGenerated desc
        """.strip(),
                "cross_tenant_probing": """
        AiAgentAudit_CL
        | where action_type_s == "cross_tenant_access_attempt"
<<<<<<< HEAD
        | summarize attempts=count(), paths=make_set(path_s)
            by correlation_id_s, bin(TimeGenerated, 5m)
=======
        | summarize attempts=count(), paths=make_set(path_s) by correlation_id_s, bin(TimeGenerated, 5m)
>>>>>>> origin/main
        | where attempts >= 3
        | order by attempts desc, TimeGenerated desc
        """.strip(),
                "rate_limit_spikes": """
        AiAgentAudit_CL
        | where action_type_s == "rate_limit_exceeded"
<<<<<<< HEAD
        | summarize blocked=count()
            by error_code_s, path_s, bin(TimeGenerated, 5m)
=======
        | summarize blocked=count() by error_code_s, path_s, bin(TimeGenerated, 5m)
>>>>>>> origin/main
        | where blocked >= 5
        | order by blocked desc, TimeGenerated desc
        """.strip(),
                "compliance_processing_basis": """
            AiAgentAudit_CL
<<<<<<< HEAD
            | summarize events=count()
                by data_processing_basis_s, consent_status_s
=======
            | summarize events=count() by data_processing_basis_s, consent_status_s
>>>>>>> origin/main
            | order by events desc
        """.strip(),
                "compliance_classification_posture": """
            AiAgentAudit_CL
<<<<<<< HEAD
            | summarize events=count(),
                blocked=countif(outcome_s == "blocked")
                by classification_label_s, action_type_s
=======
            | summarize events=count(), blocked=countif(outcome_s == "blocked") by classification_label_s, action_type_s
>>>>>>> origin/main
            | order by blocked desc, events desc
        """.strip(),
                "compliance_dsar_exports": """
            AiAgentAudit_CL
            | where action_type_s == "admin_dsar_export"
            | project TimeGenerated, run_id_s, correlation_id_s, error_code_s, path_s
            | order by TimeGenerated desc
""".strip(),
        }

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
