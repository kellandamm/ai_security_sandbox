"""
OPA policy client.

OPA runs as a sidecar container in the same Container App Job replica (port 8181).
The Rego bundle is loaded from Azure Blob at job start by the init container.

Decision flow:
  ALLOW            → return, caller proceeds
  DENY             → raise PolicyDenyError (action blocked, audit logged)
  REQUIRES_APPROVAL → raise ApprovalRequiredError (caller must gate on Logic App)
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

import requests
from audit import AuditLogger
from models.audit_event import ActionType, Outcome, PolicyDecision

logger = logging.getLogger(__name__)

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
OPA_TIMEOUT_SECONDS = 2
POLICY_PATH = "/v1/data/agent/actions"


class PolicyDenyError(Exception):
    """Raised when OPA returns allow=false."""

    def __init__(self, action: str, reason: str):
        self.action = action
        self.reason = reason
        super().__init__(f"Policy denied '{action}': {reason}")


class ApprovalRequiredError(Exception):
    """Raised when OPA returns requires_approval=true."""

    def __init__(self, action: str, approvals: list[str]):
        self.action = action
        self.required_approvals = approvals
        super().__init__(f"Action '{action}' requires human approval: {approvals}")


class OPAClient:
    """
    Thin client for OPA sidecar.

    Caches DENY decisions for 30 seconds — repeated fast-deny attempts are
    both an anomaly signal and a wasted latency hit.
    """

    def __init__(self, auditor: AuditLogger, run_id: str, agent_type: str):
        self._auditor = auditor
        self._run_id = run_id
        self._agent_type = agent_type
        self._deny_cache: dict[
            str, tuple[str, float]
        ] = {}  # cache_key → (reason, expires)

    def _cache_key(
        self, action_type: str, path: Optional[str], destination: Optional[str]
    ) -> str:
        return f"{action_type}:{path or ''}:{destination or ''}"

    def authorize(
        self,
        action_type: str,
        *,
        path: Optional[str] = None,
        destination: Optional[str] = None,
        extra_input: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Query OPA for authorization.

        Raises PolicyDenyError or ApprovalRequiredError; returns None on ALLOW.
        All decisions are audit-logged regardless of outcome.
        """
        # Fast-path: check deny cache
        cache_key = self._cache_key(action_type, path, destination)
        if cache_key in self._deny_cache:
            reason, expires = self._deny_cache[cache_key]
            if time.monotonic() < expires:
                self._auditor.log(
                    ActionType.POLICY_CHECK,
                    policy_decision=PolicyDecision.DENY,
                    path=path,
                    destination=destination,
                    outcome=Outcome.BLOCKED,
                    error_code=f"cached_deny:{reason}",
                )
                raise PolicyDenyError(action_type, f"[cached] {reason}")

        opa_input: dict[str, Any] = {
            "run_id": self._run_id,
            "agent_type": self._agent_type,
            "action_type": action_type,
            "path": path or "",
            "destination": destination or "",
        }
        if extra_input:
            opa_input.update(extra_input)

        try:
            resp = requests.post(
                f"{OPA_URL}{POLICY_PATH}",
                json={"input": opa_input},
                timeout=OPA_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
        except requests.RequestException as exc:
            # OPA unreachable → fail closed
            logger.error("OPA sidecar unreachable: %s — failing closed", exc)
            self._auditor.log(
                ActionType.POLICY_CHECK,
                policy_decision=PolicyDecision.DENY,
                path=path,
                destination=destination,
                outcome=Outcome.BLOCKED,
                error_code="opa_unreachable",
            )
            raise PolicyDenyError(action_type, "OPA sidecar unreachable")

        allows = result.get("allow", False)
        requires_approval = result.get("requires_approval", False)
        reason = result.get("reason", "policy_deny")
        required_approvals = result.get("required_approvals", [])

        if not allows and not requires_approval:
            # Cache the deny for 30 seconds
            self._deny_cache[cache_key] = (reason, time.monotonic() + 30)
            self._auditor.log(
                ActionType.POLICY_CHECK,
                policy_decision=PolicyDecision.DENY,
                path=path,
                destination=destination,
                outcome=Outcome.BLOCKED,
                error_code=reason,
            )
            raise PolicyDenyError(action_type, reason)

        if requires_approval:
            self._auditor.log(
                ActionType.POLICY_CHECK,
                policy_decision=PolicyDecision.REQUIRES_APPROVAL,
                path=path,
                destination=destination,
                outcome=Outcome.SUCCESS,
            )
            raise ApprovalRequiredError(action_type, required_approvals)

        # ALLOW
        self._auditor.log(
            ActionType.POLICY_CHECK,
            policy_decision=PolicyDecision.ALLOW,
            path=path,
            destination=destination,
            outcome=Outcome.SUCCESS,
        )
