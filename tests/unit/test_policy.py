"""
Unit tests for policy.py — OPA client behavior.

Tests cover:
  - ALLOW decisions pass through
  - DENY decisions raise PolicyDenyError
  - REQUIRES_APPROVAL raises ApprovalRequiredError
  - OPA unreachable → fail-closed (PolicyDenyError)
  - Deny cache prevents redundant OPA calls
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../app"))

from unittest.mock import MagicMock, patch

import pytest
import requests as req_lib
from models.audit_event import ActionType, Outcome, PolicyDecision
from policy import ApprovalRequiredError, OPAClient, PolicyDenyError

RUN_ID = "12345678-1234-1234-1234-123456789abc"
AGENT_TYPE = "data-analyst"


def _make_client() -> OPAClient:
    auditor = MagicMock()
    auditor.log = MagicMock(return_value=MagicMock())
    return OPAClient(auditor=auditor, run_id=RUN_ID, agent_type=AGENT_TYPE)


class TestOPAClientAllow:
    def test_allow_passes_without_exception(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "result": {"allow": True, "requires_approval": False, "reason": ""}
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("policy.requests.post", return_value=mock_resp):
            client.authorize("file_write", path=f"/workspace/{RUN_ID}/write/out.json")
        # No exception = pass

    def test_allow_logs_policy_check(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "result": {"allow": True, "requires_approval": False}
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("policy.requests.post", return_value=mock_resp):
            client.authorize("openai_call")

        client._auditor.log.assert_called_once()
        call_args = client._auditor.log.call_args
        assert call_args[0][0] == ActionType.POLICY_CHECK
        assert call_args[1]["policy_decision"] == PolicyDecision.ALLOW


class TestOPAClientDeny:
    def test_deny_raises_policy_deny_error(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "result": {
                "allow": False,
                "requires_approval": False,
                "reason": "tool_not_in_capability_manifest",
            }
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("policy.requests.post", return_value=mock_resp):
            with pytest.raises(PolicyDenyError) as exc_info:
                client.authorize("http_delete", path="/workspace/x/write/foo.txt")

        assert exc_info.value.reason == "tool_not_in_capability_manifest"

    def test_deny_logs_blocked_outcome(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "result": {
                "allow": False,
                "requires_approval": False,
                "reason": "path_escapes_run_sandbox",
            }
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("policy.requests.post", return_value=mock_resp):
            with pytest.raises(PolicyDenyError):
                client.authorize("file_write", path="/etc/passwd")

        call_args = client._auditor.log.call_args
        assert call_args[1]["outcome"] == Outcome.BLOCKED
        assert call_args[1]["policy_decision"] == PolicyDecision.DENY

    def test_deny_is_cached_for_30_seconds(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "result": {
                "allow": False,
                "requires_approval": False,
                "reason": "test_deny",
            }
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("policy.requests.post", return_value=mock_resp) as mock_post:
            with pytest.raises(PolicyDenyError):
                client.authorize("file_write", path="/etc/passwd")
            # Second call should use cache — OPA not called again
            with pytest.raises(PolicyDenyError):
                client.authorize("file_write", path="/etc/passwd")

        assert mock_post.call_count == 1  # only one real OPA call

    def test_different_paths_not_cached_together(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "result": {"allow": False, "requires_approval": False, "reason": "test"}
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("policy.requests.post", return_value=mock_resp) as mock_post:
            with pytest.raises(PolicyDenyError):
                client.authorize("file_write", path="/etc/passwd")
            with pytest.raises(PolicyDenyError):
                client.authorize("file_write", path="/etc/shadow")

        assert mock_post.call_count == 2  # different paths = different cache keys


class TestOPAClientApproval:
    def test_requires_approval_raises_approval_required_error(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "result": {
                "allow": False,
                "requires_approval": True,
                "required_approvals": ["security-team@example.com"],
                "reason": "requires_human_approval",
            }
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("policy.requests.post", return_value=mock_resp):
            with pytest.raises(ApprovalRequiredError) as exc_info:
                client.authorize("http_post", destination="api.github.com")

        assert "security-team@example.com" in exc_info.value.required_approvals

    def test_requires_approval_logs_pending(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "result": {
                "allow": False,
                "requires_approval": True,
                "required_approvals": [],
                "reason": "",
            }
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("policy.requests.post", return_value=mock_resp):
            with pytest.raises(ApprovalRequiredError):
                client.authorize("http_post")

        call_args = client._auditor.log.call_args
        assert call_args[1]["policy_decision"] == PolicyDecision.REQUIRES_APPROVAL


class TestOPAClientFailClosed:
    def test_opa_connection_error_fails_closed(self):
        client = _make_client()

        with patch(
            "policy.requests.post", side_effect=req_lib.ConnectionError("OPA down")
        ):
            with pytest.raises(PolicyDenyError) as exc_info:
                client.authorize(
                    "file_write", path=f"/workspace/{RUN_ID}/write/out.txt"
                )

        assert "unreachable" in exc_info.value.reason.lower()

    def test_opa_timeout_fails_closed(self):
        client = _make_client()

        with patch("policy.requests.post", side_effect=req_lib.Timeout("timed out")):
            with pytest.raises(PolicyDenyError):
                client.authorize("openai_call")

    def test_opa_http_500_fails_closed(self):
        client = _make_client()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = req_lib.HTTPError("500 Server Error")

        with patch("policy.requests.post", return_value=mock_resp):
            with pytest.raises(PolicyDenyError):
                client.authorize("file_write")
