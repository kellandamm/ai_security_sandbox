import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../app"))

import main
from rate_limiter import RateLimitExceeded


def test_rate_limit_exceeded_emits_audit_event(monkeypatch):
    events: list[dict[str, object]] = []

    def _capture(req, **kwargs):
        events.append(kwargs)

    def _raise_rate_limit(_identifier: str):
        raise RateLimitExceeded("test-agent", 1.25)

    monkeypatch.setattr(main, "_emit_request_audit_event", _capture)
    monkeypatch.setattr(main._rate_limiter, "check", _raise_rate_limit)

    with TestClient(main.app) as client:
        response = client.get("/health", headers={"X-Agent-ID": "test-agent"})

    assert response.status_code == 429
    assert events
    event = events[-1]
    assert event["action_type"] == main.ActionType.RATE_LIMIT_EXCEEDED
    assert event["policy_decision"] == main.PolicyDecision.DENY
    assert event["outcome"] == main.Outcome.BLOCKED
    assert str(event["error_code"]).startswith("RATE_LIMIT_EXCEEDED:")
