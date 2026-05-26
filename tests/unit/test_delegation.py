"""Tests for Phase 2 — agent-to-agent delegation."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[2] / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from delegation import (  # noqa: E402
    DEFAULT_TTL_SECONDS,
    MAX_CALL_DEPTH,
    DelegationToken,
    assert_child_type_allowed,
    assert_scope_is_subset,
)
from errors import DelegationDeniedError  # noqa: E402

SECRET = "unit-test-signing-secret"


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── DelegationToken issue/verify ─────────────────────────────────────────────
class TestDelegationTokenIssue:
    def test_issue_returns_token_and_envelope(self):
        token, envelope = DelegationToken.issue(
            parent_run_id="run-a",
            parent_agent_type="web-researcher",
            child_agent_type="data-analyst",
            allowed_tools=["file_read", "openai_call"],
            signing_secret=SECRET,
        )
        assert token.parent_run_id == "run-a"
        assert token.child_agent_type == "data-analyst"
        assert token.allowed_tools == ("file_read", "openai_call")
        assert token.call_depth == 1
        assert token.expires_at > token.issued_at
        assert "." in envelope

    def test_issue_canonicalizes_tool_order(self):
        token, _ = DelegationToken.issue(
            parent_run_id="r",
            parent_agent_type="web-researcher",
            child_agent_type="data-analyst",
            allowed_tools=["openai_call", "file_read", "file_read"],
            signing_secret=SECRET,
        )
        # Sorted + de-duplicated.
        assert token.allowed_tools == ("file_read", "openai_call")

    def test_issue_rejects_empty_secret(self):
        with pytest.raises(ValueError):
            DelegationToken.issue(
                parent_run_id="r",
                parent_agent_type="web-researcher",
                child_agent_type="data-analyst",
                allowed_tools=[],
                signing_secret="",
            )

    def test_issue_rejects_invalid_depth(self):
        with pytest.raises(ValueError):
            DelegationToken.issue(
                parent_run_id="r",
                parent_agent_type="web-researcher",
                child_agent_type="data-analyst",
                allowed_tools=[],
                signing_secret=SECRET,
                call_depth=0,
            )

    def test_issue_rejects_blank_ids(self):
        with pytest.raises(ValueError):
            DelegationToken.issue(
                parent_run_id="",
                parent_agent_type="web-researcher",
                child_agent_type="data-analyst",
                allowed_tools=[],
                signing_secret=SECRET,
            )

    def test_default_ttl_is_300_seconds(self):
        token, _ = DelegationToken.issue(
            parent_run_id="r",
            parent_agent_type="web-researcher",
            child_agent_type="data-analyst",
            allowed_tools=[],
            signing_secret=SECRET,
        )
        assert token.expires_at - token.issued_at == DEFAULT_TTL_SECONDS


class TestDelegationTokenVerify:
    def _envelope(self, **overrides):
        kwargs = dict(
            parent_run_id="run-a",
            parent_agent_type="web-researcher",
            child_agent_type="data-analyst",
            allowed_tools=["file_read"],
            signing_secret=SECRET,
        )
        kwargs.update(overrides)
        _, env = DelegationToken.issue(**kwargs)
        return env

    def test_round_trip(self):
        env = self._envelope()
        token = DelegationToken.verify(env, signing_secret=SECRET)
        assert token.parent_run_id == "run-a"
        assert token.allowed_tools == ("file_read",)

    def test_signature_tamper_rejected(self):
        env = self._envelope()
        payload, sig = env.split(".", 1)
        # Flip one char in the signature.
        tampered_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
        with pytest.raises(DelegationDeniedError):
            DelegationToken.verify(
                f"{payload}.{tampered_sig}", signing_secret=SECRET
            )

    def test_payload_tamper_rejected(self):
        env = self._envelope()
        payload, sig = env.split(".", 1)
        # Flip one char in the payload — signature won't match the new bytes.
        bad_payload = ("A" if payload[0] != "A" else "B") + payload[1:]
        with pytest.raises(DelegationDeniedError):
            DelegationToken.verify(f"{bad_payload}.{sig}", signing_secret=SECRET)

    def test_wrong_secret_rejected(self):
        env = self._envelope()
        with pytest.raises(DelegationDeniedError):
            DelegationToken.verify(env, signing_secret="different-secret")

    def test_empty_secret_rejected(self):
        env = self._envelope()
        with pytest.raises(DelegationDeniedError):
            DelegationToken.verify(env, signing_secret="")

    def test_empty_envelope_rejected(self):
        with pytest.raises(DelegationDeniedError):
            DelegationToken.verify("", signing_secret=SECRET)

    def test_malformed_envelope_rejected(self):
        with pytest.raises(DelegationDeniedError):
            DelegationToken.verify("not-an-envelope", signing_secret=SECRET)

    def test_expired_token_rejected(self):
        env = self._envelope(ttl_seconds=-1)
        with pytest.raises(DelegationDeniedError, match="expired"):
            DelegationToken.verify(env, signing_secret=SECRET)

    def test_depth_cap_enforced(self):
        env = self._envelope(call_depth=MAX_CALL_DEPTH + 1)
        with pytest.raises(DelegationDeniedError, match="call_depth"):
            DelegationToken.verify(env, signing_secret=SECRET)

    def test_depth_at_cap_accepted(self):
        env = self._envelope(call_depth=MAX_CALL_DEPTH)
        token = DelegationToken.verify(env, signing_secret=SECRET)
        assert token.call_depth == MAX_CALL_DEPTH


# ── runtime tool authorization ───────────────────────────────────────────────
class TestAuthorizeTool:
    def test_allowed_tool_passes(self):
        token, _ = DelegationToken.issue(
            parent_run_id="r",
            parent_agent_type="web-researcher",
            child_agent_type="data-analyst",
            allowed_tools=["file_read"],
            signing_secret=SECRET,
        )
        token.authorize_tool("file_read")  # no raise

    def test_disallowed_tool_rejected(self):
        token, _ = DelegationToken.issue(
            parent_run_id="r",
            parent_agent_type="web-researcher",
            child_agent_type="data-analyst",
            allowed_tools=["file_read"],
            signing_secret=SECRET,
        )
        with pytest.raises(DelegationDeniedError, match="not in delegation scope"):
            token.authorize_tool("http_get")


class TestChildCallChain:
    def test_chain_includes_parent_and_child(self):
        token, _ = DelegationToken.issue(
            parent_run_id="run-b",
            parent_agent_type="web-researcher",
            child_agent_type="data-analyst",
            allowed_tools=[],
            signing_secret=SECRET,
            call_chain=["run-a"],
        )
        chain = token.child_call_chain("run-c")
        assert chain == ["run-a", "run-b", "run-c"]


# ── policy-side validators ───────────────────────────────────────────────────
class TestScopeSubset:
    def test_strict_subset_allowed(self):
        assert_scope_is_subset(
            requested_tools=["file_read"],
            parent_delegation_scopes=["file_read", "openai_call"],
        )

    def test_equal_set_allowed(self):
        assert_scope_is_subset(
            requested_tools=["file_read", "openai_call"],
            parent_delegation_scopes=["openai_call", "file_read"],
        )

    def test_superset_rejected(self):
        with pytest.raises(DelegationDeniedError, match="not in parent"):
            assert_scope_is_subset(
                requested_tools=["file_read", "http_get"],
                parent_delegation_scopes=["file_read"],
            )

    def test_empty_request_allowed(self):
        assert_scope_is_subset(
            requested_tools=[],
            parent_delegation_scopes=[],
        )


class TestChildTypeAllowed:
    def test_listed_child_passes(self):
        assert_child_type_allowed(
            child_agent_type="data-analyst",
            allowed_child_agent_types=["data-analyst"],
        )

    def test_unlisted_child_rejected(self):
        with pytest.raises(DelegationDeniedError, match="not in parent"):
            assert_child_type_allowed(
                child_agent_type="web-researcher",
                allowed_child_agent_types=["data-analyst"],
            )

    def test_empty_allowlist_rejects_all(self):
        with pytest.raises(DelegationDeniedError):
            assert_child_type_allowed(
                child_agent_type="data-analyst",
                allowed_child_agent_types=[],
            )


# ── /runs/{id}/spawn route ───────────────────────────────────────────────────
def _admin_headers(monkeypatch):
    import main as main_module

    monkeypatch.setattr(main_module, "ENABLE_APP_AUTHZ", True)
    monkeypatch.setattr(main_module, "REQUIRE_IDENTITY_SIGNATURE", True)
    monkeypatch.setattr(
        main_module, "APIM_IDENTITY_SIGNING_SECRET", "unit-test-signing-secret"
    )
    monkeypatch.setattr(main_module._kill_switch, "check", lambda *a, **k: None)

    timestamp = str(int(time.time()))
    signature = main_module._compute_identity_signature(
        subject="admin-user",
        tenant_id="tenant-a",
        roles="Sandbox.Admin",
        scopes="",
        timestamp=timestamp,
        secret="unit-test-signing-secret",
    )
    return {
        "X-Auth-Subject": "admin-user",
        "X-Auth-Tenant-Id": "tenant-a",
        "X-Auth-Timestamp": timestamp,
        "X-Auth-Signature": signature,
        "X-Auth-Roles": "Sandbox.Admin",
    }


def _seed_parent_run(main_module, *, agent_type="web-researcher"):
    run_id = "parent-run-1"
    main_module._runs[run_id] = {
        "run_id": run_id,
        "status": main_module.RunStatus.RUNNING,
        "agent_type": agent_type,
        "result": None,
        "error": None,
        "created_at": "2026-05-21T00:00:00+00:00",
        "updated_at": "2026-05-21T00:00:00+00:00",
        "correlation_id": "corr-1",
        "owner_subject": "admin-user",
        "owner_tenant_id": "tenant-a",
        "uploaded_filename": None,
        "parent_run_id": None,
        "call_chain": [run_id],
        "call_depth": 0,
    }
    return run_id


class TestSpawnRoute:
    def _stub_execute_run(self, monkeypatch, main_module):
        # Prevent the spawned background task from actually invoking the agent.
        async def _noop(*args, **kwargs):
            return None

        monkeypatch.setattr(main_module, "_execute_run", _noop)

    def test_spawn_requires_existing_parent(self, monkeypatch):
        import main as main_module
        from fastapi.testclient import TestClient

        headers = _admin_headers(monkeypatch)
        self._stub_execute_run(monkeypatch, main_module)
        with TestClient(main_module.app) as client:
            resp = client.post(
                "/runs/does-not-exist/spawn",
                headers=headers,
                json={
                    "child_agent_type": "data-analyst",
                    "allowed_tools": [],
                    "task": "hello",
                },
            )
        assert resp.status_code == 404

    def test_spawn_blocked_when_parent_not_allowed_to_delegate(self, monkeypatch):
        import main as main_module
        from fastapi.testclient import TestClient

        headers = _admin_headers(monkeypatch)
        self._stub_execute_run(monkeypatch, main_module)
        parent_id = _seed_parent_run(main_module, agent_type="data-analyst")
        try:
            with TestClient(main_module.app) as client:
                resp = client.post(
                    f"/runs/{parent_id}/spawn",
                    headers=headers,
                    json={
                        "child_agent_type": "data-analyst",
                        "allowed_tools": [],
                        "task": "hello",
                    },
                )
            assert resp.status_code == 403
            assert "not permitted to delegate" in resp.json()["detail"]
        finally:
            main_module._runs.pop(parent_id, None)

    def test_spawn_blocked_when_child_type_not_allowed(self, monkeypatch):
        import main as main_module
        from fastapi.testclient import TestClient

        headers = _admin_headers(monkeypatch)
        self._stub_execute_run(monkeypatch, main_module)
        parent_id = _seed_parent_run(main_module)
        try:
            with TestClient(main_module.app) as client:
                resp = client.post(
                    f"/runs/{parent_id}/spawn",
                    headers=headers,
                    json={
                        "child_agent_type": "web-researcher",
                        "allowed_tools": [],
                        "task": "hello",
                    },
                )
            assert resp.status_code == 403
        finally:
            main_module._runs.pop(parent_id, None)

    def test_spawn_blocked_when_scope_not_subset(self, monkeypatch):
        import main as main_module
        from fastapi.testclient import TestClient

        headers = _admin_headers(monkeypatch)
        self._stub_execute_run(monkeypatch, main_module)
        parent_id = _seed_parent_run(main_module)
        try:
            with TestClient(main_module.app) as client:
                resp = client.post(
                    f"/runs/{parent_id}/spawn",
                    headers=headers,
                    json={
                        "child_agent_type": "data-analyst",
                        "allowed_tools": ["http_get"],  # not in parent scope
                        "task": "hello",
                    },
                )
            assert resp.status_code == 403
        finally:
            main_module._runs.pop(parent_id, None)

    def test_spawn_happy_path(self, monkeypatch):
        import main as main_module
        from fastapi.testclient import TestClient

        headers = _admin_headers(monkeypatch)
        self._stub_execute_run(monkeypatch, main_module)
        parent_id = _seed_parent_run(main_module)
        try:
            with TestClient(main_module.app) as client:
                resp = client.post(
                    f"/runs/{parent_id}/spawn",
                    headers=headers,
                    json={
                        "child_agent_type": "data-analyst",
                        "allowed_tools": ["file_read"],
                        "task": "summarize the staged document",
                    },
                )
            assert resp.status_code == 202, resp.text
            body = resp.json()
            assert body["parent_run_id"] == parent_id
            assert body["call_depth"] == 1
            assert body["call_chain"][-2] == parent_id
            assert body["call_chain"][-1] == body["run_id"]
            assert body["delegation_nonce"]
            # Child run was recorded with parent linkage.
            child = main_module._runs[body["run_id"]]
            assert child["parent_run_id"] == parent_id
            assert child["call_depth"] == 1
            assert child["delegation_allowed_tools"] == ["file_read"]
        finally:
            child_id = main_module._runs.get(parent_id, {})
            main_module._runs.pop(parent_id, None)
            for rid in list(main_module._runs.keys()):
                if main_module._runs[rid].get("parent_run_id") == parent_id:
                    main_module._runs.pop(rid, None)
            _ = child_id  # silence linter

    def test_spawn_depth_cap_enforced_via_chain(self, monkeypatch):
        import main as main_module
        from fastapi.testclient import TestClient

        headers = _admin_headers(monkeypatch)
        self._stub_execute_run(monkeypatch, main_module)
        parent_id = _seed_parent_run(main_module)
        # Push parent depth to MAX_CALL_DEPTH so a child spawn would exceed it.
        main_module._runs[parent_id]["call_depth"] = MAX_CALL_DEPTH
        try:
            with TestClient(main_module.app) as client:
                resp = client.post(
                    f"/runs/{parent_id}/spawn",
                    headers=headers,
                    json={
                        "child_agent_type": "data-analyst",
                        "allowed_tools": ["file_read"],
                        "task": "hello",
                    },
                )
            assert resp.status_code == 403
            assert "call_depth" in resp.json()["detail"]
        finally:
            main_module._runs.pop(parent_id, None)

    def test_spawn_requires_signing_secret(self, monkeypatch):
        import main as main_module
        from fastapi.testclient import TestClient

        headers = _admin_headers(monkeypatch)
        # Override secret to empty AFTER computing headers — issuance must fail closed.
        monkeypatch.setattr(main_module, "APIM_IDENTITY_SIGNING_SECRET", "")
        self._stub_execute_run(monkeypatch, main_module)
        parent_id = _seed_parent_run(main_module)
        try:
            with TestClient(main_module.app) as client:
                resp = client.post(
                    f"/runs/{parent_id}/spawn",
                    headers=headers,
                    json={
                        "child_agent_type": "data-analyst",
                        "allowed_tools": ["file_read"],
                        "task": "hello",
                    },
                )
            # Either 401 (sig invalidated when secret was wiped) or 503
            # (route fails closed). Both are acceptable fail-closed behaviors;
            # the contract is "not 202".
            assert resp.status_code in (401, 403, 503)
        finally:
            main_module._runs.pop(parent_id, None)

    def test_spawn_rejects_unauthorized_caller(self, monkeypatch):
        import main as main_module
        from fastapi.testclient import TestClient

        monkeypatch.setattr(main_module, "ENABLE_APP_AUTHZ", True)
        monkeypatch.setattr(main_module, "REQUIRE_IDENTITY_SIGNATURE", True)
        monkeypatch.setattr(main_module._kill_switch, "check", lambda *a, **k: None)
        self._stub_execute_run(monkeypatch, main_module)
        parent_id = _seed_parent_run(main_module)
        try:
            with TestClient(main_module.app) as client:
                resp = client.post(
                    f"/runs/{parent_id}/spawn",
                    json={
                        "child_agent_type": "data-analyst",
                        "allowed_tools": [],
                        "task": "hello",
                    },
                )
            assert resp.status_code in (401, 403)
        finally:
            main_module._runs.pop(parent_id, None)
