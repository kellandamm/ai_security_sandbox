"""
Phase 6 — MCP server tests (orchestrator-exposed tools).

Verifies:
 - JSON-RPC envelope validation
 - ``initialize`` shape
 - ``tools/list`` returns only capability-manifest-allowed tools, namespaced
 - ``tools/call`` requires an executor; capability deny short-circuits
 - executor result passes through to MCP content payload
 - executor returning {"error": ...} surfaces as POLICY_DENIED
 - admin gate on /mcp/tools and /mcp/rpc routes
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "app"))

os.environ.setdefault("APIM_IDENTITY_SIGNING_SECRET", "test-signing-secret")

import mcp_server  # noqa: E402
from mcp_server import (  # noqa: E402
    CAPABILITY_DENIED,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    MCP_PROTOCOL_VERSION,
    METHOD_NOT_FOUND,
    MCPServer,
    POLICY_DENIED,
)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _fake_tool_definitions(allowed: list[str]):
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": f"{name} tool",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        for name in allowed
    ]


def _server() -> MCPServer:
    return MCPServer(tool_definitions=_fake_tool_definitions)


# ── envelope validation ─────────────────────────────────────────────────────
def test_non_object_envelope_rejected():
    resp = _run(_server().handle_rpc("not-an-object", agent_type="data-analyst"))
    assert resp["error"]["code"] == INVALID_REQUEST


def test_missing_jsonrpc_field_rejected():
    resp = _run(
        _server().handle_rpc({"method": "tools/list", "id": 1}, agent_type="data-analyst")
    )
    assert resp["error"]["code"] == INVALID_REQUEST


def test_missing_method_rejected():
    resp = _run(
        _server().handle_rpc(
            {"jsonrpc": "2.0", "id": 1}, agent_type="data-analyst"
        )
    )
    assert resp["error"]["code"] == INVALID_REQUEST


def test_unknown_method_returns_method_not_found():
    resp = _run(
        _server().handle_rpc(
            {"jsonrpc": "2.0", "id": 7, "method": "tools/unknown"},
            agent_type="data-analyst",
        )
    )
    assert resp["error"]["code"] == METHOD_NOT_FOUND


def test_bad_params_type_rejected():
    resp = _run(
        _server().handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "bad"},
            agent_type="data-analyst",
        )
    )
    assert resp["error"]["code"] == INVALID_PARAMS


# ── initialize ──────────────────────────────────────────────────────────────
def test_initialize_returns_protocol_metadata():
    resp = _run(
        _server().handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            agent_type="data-analyst",
        )
    )
    assert resp["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert resp["result"]["serverInfo"]["name"]


# ── tools/list ─────────────────────────────────────────────────────────────
def test_tools_list_filters_by_capability_manifest():
    # data-analyst: file_read, file_write, openai_call (no http_get).
    resp = _run(
        _server().handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            agent_type="data-analyst",
        )
    )
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {"file_read", "file_write", "openai_call"}
    # All tools must carry a namespaced URI.
    for tool in resp["result"]["tools"]:
        assert tool["uri"].startswith("mcp://orchestrator/data-analyst/")
        assert "inputSchema" in tool


def test_tools_list_unknown_agent_returns_empty():
    resp = _run(
        _server().handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            agent_type="ghost-agent",
        )
    )
    assert resp["result"]["tools"] == []


def test_list_tools_helper_returns_namespaced_uris():
    tools = _server().list_tools("web-researcher")
    names = {t["name"] for t in tools}
    assert "http_get" in names
    for tool in tools:
        assert tool["uri"].startswith("mcp://orchestrator/web-researcher/")


# ── tools/call ──────────────────────────────────────────────────────────────
def test_tools_call_requires_executor():
    resp = _run(
        _server().handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "file_read", "arguments": {}},
            },
            agent_type="data-analyst",
        )
    )
    assert resp["error"]["code"] == INTERNAL_ERROR


def test_tools_call_capability_deny_short_circuits():
    calls: list[tuple[str, dict]] = []

    async def executor(name: str, args: dict) -> dict:
        calls.append((name, args))
        return {"ok": True}

    resp = _run(
        _server().handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                # http_get is NOT in data-analyst manifest.
                "params": {"name": "http_get", "arguments": {"url": "x"}},
            },
            agent_type="data-analyst",
            executor=executor,
        )
    )
    assert resp["error"]["code"] == CAPABILITY_DENIED
    # Executor must not have been invoked — short circuit before sandbox.
    assert calls == []


def test_tools_call_unknown_agent_blocked():
    async def executor(name: str, args: dict) -> dict:
        return {"ok": True}

    resp = _run(
        _server().handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "file_read", "arguments": {}},
            },
            agent_type="not-a-real-agent",
            executor=executor,
        )
    )
    assert resp["error"]["code"] == CAPABILITY_DENIED


def test_tools_call_success_wraps_result_in_mcp_content():
    async def executor(name: str, args: dict) -> dict:
        return {"content": "abc", "size": 3}

    resp = _run(
        _server().handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "file_read", "arguments": {"path": "/x"}},
            },
            agent_type="data-analyst",
            executor=executor,
        )
    )
    assert resp["result"]["isError"] is False
    assert resp["result"]["uri"] == "mcp://orchestrator/data-analyst/file_read"
    payload = resp["result"]["content"][0]
    assert payload["type"] == "json"
    assert payload["data"]["content"] == "abc"


def test_tools_call_executor_error_dict_surfaces_as_policy_denied():
    async def executor(name: str, args: dict) -> dict:
        return {"error": "Policy denied: tool_not_in_manifest"}

    resp = _run(
        _server().handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "file_read", "arguments": {}},
            },
            agent_type="data-analyst",
            executor=executor,
        )
    )
    assert resp["error"]["code"] == POLICY_DENIED


def test_tools_call_missing_tool_name_rejected():
    async def executor(name: str, args: dict) -> dict:
        return {}

    resp = _run(
        _server().handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"arguments": {}},
            },
            agent_type="data-analyst",
            executor=executor,
        )
    )
    assert resp["error"]["code"] == INVALID_PARAMS


# ── audit emission ──────────────────────────────────────────────────────────
class _RecordingAuditor:
    def __init__(self) -> None:
        self.events: list[tuple] = []

    def log(self, action, **kwargs):
        self.events.append((action, kwargs))


def test_tools_list_emits_discovery_audit():
    auditor = _RecordingAuditor()
    _run(
        _server().handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            agent_type="data-analyst",
            auditor=auditor,
        )
    )
    actions = [e[0].value for e in auditor.events]
    assert "mcp_tool_discovery" in actions


def test_tools_call_emits_audit_event_on_success():
    auditor = _RecordingAuditor()

    async def executor(name: str, args: dict) -> dict:
        return {"ok": True}

    _run(
        _server().handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "file_read", "arguments": {}},
            },
            agent_type="data-analyst",
            executor=executor,
            auditor=auditor,
        )
    )
    actions = [e[0].value for e in auditor.events]
    assert "mcp_tool_call" in actions


# ── route gates ──────────────────────────────────────────────────────────────
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


def test_mcp_tools_route_requires_admin(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    monkeypatch.setattr(main_module, "ENABLE_APP_AUTHZ", True)
    monkeypatch.setattr(main_module, "REQUIRE_IDENTITY_SIGNATURE", True)
    monkeypatch.setattr(main_module._kill_switch, "check", lambda *a, **k: None)
    with TestClient(main_module.app) as client:
        resp = client.get("/mcp/tools?agent_type=data-analyst")
    assert resp.status_code in (401, 403)


def test_mcp_tools_route_returns_namespaced_tools(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.get(
            "/mcp/tools?agent_type=data-analyst", headers=headers
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_type"] == "data-analyst"
    assert {t["name"] for t in body["tools"]} >= {"file_read", "file_write"}


def test_mcp_tools_route_rejects_unknown_agent_type(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.get(
            "/mcp/tools?agent_type=ghost", headers=headers
        )
    assert resp.status_code == 400


def test_mcp_rpc_initialize_via_route(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.post(
            "/mcp/rpc?agent_type=data-analyst",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["protocolVersion"] == mcp_server.MCP_PROTOCOL_VERSION


def test_mcp_rpc_tools_list_via_route(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.post(
            "/mcp/rpc?agent_type=web-researcher",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
    assert resp.status_code == 200
    names = {t["name"] for t in resp.json()["result"]["tools"]}
    assert "http_get" in names


def test_mcp_external_servers_route_admin_only(monkeypatch):
    from fastapi.testclient import TestClient

    import main as main_module

    headers = _admin_headers(monkeypatch)
    with TestClient(main_module.app) as client:
        resp = client.get("/mcp/external/servers", headers=headers)
    assert resp.status_code == 200
    assert "servers" in resp.json()
