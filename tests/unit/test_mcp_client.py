"""
Phase 6 — MCP client tests (consume external MCP servers).

Verifies:
 - registry loads from env var JSON
 - tool descriptor validation (reject malformed, oversized, bad names)
 - discovery respects the per-agent allowlist (empty allowlist → fail-closed)
 - call_tool round-trip via injected transport
 - transport / HTTP / parse failures raise MCPToolError
 - split_namespaced helper round-trips the mcp::server::tool format
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "app"))

os.environ.setdefault("APIM_IDENTITY_SIGNING_SECRET", "test-signing-secret")

from errors import MCPToolError  # noqa: E402
from mcp_client import (  # noqa: E402
    MAX_DESCRIPTION_LEN,
    MAX_TOOLS_PER_SERVER,
    MCPClient,
    MCPRegistry,
    MCPServerConfig,
    MCPToolDescriptor,
    get_default_registry,
    reset_default_registry,
    split_namespaced,
)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _make_handler(response_payload: dict[str, Any] | list[dict[str, Any]]):
    """Build an httpx MockTransport handler that returns *response_payload*.

    If a list is supplied, responses are returned in order across calls.
    """
    state = {"i": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if isinstance(response_payload, list):
            payload = response_payload[state["i"]]
            state["i"] = min(state["i"] + 1, len(response_payload) - 1)
        else:
            payload = response_payload
        return httpx.Response(200, json=payload)

    return handler


def _client_with(handler) -> MCPClient:
    transport = httpx.MockTransport(handler)
    httpx_client = httpx.AsyncClient(transport=transport)
    registry = MCPRegistry()
    registry.register(
        MCPServerConfig(
            name="weather", url="https://mcp.example.com/rpc", fqdn="mcp.example.com"
        )
    )
    return MCPClient(registry, transport=httpx_client)


# ── registry ────────────────────────────────────────────────────────────────
def test_registry_from_env_parses_valid_entries(monkeypatch):
    monkeypatch.setenv(
        "MCP_EXTERNAL_SERVERS",
        json.dumps(
            [
                {"name": "a", "url": "https://a/rpc", "fqdn": "a.example.com"},
                {"name": "b", "url": "https://b/rpc", "fqdn": "b.example.com"},
            ]
        ),
    )
    reg = MCPRegistry.from_env()
    names = {s.name for s in reg.list()}
    assert names == {"a", "b"}


def test_registry_from_env_ignores_malformed(monkeypatch):
    monkeypatch.setenv("MCP_EXTERNAL_SERVERS", "not-json")
    reg = MCPRegistry.from_env()
    assert reg.list() == []


def test_registry_from_env_ignores_non_list(monkeypatch):
    monkeypatch.setenv("MCP_EXTERNAL_SERVERS", '{"name": "x"}')
    reg = MCPRegistry.from_env()
    assert reg.list() == []


def test_registry_from_env_skips_entries_missing_fields(monkeypatch):
    monkeypatch.setenv(
        "MCP_EXTERNAL_SERVERS",
        json.dumps([{"name": "ok", "url": "https://x", "fqdn": "x.com"}, {"name": "bad"}]),
    )
    reg = MCPRegistry.from_env()
    assert [s.name for s in reg.list()] == ["ok"]


def test_default_registry_is_singleton_until_reset(monkeypatch):
    monkeypatch.setenv("MCP_EXTERNAL_SERVERS", "[]")
    reset_default_registry()
    a = get_default_registry()
    b = get_default_registry()
    assert a is b
    reset_default_registry()
    c = get_default_registry()
    assert c is not a


# ── tool descriptor validation ─────────────────────────────────────────────
def test_validate_tool_rejects_non_dict():
    assert MCPClient._validate_tool("srv", "not-a-dict") is None


def test_validate_tool_rejects_missing_name():
    assert MCPClient._validate_tool("srv", {"description": "x"}) is None


def test_validate_tool_rejects_illegal_chars():
    bad = {"name": "tool with spaces", "description": "x"}
    assert MCPClient._validate_tool("srv", bad) is None


def test_validate_tool_rejects_oversized_name():
    bad = {"name": "a" * 65, "description": "x"}
    assert MCPClient._validate_tool("srv", bad) is None


def test_validate_tool_truncates_description():
    raw = {"name": "ok", "description": "x" * (MAX_DESCRIPTION_LEN + 100)}
    tool = MCPClient._validate_tool("srv", raw)
    assert tool is not None
    assert len(tool.description) == MAX_DESCRIPTION_LEN


def test_validate_tool_accepts_camel_or_snake_schema():
    cs = MCPClient._validate_tool("s", {"name": "x", "inputSchema": {"type": "object"}})
    ss = MCPClient._validate_tool("s", {"name": "x", "input_schema": {"type": "object"}})
    assert cs is not None and ss is not None
    assert cs.input_schema == {"type": "object"}


# ── namespacing ─────────────────────────────────────────────────────────────
def test_tool_descriptor_namespaced_name():
    t = MCPToolDescriptor(server="weather", name="get_forecast", description="", input_schema={})
    assert t.namespaced_name == "mcp::weather::get_forecast"
    assert t.namespace == "mcp://weather/get_forecast"


def test_split_namespaced_round_trip():
    assert split_namespaced("mcp::weather::get_forecast") == ("weather", "get_forecast")


def test_split_namespaced_rejects_local_tool_names():
    assert split_namespaced("file_read") is None
    assert split_namespaced("mcp::weather") is None
    assert split_namespaced("mcp::::tool") is None


# ── discovery happy + fail-closed paths ────────────────────────────────────
def test_discover_returns_validated_tools():
    handler = _make_handler(
        {
            "jsonrpc": "2.0",
            "id": "weather:tools/list",
            "result": {
                "tools": [
                    {"name": "get_forecast", "description": "weather"},
                    {"name": "bad name with space"},
                    {"name": "ok", "description": "second"},
                ]
            },
        }
    )
    client = _client_with(handler)
    tools = _run(client.discover())
    names = {t.name for t in tools}
    assert names == {"get_forecast", "ok"}


def test_discover_caps_tool_count():
    raw_tools = [{"name": f"t{i}", "description": "x"} for i in range(MAX_TOOLS_PER_SERVER + 10)]
    handler = _make_handler(
        {"jsonrpc": "2.0", "id": "x", "result": {"tools": raw_tools}}
    )
    client = _client_with(handler)
    tools = _run(client.discover())
    assert len(tools) == MAX_TOOLS_PER_SERVER


def test_discover_empty_allowlist_returns_nothing():
    """Fail-closed: agent with empty mcp_endpoints gets zero external tools."""
    handler = _make_handler(
        {"jsonrpc": "2.0", "id": "x", "result": {"tools": [{"name": "t"}]}}
    )
    client = _client_with(handler)
    tools = _run(client.discover(allowlist=[]))
    assert tools == []


def test_discover_filters_by_allowlist():
    handler = _make_handler(
        {"jsonrpc": "2.0", "id": "x", "result": {"tools": [{"name": "t"}]}}
    )
    client = _client_with(handler)
    # weather is registered, "missing" is not — allowlist intersection: weather
    tools = _run(client.discover(allowlist=["weather", "missing"]))
    assert len(tools) == 1


def test_discover_handles_server_error_gracefully():
    handler = _make_handler(
        {"jsonrpc": "2.0", "id": "x", "error": {"code": -1, "message": "boom"}}
    )
    client = _client_with(handler)
    tools = _run(client.discover())
    # Errors are logged; discovery returns empty for that server, not raise.
    assert tools == []


def test_discover_handles_missing_tools_array():
    handler = _make_handler(
        {"jsonrpc": "2.0", "id": "x", "result": {"tools": "not-a-list"}}
    )
    client = _client_with(handler)
    tools = _run(client.discover())
    assert tools == []


# ── call_tool happy + fail-closed paths ────────────────────────────────────
def test_call_tool_round_trip():
    handler = _make_handler(
        {"jsonrpc": "2.0", "id": "x", "result": {"content": [{"type": "json", "data": {"ok": True}}]}}
    )
    client = _client_with(handler)
    result = _run(
        client.call_tool(server_name="weather", tool_name="get_forecast", arguments={})
    )
    assert result["content"][0]["data"]["ok"] is True


def test_call_tool_unknown_server_raises():
    handler = _make_handler({"jsonrpc": "2.0", "id": "x", "result": {}})
    client = _client_with(handler)
    try:
        _run(client.call_tool(server_name="nope", tool_name="t", arguments={}))
    except MCPToolError as exc:
        assert "not registered" in str(exc)
    else:
        raise AssertionError("expected MCPToolError")


def test_call_tool_server_error_raises():
    handler = _make_handler(
        {"jsonrpc": "2.0", "id": "x", "error": {"code": -1, "message": "denied"}}
    )
    client = _client_with(handler)
    try:
        _run(client.call_tool(server_name="weather", tool_name="t", arguments={}))
    except MCPToolError as exc:
        assert "denied" in str(exc)
    else:
        raise AssertionError("expected MCPToolError")


def test_call_tool_http_error_raises():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="oops")

    transport = httpx.MockTransport(handler)
    registry = MCPRegistry()
    registry.register(
        MCPServerConfig(
            name="weather", url="https://mcp.example.com/rpc", fqdn="mcp.example.com"
        )
    )
    client = MCPClient(registry, transport=httpx.AsyncClient(transport=transport))
    try:
        _run(client.call_tool(server_name="weather", tool_name="t", arguments={}))
    except MCPToolError as exc:
        assert "http_500" in str(exc)
    else:
        raise AssertionError("expected MCPToolError")


def test_call_tool_invalid_json_raises():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    transport = httpx.MockTransport(handler)
    registry = MCPRegistry()
    registry.register(
        MCPServerConfig(
            name="weather", url="https://mcp.example.com/rpc", fqdn="mcp.example.com"
        )
    )
    client = MCPClient(registry, transport=httpx.AsyncClient(transport=transport))
    try:
        _run(client.call_tool(server_name="weather", tool_name="t", arguments={}))
    except MCPToolError as exc:
        assert "invalid_json" in str(exc)
    else:
        raise AssertionError("expected MCPToolError")


def test_call_tool_transport_failure_raises():
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("cannot connect")

    transport = httpx.MockTransport(handler)
    registry = MCPRegistry()
    registry.register(
        MCPServerConfig(
            name="weather", url="https://mcp.example.com/rpc", fqdn="mcp.example.com"
        )
    )
    client = MCPClient(registry, transport=httpx.AsyncClient(transport=transport))
    try:
        _run(client.call_tool(server_name="weather", tool_name="t", arguments={}))
    except MCPToolError as exc:
        assert "transport_error" in str(exc)
    else:
        raise AssertionError("expected MCPToolError")


def test_to_openai_tool_shape():
    t = MCPToolDescriptor(
        server="weather",
        name="get_forecast",
        description="d",
        input_schema={"type": "object", "properties": {"city": {"type": "string"}}},
    )
    defn = t.to_openai_tool()
    assert defn["type"] == "function"
    assert defn["function"]["name"] == "mcp::weather::get_forecast"
    assert defn["function"]["parameters"]["properties"]["city"]["type"] == "string"
