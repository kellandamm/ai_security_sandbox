"""
Phase 6 — MCP client (consume external MCP servers from the orchestrator).

Allows the agent loop to merge tools advertised by external MCP servers
into its tool catalog **subject to** the calling agent type's
``mcp_endpoints`` allowlist on its capability manifest, an OPA decision
(``MCP_TOOL_CALL``), and a network egress check against the server FQDN.

Threat model
~~~~~~~~~~~~
External MCP servers are untrusted. They can return arbitrary JSON. We:

* Validate each tool descriptor matches a minimal schema before merging.
* Namespace every tool name as ``mcp::<server>::<tool>`` so it cannot
  collide with a local tool name and the OPA layer can tell them apart.
* Strip executable/markup content from tool descriptions (informational
  fields only flow into the model prompt; the model never reads raw
  server-returned bytes without OPA + retrieved-content rescan).
* Fail closed on transport, timeout, or non-2xx HTTP — discovery and
  invocation both raise :class:`MCPToolError` and emit audit events.

Configuration
~~~~~~~~~~~~~
External servers come from the ``MCP_EXTERNAL_SERVERS`` env var (JSON):

    [{"name": "weather",
      "url": "https://mcp.example.com/rpc",
      "fqdn": "mcp.example.com"}]

…or programmatic registration via :class:`MCPRegistry.register`.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from errors import MCPToolError

logger = logging.getLogger(__name__)

# Bound how much we'll ingest from an untrusted server — defense in depth.
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TOOLS_PER_SERVER = 32
MAX_DESCRIPTION_LEN = 1024


@dataclass(frozen=True)
class MCPServerConfig:
    """An external MCP server the orchestrator may consume from."""

    name: str
    url: str
    fqdn: str  # used for egress allowlist check
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def to_audit(self) -> dict[str, Any]:
        return {"name": self.name, "fqdn": self.fqdn}


@dataclass
class MCPToolDescriptor:
    """Validated tool descriptor returned by an external MCP server."""

    server: str
    name: str
    description: str
    input_schema: dict[str, Any]

    @property
    def namespaced_name(self) -> str:
        # Use double-colon — it cannot appear in a local tool name (regex
        # disallows it elsewhere) and disambiguates audit events.
        return f"mcp::{self.server}::{self.name}"

    @property
    def namespace(self) -> str:
        return f"mcp://{self.server}/{self.name}"

    def to_openai_tool(self) -> dict[str, Any]:
        """Convert to the OpenAI tool format the agent loop already consumes."""
        return {
            "type": "function",
            "function": {
                "name": self.namespaced_name,
                "description": self.description,
                "parameters": self.input_schema or {
                    "type": "object",
                    "properties": {},
                },
            },
        }


class MCPRegistry:
    """In-memory registry of external MCP servers."""

    def __init__(self) -> None:
        self._servers: dict[str, MCPServerConfig] = {}

    @classmethod
    def from_env(cls, env_var: str = "MCP_EXTERNAL_SERVERS") -> "MCPRegistry":
        reg = cls()
        raw = os.environ.get(env_var, "").strip()
        if not raw:
            return reg
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Bad %s JSON; ignoring: %s", env_var, exc)
            return reg
        if not isinstance(entries, list):
            return reg
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            url = entry.get("url")
            fqdn = entry.get("fqdn")
            if not (
                isinstance(name, str)
                and isinstance(url, str)
                and isinstance(fqdn, str)
            ):
                continue
            reg.register(MCPServerConfig(name=name, url=url, fqdn=fqdn))
        return reg

    def register(self, server: MCPServerConfig) -> None:
        self._servers[server.name] = server

    def get(self, name: str) -> Optional[MCPServerConfig]:
        return self._servers.get(name)

    def list(self) -> list[MCPServerConfig]:
        return list(self._servers.values())


class MCPClient:
    """Async JSON-RPC 2.0 client speaking the MCP profile."""

    def __init__(
        self,
        registry: MCPRegistry,
        *,
        transport: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._registry = registry
        self._transport = transport
        self._owns_transport = transport is None

    # ── lifecycle ─────────────────────────────────────────────────────────
    async def __aenter__(self) -> "MCPClient":
        if self._transport is None:
            self._transport = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS)
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._owns_transport and self._transport is not None:
            await self._transport.aclose()
            self._transport = None

    # ── discovery ─────────────────────────────────────────────────────────
    async def discover(
        self,
        *,
        allowlist: list[str] | None = None,
    ) -> list[MCPToolDescriptor]:
        """Discover tools across all registered servers.

        ``allowlist`` is the agent's ``capability_manifest.mcp_endpoints``.
        When provided, only servers whose ``name`` appears in the allowlist
        are queried. An empty allowlist returns ``[]`` — fail-closed for
        agents that have not opted in to MCP.
        """
        if allowlist is None:
            servers = self._registry.list()
        elif not allowlist:
            return []
        else:
            servers = [s for s in self._registry.list() if s.name in allowlist]

        out: list[MCPToolDescriptor] = []
        for server in servers:
            try:
                tools = await self._list_tools_one(server)
            except MCPToolError as exc:
                logger.warning("MCP discovery failed for %s: %s", server.name, exc)
                continue
            out.extend(tools)
        return out

    async def _list_tools_one(self, server: MCPServerConfig) -> list[MCPToolDescriptor]:
        response = await self._rpc(server, method="tools/list", params={})
        if "error" in response:
            msg = response["error"].get("message", "tools/list failed")
            raise MCPToolError(f"[{server.name}] {msg}")
        result = response.get("result", {})
        raw_tools = result.get("tools", [])
        if not isinstance(raw_tools, list):
            raise MCPToolError(
                f"[{server.name}] tools/list result missing 'tools' array"
            )
        out: list[MCPToolDescriptor] = []
        for raw in raw_tools[:MAX_TOOLS_PER_SERVER]:
            tool = self._validate_tool(server.name, raw)
            if tool is not None:
                out.append(tool)
        return out

    @staticmethod
    def _validate_tool(server: str, raw: Any) -> Optional[MCPToolDescriptor]:
        if not isinstance(raw, dict):
            return None
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            return None
        # Local tool names use snake_case [a-z_]. We accept the same set
        # for external names to keep audit fields safe.
        if not all(c.isalnum() or c in "_-" for c in name) or len(name) > 64:
            return None
        description = raw.get("description") or ""
        if not isinstance(description, str):
            description = ""
        description = description[:MAX_DESCRIPTION_LEN]
        input_schema = raw.get("inputSchema") or raw.get("input_schema") or {}
        if not isinstance(input_schema, dict):
            input_schema = {}
        return MCPToolDescriptor(
            server=server,
            name=name,
            description=description,
            input_schema=input_schema,
        )

    # ── invocation ────────────────────────────────────────────────────────
    async def call_tool(
        self,
        *,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> Any:
        server = self._registry.get(server_name)
        if server is None:
            raise MCPToolError(f"[{server_name}] server not registered")
        response = await self._rpc(
            server,
            method="tools/call",
            params={"name": tool_name, "arguments": arguments},
        )
        if "error" in response:
            msg = response["error"].get("message", "tools/call failed")
            raise MCPToolError(f"[{server_name}] {msg}")
        return response.get("result")

    # ── transport ─────────────────────────────────────────────────────────
    async def _rpc(
        self,
        server: MCPServerConfig,
        *,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        envelope = {
            "jsonrpc": "2.0",
            "id": f"{server.name}:{method}",
            "method": method,
            "params": params,
        }
        if self._transport is None:
            # Lazy-init for callers not using the async context manager.
            self._transport = httpx.AsyncClient(timeout=server.timeout_seconds)
            self._owns_transport = True
        try:
            resp = await self._transport.post(
                server.url, json=envelope, timeout=server.timeout_seconds
            )
        except (httpx.HTTPError, OSError) as exc:
            raise MCPToolError(
                f"[{server.name}] transport_error:{exc}"
            ) from exc
        if resp.status_code >= 400:
            raise MCPToolError(
                f"[{server.name}] http_{resp.status_code}:{resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise MCPToolError(
                f"[{server.name}] invalid_json_response"
            ) from exc


# ── Module-level helpers used by the agent loop ──────────────────────────────
_default_registry: MCPRegistry | None = None


def get_default_registry() -> MCPRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = MCPRegistry.from_env()
    return _default_registry


def reset_default_registry() -> None:
    """Test helper — drop cached singleton so env changes re-read."""
    global _default_registry
    _default_registry = None


def split_namespaced(name: str) -> tuple[str, str] | None:
    """Return ``(server, tool)`` if *name* is an MCP-namespaced tool name."""
    if not name.startswith("mcp::"):
        return None
    rest = name[len("mcp::") :]
    if "::" not in rest:
        return None
    server, tool = rest.split("::", 1)
    if not server or not tool:
        return None
    return server, tool


__all__ = [
    "MAX_DESCRIPTION_LEN",
    "MAX_TOOLS_PER_SERVER",
    "MCPClient",
    "MCPRegistry",
    "MCPServerConfig",
    "MCPToolDescriptor",
    "get_default_registry",
    "reset_default_registry",
    "split_namespaced",
]
