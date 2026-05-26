"""
Phase 6 — MCP server (orchestrator-exposed).

Exposes the orchestrator's per-agent-type tool catalog as **Model Context
Protocol** tools over JSON-RPC 2.0 (the transport spec used by the modern
streamable-HTTP MCP profile).

Why JSON-RPC directly instead of the official ``mcp`` SDK?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The SDK is fine but ships its own transport plumbing that does not compose
cleanly with FastAPI middleware. We need every MCP call to traverse:

    APIM signed envelope → KillSwitchMiddleware → admin gate →
    capability manifest → kill switch → OPA → sandbox.

A 100-line JSON-RPC dispatcher avoids two transport layers fighting each
other. The on-the-wire shape stays MCP-compatible (``initialize``,
``tools/list``, ``tools/call``) so an upstream MCP client can speak to us
without changes.

Security pipeline
~~~~~~~~~~~~~~~~~
- ``tools/list`` returns only tools in the calling agent type's capability
  manifest. Tool URIs are namespaced ``mcp://orchestrator/{agent_type}/{tool}``
  so downstream audit events carry provenance.
- ``tools/call`` invokes a caller-supplied executor (the orchestrator wires
  it to :func:`agent._execute_tool`) which itself goes through OPA +
  sandbox. The MCP layer is **not** a bypass.
- Every RPC emits an audit event (``MCP_TOOL_DISCOVERY`` for ``tools/list``,
  ``MCP_TOOL_CALL`` for ``tools/call``).
- Unknown methods return JSON-RPC ``-32601`` (method not found); malformed
  envelopes return ``-32600``. Internal errors return ``-32603`` and the
  underlying exception text is **not** included in the response body to
  avoid leaking sandbox internals.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from capability_manifest import get_capabilities
from models.audit_event import ActionType, Outcome, PolicyDecision

logger = logging.getLogger(__name__)

# JSON-RPC error codes (per spec).
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# MCP-specific codes (we reuse the server-defined range -32000..-32099).
POLICY_DENIED = -32001
CAPABILITY_DENIED = -32002

MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_SERVER_NAME = "ai-security-sandbox-orchestrator"
MCP_SERVER_VERSION = "1.0.0"


ToolExecutor = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]
ToolDefinitionsProvider = Callable[[list[str]], list[dict[str, Any]]]


def _namespaced_uri(agent_type: str, tool_name: str) -> str:
    return f"mcp://orchestrator/{agent_type}/{tool_name}"


def _to_mcp_tool(agent_type: str, openai_tool: dict[str, Any]) -> dict[str, Any]:
    """Convert an OpenAI-format tool definition into an MCP tool descriptor."""
    fn = openai_tool.get("function", {})
    name = fn.get("name", "")
    return {
        "name": name,
        "uri": _namespaced_uri(agent_type, name),
        "description": fn.get("description", ""),
        "inputSchema": fn.get("parameters", {"type": "object", "properties": {}}),
    }


class MCPServer:
    """JSON-RPC 2.0 dispatcher for the orchestrator's MCP endpoint."""

    def __init__(
        self,
        *,
        tool_definitions: ToolDefinitionsProvider,
    ) -> None:
        self._tool_definitions = tool_definitions

    # ── public discovery helper (also used by REST /mcp/tools) ────────────
    def list_tools(self, agent_type: str) -> list[dict[str, Any]]:
        try:
            caps = get_capabilities(agent_type)
        except ValueError:
            return []
        openai_defs = self._tool_definitions(caps.allowed_tools)
        return [_to_mcp_tool(agent_type, d) for d in openai_defs]

    # ── JSON-RPC entrypoint ───────────────────────────────────────────────
    async def handle_rpc(
        self,
        envelope: Any,
        *,
        agent_type: str,
        executor: ToolExecutor | None = None,
        auditor: Any | None = None,
    ) -> dict[str, Any]:
        """Dispatch a single JSON-RPC envelope.

        ``executor`` is required for ``tools/call`` requests; passing it per
        call lets the caller bind a request-scoped workspace + OPA + audit
        stack so each MCP invocation runs through the same security
        pipeline as an in-process agent tool call.
        """
        # Envelope validation
        if not isinstance(envelope, dict):
            return _rpc_error(None, INVALID_REQUEST, "Envelope must be a JSON object")
        if envelope.get("jsonrpc") != "2.0":
            return _rpc_error(
                envelope.get("id"), INVALID_REQUEST, "Missing jsonrpc=2.0"
            )
        method = envelope.get("method")
        if not isinstance(method, str):
            return _rpc_error(envelope.get("id"), INVALID_REQUEST, "Missing method")
        params = envelope.get("params") or {}
        if not isinstance(params, dict):
            return _rpc_error(
                envelope.get("id"), INVALID_PARAMS, "params must be object"
            )
        rpc_id = envelope.get("id")

        try:
            if method == "initialize":
                return _rpc_ok(rpc_id, self._initialize())
            if method == "tools/list":
                tools = self.list_tools(agent_type)
                self._audit(
                    auditor,
                    ActionType.MCP_TOOL_DISCOVERY,
                    decision=PolicyDecision.ALLOW,
                    outcome=Outcome.SUCCESS,
                    code=f"mcp_tools_list:{agent_type}:{len(tools)}",
                )
                return _rpc_ok(rpc_id, {"tools": tools})
            if method == "tools/call":
                if executor is None:
                    return _rpc_error(
                        rpc_id,
                        INTERNAL_ERROR,
                        "tools/call requires a request-scoped executor",
                    )
                return await self._call_tool(
                    rpc_id, params, agent_type, executor, auditor
                )
            return _rpc_error(
                rpc_id, METHOD_NOT_FOUND, f"Unknown method {method!r}"
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("MCP RPC internal error")
            self._audit(
                auditor,
                ActionType.MCP_TOOL_CALL,
                decision=PolicyDecision.DENY,
                outcome=Outcome.FAILURE,
                code="mcp_internal_error",
            )
            # Do NOT leak exc text — internal details stay internal.
            _ = exc
            return _rpc_error(rpc_id, INTERNAL_ERROR, "Internal MCP error")

    # ── private helpers ───────────────────────────────────────────────────
    def _initialize(self) -> dict[str, Any]:
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "serverInfo": {"name": MCP_SERVER_NAME, "version": MCP_SERVER_VERSION},
            "capabilities": {"tools": {"listChanged": False}},
        }

    async def _call_tool(
        self,
        rpc_id: Any,
        params: dict[str, Any],
        agent_type: str,
        executor: ToolExecutor,
        auditor: Any | None,
    ) -> dict[str, Any]:
        tool_name = params.get("name")
        arguments = params.get("arguments", {}) or {}
        if not isinstance(tool_name, str) or not tool_name:
            return _rpc_error(rpc_id, INVALID_PARAMS, "Missing tool name")
        if not isinstance(arguments, dict):
            return _rpc_error(rpc_id, INVALID_PARAMS, "arguments must be object")

        # Capability-manifest pre-check. The executor will re-check inside
        # the OPA pipeline; this short-circuits with a clean MCP error code.
        try:
            caps = get_capabilities(agent_type)
        except ValueError:
            self._audit(
                auditor,
                ActionType.MCP_TOOL_CALL,
                decision=PolicyDecision.DENY,
                outcome=Outcome.BLOCKED,
                code=f"mcp_unknown_agent_type:{agent_type}",
            )
            return _rpc_error(rpc_id, CAPABILITY_DENIED, "Unknown agent type")
        if tool_name not in caps.allowed_tools:
            self._audit(
                auditor,
                ActionType.MCP_TOOL_CALL,
                decision=PolicyDecision.DENY,
                outcome=Outcome.BLOCKED,
                code=f"mcp_tool_not_in_manifest:{tool_name}",
            )
            return _rpc_error(
                rpc_id,
                CAPABILITY_DENIED,
                f"Tool '{tool_name}' not allowed for agent type",
            )

        # Hand off to the orchestrator's tool executor (OPA + sandbox).
        result = await executor(tool_name, arguments)

        # Tool may legitimately return {"error": "..."} — surface as MCP
        # policy error so the caller sees a structured failure rather than
        # silently re-ingesting an error string.
        if isinstance(result, dict) and result.get("error"):
            self._audit(
                auditor,
                ActionType.MCP_TOOL_CALL,
                decision=PolicyDecision.DENY,
                outcome=Outcome.BLOCKED,
                code=f"mcp_tool_denied:{tool_name}",
            )
            return _rpc_error(rpc_id, POLICY_DENIED, str(result["error"]))

        self._audit(
            auditor,
            ActionType.MCP_TOOL_CALL,
            decision=PolicyDecision.ALLOW,
            outcome=Outcome.SUCCESS,
            code=f"mcp_tool_ok:{tool_name}",
        )
        return _rpc_ok(
            rpc_id,
            {
                "content": [{"type": "json", "data": result}],
                "isError": False,
                "uri": _namespaced_uri(agent_type, tool_name),
            },
        )

    def _audit(
        self,
        auditor: Any | None,
        action: ActionType,
        *,
        decision: PolicyDecision,
        outcome: Outcome,
        code: str,
    ) -> None:
        if auditor is None:
            return
        try:
            auditor.log(
                action,
                policy_decision=decision,
                outcome=outcome,
                error_code=code,
            )
        except Exception:  # pragma: no cover - defensive
            logger.warning("MCP audit emission failed", exc_info=True)


# ── JSON-RPC response helpers ────────────────────────────────────────────────
def _rpc_ok(rpc_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _rpc_error(rpc_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {"code": code, "message": message},
    }


__all__ = [
    "CAPABILITY_DENIED",
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "MCP_PROTOCOL_VERSION",
    "MCP_SERVER_NAME",
    "MCP_SERVER_VERSION",
    "METHOD_NOT_FOUND",
    "MCPServer",
    "PARSE_ERROR",
    "POLICY_DENIED",
]
