"""
Sandboxed AI agent loop.

Per iteration:
  1. Check kill switch (global + agent-type)
  2. Check token budget
  3. Call Azure OpenAI (via private endpoint, Managed Identity auth)
  4. Parse tool calls from model response
  5. For each tool call:
     a. Check capability manifest (is this tool allowed?)
     b. OPA policy check (authorize the specific call)
     c. If REQUIRES_APPROVAL → post to Logic App webhook, await callback
     d. Execute tool in sandbox
     e. Audit log result
  6. Continue until done signal, token budget exhausted, or time limit
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
from typing import Any
from urllib.parse import urlparse

import httpx
<<<<<<< HEAD
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import AzureOpenAI

from anomaly import RunStats, get_default_scorer
from audit import AuditLogger
from capability_manifest import get_capabilities, is_egress_allowed, is_tool_allowed
from errors import (
    AnomalyHaltError,
    CostBudgetExceededError,
    LoopDetectedError,
    PromptInjectionError,
)
from kill_switch import KillSwitchClient, KillSwitchError
from loop_detection import LoopDetector
from models.audit_event import ActionType, Outcome, PolicyDecision
from models.requests import AgentRunRequest
from policy import ApprovalRequiredError, OPAClient, PolicyDenyError
from prompt_shield import PromptShieldClient
from rate_limiter import CostBudget, TokenBudget
from sandbox import EphemeralWorkspace
from tool_schema import ToolArgumentError, validate_tool_arguments
=======
from audit import AuditLogger
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from capability_manifest import get_capabilities, is_egress_allowed, is_tool_allowed
from kill_switch import KillSwitchClient, KillSwitchError
from models.audit_event import ActionType, Outcome, PolicyDecision
from models.requests import AgentRunRequest
from openai import AzureOpenAI
from policy import ApprovalRequiredError, OPAClient, PolicyDenyError
from rate_limiter import TokenBudget
from sandbox import EphemeralWorkspace
>>>>>>> origin/main

logger = logging.getLogger(__name__)

AZURE_OPENAI_ENDPOINT = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
APPROVAL_LOGIC_APP_URL = os.environ.get("APPROVAL_LOGIC_APP_URL", "")

<<<<<<< HEAD
# Phase 1 — shared Prompt Shields client for retrieved-content rescans.
# A no-op when CONTENT_SAFETY_ENDPOINT is unset (offline / unit tests).
_prompt_shield: PromptShieldClient = PromptShieldClient()
# Minimum tool-result size to bother sending to Prompt Shields.
_RESCAN_MIN_CHARS = int(os.environ.get("PROMPT_SHIELD_RESCAN_MIN_CHARS", "256"))
# Maximum tool-result size we forward to the scanner per call.
_RESCAN_MAX_CHARS = int(os.environ.get("PROMPT_SHIELD_RESCAN_MAX_CHARS", "16000"))
_INJECTION_STUB = (
    "[REDACTED: tool result removed because Prompt Shields detected an "
    "indirect prompt-injection attempt in the retrieved content.]"
)

=======
>>>>>>> origin/main
# Approval callback: run_id -> pending approval state.
_pending_approvals: dict[str, dict[str, Any]] = {}


def _classify_text_label(text: str) -> str:
    lowered = text.lower()
<<<<<<< HEAD
    if any(
        token in lowered
        for token in ["ssn", "accountkey=", "secret", "token", "password"]
    ):
=======
    if any(token in lowered for token in ["ssn", "accountkey=", "secret", "token", "password"]):
>>>>>>> origin/main
        return "restricted"
    if any(token in lowered for token in ["confidential", "private", "internal only"]):
        return "confidential"
    if any(token in lowered for token in ["public", "published", "marketing"]):
        return "public"
    return "internal"


def register_approval_future(run_id: str, callback_token: str) -> asyncio.Future:
    loop = asyncio.get_event_loop()
    fut: asyncio.Future = loop.create_future()
    _pending_approvals[run_id] = {
        "future": fut,
        "callback_token": callback_token,
    }
    return fut


def build_callback_token(run_id: str) -> str:
    return hmac.new(
        key=run_id.encode("utf-8"),
        msg=os.urandom(32),
        digestmod="sha256",
    ).hexdigest()


def resolve_approval(run_id: str, approved: bool, callback_token: str) -> bool:
    """Called by the Logic App callback endpoint."""
    pending = _pending_approvals.get(run_id)
    if not pending:
        return False

    expected_token = pending["callback_token"]
    if not hmac.compare_digest(expected_token, callback_token):
        return False

    fut = pending["future"]
    _pending_approvals.pop(run_id, None)
    if fut and not fut.done():
        fut.set_result(approved)
        return True
    return False


async def _request_human_approval(
    run_id: str,
    agent_type: str,
    action_type: str,
    action_details: dict,
    risk_score: float,
    correlation_id: str,
    callback_token: str,
    auditor: AuditLogger,
) -> bool:
    """
    Post an approval request to the Logic App and await the callback.
    Returns True if approved, False if rejected or timed out (24h).
    """
    if not APPROVAL_LOGIC_APP_URL:
        logger.warning(
            "No APPROVAL_LOGIC_APP_URL configured; auto-denying approval request"
        )
        return False

    auditor.log(
        ActionType.APPROVAL_REQUEST,
        policy_decision=PolicyDecision.REQUIRES_APPROVAL,
        outcome=Outcome.SUCCESS,
        risk_score=risk_score,
    )

    payload = {
        "run_id": run_id,
        "agent_type": agent_type,
        "action_type": action_type,
        "action_details": action_details,
        "risk_score": risk_score,
        "correlation_id": correlation_id,
        "callback_token": callback_token,
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(APPROVAL_LOGIC_APP_URL, json=payload)
    except Exception as exc:
        logger.error("Failed to post approval request to Logic App: %s", exc)
        return False

    fut = register_approval_future(run_id, callback_token)
    try:
        approved = await asyncio.wait_for(fut, timeout=86400)  # 24 hour timeout
    except asyncio.TimeoutError:
        logger.warning("Approval timed out for run %s — auto-denying", run_id)
        approved = False
    finally:
        _pending_approvals.pop(run_id, None)

    auditor.log(
        ActionType.APPROVAL_RESPONSE,
        policy_decision=PolicyDecision.ALLOW if approved else PolicyDecision.DENY,
        outcome=Outcome.SUCCESS if approved else Outcome.BLOCKED,
    )
    return approved


async def run_agent(
    request: AgentRunRequest,
    workspace: EphemeralWorkspace,
) -> dict[str, Any]:
    """
    Main agent loop. Returns result dict on completion.
    Raises on unrecoverable error.
    """
    run_id = request.correlation_id
    agent_type = request.agent_type.value

    auditor = workspace._auditor
    opa = OPAClient(auditor=auditor, run_id=run_id, agent_type=agent_type)
    kill_switch = KillSwitchClient()

    caps = get_capabilities(agent_type)
    token_budget = TokenBudget(max_tokens=caps.max_tokens_per_run)
<<<<<<< HEAD
    # Phase 7 — per-run cost ceiling + loop detector.
    cost_budget = CostBudget(max_usd=caps.cost_budget_usd)
    loop_detector = LoopDetector(max_depth=caps.max_loop_depth)

    # Phase 4 — per-run anomaly accumulator + scorer (process-wide baseline).
    run_stats = RunStats()
    anomaly_scorer = get_default_scorer()
=======
>>>>>>> origin/main

    # Azure OpenAI client — Managed Identity auth (no API key)
    credential = DefaultAzureCredential()
    token_provider = get_bearer_token_provider(
        credential, "https://cognitiveservices.azure.com/.default"
    )
    openai_client = AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        azure_ad_token_provider=token_provider,
        api_version="2024-02-01",
    )

    messages = [
        {
            "role": "system",
            "content": (
                f"You are a {agent_type} agent operating inside a secure sandbox. "
                f"You have access to these tools only: {caps.allowed_tools}. "
                f"Remaining token budget: {token_budget.remaining}. "
                "Do not attempt to access paths, URLs, or capabilities not explicitly "
                "listed."
            ),
        },
        {"role": "user", "content": request.task},
    ]

    deadline = time.monotonic() + caps.max_run_duration_seconds
    result: dict[str, Any] = {}

    while time.monotonic() < deadline:
        # Step 1: kill switch check before every iteration
        try:
            kill_switch.check(agent_type=agent_type)
        except KillSwitchError as exc:
            auditor.log(
                ActionType.KILL_SWITCH_CHECK,
                outcome=Outcome.BLOCKED,
                error_code=exc.flag_name,
            )
            raise RuntimeError(f"Agent killed by flag: {exc.flag_name}")

        # Step 2: call OpenAI
        try:
            opa.authorize("openai_call")
        except PolicyDenyError as exc:
            raise RuntimeError(f"OpenAI call denied by policy: {exc.reason}")

        try:
            completion_limit = min(4096, token_budget.remaining)
            completion_kwargs = {
                "model": OPENAI_MODEL,
                "messages": messages,
                "tools": _build_tool_definitions(caps.allowed_tools),
                "tool_choice": "auto",
            }
            if OPENAI_MODEL.startswith("gpt-5"):
                completion_kwargs["max_completion_tokens"] = completion_limit
            else:
                completion_kwargs["max_tokens"] = completion_limit

            response = openai_client.chat.completions.create(**completion_kwargs)
        except Exception as exc:
            auditor.log(
                ActionType.OPENAI_CALL,
                outcome=Outcome.FAILURE,
                error_code=str(exc),
            )
            raise

        usage = response.usage
        if usage:
            token_budget.consume(usage.total_tokens)
<<<<<<< HEAD
            # Phase 7 — track cumulative USD spend; fail closed on overrun.
            try:
                total_usd = cost_budget.consume(
                    model_name=OPENAI_MODEL,
                    prompt_tokens=usage.prompt_tokens or 0,
                    completion_tokens=usage.completion_tokens or 0,
                )
            except CostBudgetExceededError as exc:
                auditor.log(
                    ActionType.COST_THRESHOLD_BREACH,
                    policy_decision=PolicyDecision.DENY,
                    outcome=Outcome.BLOCKED,
                    token_count=usage.total_tokens,
                    estimated_cost_usd=exc.estimated_cost_usd,
                    error_code="COST_BUDGET_EXCEEDED",
                    risk_score=0.85,
                )
                raise
=======
>>>>>>> origin/main
            auditor.log(
                ActionType.OPENAI_CALL,
                policy_decision=PolicyDecision.ALLOW,
                token_count=usage.total_tokens,
<<<<<<< HEAD
                estimated_cost_usd=total_usd,
                outcome=Outcome.SUCCESS,
            )
            run_stats.observe_event(tokens=usage.total_tokens)
=======
                outcome=Outcome.SUCCESS,
            )
>>>>>>> origin/main

        choice = response.choices[0]

        # No tool calls → agent is done
        if not choice.message.tool_calls:
            result = {
                "output": choice.message.content,
                "tokens_used": (caps.max_tokens_per_run - token_budget.remaining),
            }
            break

        messages.append(
            {
                "role": "assistant",
                "content": choice.message.content,
                "tool_calls": choice.message.tool_calls,
            }
        )

        # Step 4-5: process each tool call
        for tool_call in choice.message.tool_calls:
            tool_name = tool_call.function.name
            tool_args = json.loads(tool_call.function.arguments or "{}")

<<<<<<< HEAD
            # Phase 7 — validate arguments against the declared JSON schema
            # before any execution. Catches hallucinated paths, oversized
            # strings, and type confusion.
            schema = _tool_parameters_schema(tool_name)
            if schema is not None:
                try:
                    validate_tool_arguments(tool_args, schema)
                except ToolArgumentError as exc:
                    auditor.log(
                        ActionType.POLICY_CHECK,
                        policy_decision=PolicyDecision.DENY,
                        outcome=Outcome.BLOCKED,
                        error_code=f"tool_arg_schema:{tool_name}:{exc}",
                        risk_score=0.4,
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": json.dumps(
                                {"error": f"Invalid arguments: {exc}"}
                            ),
                        }
                    )
                    continue

            # Phase 7 — loop detection: same (tool, args) ≥ max_loop_depth in window.
            try:
                loop_detector.observe(tool_name, tool_args)
            except LoopDetectedError as exc:
                auditor.log(
                    ActionType.LOOP_DETECTED,
                    policy_decision=PolicyDecision.DENY,
                    outcome=Outcome.BLOCKED,
                    error_code=f"LOOP_DETECTED:{tool_name}",
                    risk_score=0.8,
                )
                raise exc

            denied = False
            try:
                tool_result = await _execute_tool(
                    tool_name=tool_name,
                    tool_args=tool_args,
                    run_id=run_id,
                    agent_type=agent_type,
                    workspace=workspace,
                    opa=opa,
                    kill_switch=kill_switch,
                    auditor=auditor,
                    caps=caps,
                    correlation_id=request.correlation_id,
                )
            except (PolicyDenyError, ApprovalRequiredError):
                denied = True
                raise
            finally:
                # Always observe the tool call — denied calls are signal too
                # (and weight heavily in the denial-rate feature).
                run_stats.observe_event(tool_name=tool_name, denied=denied)
                # Live anomaly scoring. Halt path raises a domain error
                # that the orchestrator surfaces as a policy-style stop.
                decision = anomaly_scorer.score_run(agent_type, run_stats)
                auditor.log(
                    ActionType.ANOMALY_ML_SCORE,
                    policy_decision=(
                        PolicyDecision.DENY if decision.halted else PolicyDecision.ALLOW
                    ),
                    outcome=Outcome.BLOCKED if decision.halted else Outcome.SUCCESS,
                    anomaly_score=decision.score,
                    risk_score=decision.score,
                    error_code=(
                        f"ANOMALY_HALT:{tool_name}" if decision.halted
                        else f"anomaly_observed:{tool_name}"
                    ),
                )
                if decision.halted:
                    raise AnomalyHaltError(
                        f"Run halted by anomaly scorer (score={decision.score:.3f}, "
                        f"halt_threshold={anomaly_scorer._halt:.2f})",
                        anomaly_score=decision.score,
                    )
=======
            tool_result = await _execute_tool(
                tool_name=tool_name,
                tool_args=tool_args,
                run_id=run_id,
                agent_type=agent_type,
                workspace=workspace,
                opa=opa,
                kill_switch=kill_switch,
                auditor=auditor,
                caps=caps,
                correlation_id=request.correlation_id,
            )
>>>>>>> origin/main

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(tool_result),
                }
            )

<<<<<<< HEAD
    # Phase 4 — commit completed-run feature vector to the baseline.
    try:
        anomaly_scorer.commit_run(agent_type, run_stats)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to commit anomaly baseline: %s", exc)

    return result


async def _rescan_retrieved_content(
    *,
    text: str,
    source: str,
    run_id: str,
    agent_type: str,
    auditor: AuditLogger,
) -> str:
    """Phase 1 — indirect prompt-injection rescan on tool-returned content.

    Returns either the original text (clean) or a small ``[REDACTED]`` stub
    that replaces the tool result before it is appended to the model's
    message history. Fail-closed: a :class:`PromptInjectionError` from the
    shield (e.g. transport failure in ``block`` mode) collapses to the stub
    and logs a ``RETRIEVED_CONTENT_SCAN`` audit event with deny outcome.
    """
    if not text or len(text) < _RESCAN_MIN_CHARS:
        return text
    payload = text[:_RESCAN_MAX_CHARS]
    try:
        decision = await _prompt_shield.scan_document(payload, source=source)
    except PromptInjectionError as exc:
        auditor.log(
            ActionType.RETRIEVED_CONTENT_SCAN,
            policy_decision=PolicyDecision.DENY,
            outcome=Outcome.BLOCKED,
            injection_score=exc.score,
            content_safety_category=",".join(exc.categories) or "prompt_injection",
            risk_score=exc.score,
            tool_namespace=f"local://{agent_type}/{source}",
            error_code=f"retrieved_content_blocked:{source}",
        )
        return _INJECTION_STUB

    auditor.log(
        ActionType.RETRIEVED_CONTENT_SCAN,
        policy_decision=(
            PolicyDecision.DENY if decision.attack_detected else PolicyDecision.ALLOW
        ),
        outcome=Outcome.BLOCKED if decision.attack_detected else Outcome.SUCCESS,
        injection_score=decision.score,
        content_safety_category=",".join(decision.categories) or None,
        risk_score=decision.score,
        tool_namespace=f"local://{agent_type}/{source}",
        error_code=f"retrieved_content_scan:{source}",
    )
    if decision.attack_detected:
        return _INJECTION_STUB
    return text


=======
    return result


>>>>>>> origin/main
async def _execute_tool(
    tool_name: str,
    tool_args: dict,
    run_id: str,
    agent_type: str,
    workspace: EphemeralWorkspace,
    opa: OPAClient,
    kill_switch: KillSwitchClient,
    auditor: AuditLogger,
    caps,
    correlation_id: str,
) -> dict:
    """Gate every tool call through capability manifest + OPA, then execute."""

    # Capability manifest check
    if not is_tool_allowed(agent_type, tool_name):
        auditor.log(
            ActionType.POLICY_CHECK,
            policy_decision=PolicyDecision.DENY,
            outcome=Outcome.BLOCKED,
            error_code=f"tool_not_in_manifest:{tool_name}",
        )
        return {
            "error": (f"Tool '{tool_name}' not allowed for agent type '{agent_type}'")
        }

    # Kill switch check for this action type
    try:
        kill_switch.check(agent_type=agent_type, action_type=tool_name)
    except KillSwitchError as exc:
        auditor.log(
            ActionType.KILL_SWITCH_CHECK,
            outcome=Outcome.BLOCKED,
            error_code=exc.flag_name,
        )
        return {"error": f"Action blocked by kill switch: {exc.flag_name}"}

    # OPA authorization
    path = tool_args.get("path")
    destination = tool_args.get("url")
    if destination:
        parsed = urlparse(destination)
        destination = parsed.netloc  # extract FQDN for policy check

    try:
        opa.authorize(tool_name, path=path, destination=destination)
    except PolicyDenyError as exc:
        return {"error": f"Policy denied: {exc.reason}"}
    except ApprovalRequiredError:
        callback_token = build_callback_token(run_id)
        approved = await _request_human_approval(
            run_id=run_id,
            agent_type=agent_type,
            action_type=tool_name,
            action_details=tool_args,
            risk_score=0.8,
            correlation_id=correlation_id,
            callback_token=callback_token,
            auditor=auditor,
        )
        if not approved:
            return {"error": "Action rejected by human approver"}

    # Execute
    try:
        if tool_name == "file_write":
            content = tool_args.get("content", "").encode()
            vpath = workspace.write_file(
                tool_args["path"], content, tool_args.get("content_type", "text/plain")
            )
            return {"written_to": vpath}

        elif tool_name == "file_read":
            content = workspace.read_file(tool_args["path"])
<<<<<<< HEAD
            decoded = content.decode(errors="replace")
            decoded = await _rescan_retrieved_content(
                text=decoded,
                source="file_read",
                run_id=run_id,
                agent_type=agent_type,
                auditor=auditor,
            )
            return {"content": decoded}
=======
            return {"content": content.decode(errors="replace")}
>>>>>>> origin/main

        elif tool_name == "http_get":
            url = tool_args.get("url", "")
            parsed = urlparse(url)
            if not is_egress_allowed(agent_type, parsed.netloc):
                return {"error": f"FQDN not in egress allowlist: {parsed.netloc}"}
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url)
<<<<<<< HEAD
            body = resp.text[:4096]
            classification_label = _classify_text_label(body)
=======
            classification_label = _classify_text_label(resp.text[:4096])
>>>>>>> origin/main
            auditor.log(
                ActionType.NETWORK_CALL,
                policy_decision=PolicyDecision.ALLOW,
                destination=parsed.netloc,
                classification_label=classification_label,
                outcome=Outcome.SUCCESS,
            )
<<<<<<< HEAD
            body = await _rescan_retrieved_content(
                text=body,
                source="http_get",
                run_id=run_id,
                agent_type=agent_type,
                auditor=auditor,
            )
            return {"status_code": resp.status_code, "body": body}
=======
            return {"status_code": resp.status_code, "body": resp.text[:4096]}
>>>>>>> origin/main

        else:
            return {"error": f"Unimplemented tool: {tool_name}"}

    except Exception as exc:
        auditor.log(
            getattr(ActionType, tool_name.upper(), ActionType.POLICY_CHECK),
            outcome=Outcome.FAILURE,
            error_code=str(exc),
            classification_label="internal",
        )
        return {"error": str(exc)}


def _build_tool_definitions(allowed_tools: list[str]) -> list[dict]:
    """Build OpenAI-format tool definitions for the allowed tool set."""
    definitions = {
        "file_write": {
            "type": "function",
            "function": {
                "name": "file_write",
                "description": "Write content to a file in the sandbox workspace",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": (
                                "Virtual path like /workspace/{run_id}/write/output.txt"
                            ),
                        },
                        "content": {
                            "type": "string",
                            "description": "File content to write",
                        },
                        "content_type": {
                            "type": "string",
                            "enum": [
                                "text/plain",
                                "application/json",
                                "text/csv",
                                "text/markdown",
                            ],
                        },
                    },
                    "required": ["path", "content"],
                },
            },
        },
        "file_read": {
            "type": "function",
            "function": {
                "name": "file_read",
                "description": (
                    "Read a previously written file from the sandbox workspace"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Virtual path to read",
                        },
                    },
                    "required": ["path"],
                },
            },
        },
        "http_get": {
            "type": "function",
            "function": {
                "name": "http_get",
                "description": "Fetch content from an approved external URL",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Full URL to fetch"},
                    },
                    "required": ["url"],
                },
            },
        },
    }
    return [v for k, v in definitions.items() if k in allowed_tools]
<<<<<<< HEAD


# Phase 7 — lookup of the inner JSON schema for argument validation.
def _tool_parameters_schema(tool_name: str) -> dict | None:
    """Return the JSON-schema ``parameters`` block for *tool_name*, or
    ``None`` if the tool is not defined (e.g. an MCP-namespaced tool which
    carries its own schema)."""
    for entry in _build_tool_definitions([tool_name]):
        function = entry.get("function") or {}
        params = function.get("parameters")
        if isinstance(params, dict):
            return params
    return None
=======
>>>>>>> origin/main
