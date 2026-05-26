#!/usr/bin/env python3
"""
Robust demo-data seeder for the AI Security Sandbox.

Three modes (`--mode runs|direct|both`):

  runs    Fire real /sandbox/runs through APIM using AAD tokens. Exercises the
          full production path: middleware, OPA, sandbox, audit, SSE, anomaly
          model state, WORM blob writes. Slower; bounded by APIM rate limits.

  direct  POST synthetic AuditEvent rows straight to the Log Analytics Logs
          Ingestion endpoint for the AiAgentAudit_CL DCR. Fast, ideal for
          backfilling history so the SOC workbook trend panels look real, and
          for emitting action types that have no public ingress (mcp_*,
          governance_attestation, signature_verification_failure, etc.).

  both    Direct-seed the historical baseline, then fire a small wave of real
          runs so live SSE / anomaly state is populated for the demo.

Scenarios live in scripts/seed-scenarios.json so they can be edited without
touching this script. Every seeded event carries a correlation_id with the
prefix `seed-` so the `--reset` flow can find / hide them deterministically.

Cross-platform: invoked by scripts/seed-demo-data.ps1 and
scripts/seed-demo-data.sh; can also be run directly with `python3`.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import random
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

SEED_CORRELATION_PREFIX = "seed-"
DEFAULT_SCENARIOS_PATH = Path(__file__).parent / "seed-scenarios.json"

# Match AuditEvent.to_log_analytics_row():
#   - base fields are snake_case
#   - Phase 1–7 uplift fields are camelCase
PHASE17_CAMEL_FIELDS = {
    "parent_agent_id": "parentAgentId",
    "call_chain": "callChain",
    "governance_metadata_ref": "governanceMetadataRef",
    "injection_score": "injectionScore",
    "tool_namespace": "toolNamespace",
    "confirmation_token": "confirmationToken",
    "estimated_cost_usd": "estimatedCostUsd",
    "anomaly_score": "anomalyScore",
}

# Ingestion API caps: ~1MB / 500 events per request. Stay well under.
DCE_BATCH_SIZE = 100

# Run-mode parallelism defaults
DEFAULT_PARALLEL = 5
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
MAX_RETRIES = 4
BACKOFF_BASE_S = 1.0

# ──────────────────────────────────────────────────────────────────────────────
# Logging (stdout only — no extra deps)
# ──────────────────────────────────────────────────────────────────────────────

_print_lock = threading.Lock()


def _log(level: str, msg: str) -> None:
    with _print_lock:
        print(f"[{level}] {msg}", flush=True)


def info(msg: str) -> None:
    _log("INFO ", msg)


def warn(msg: str) -> None:
    _log("WARN ", msg)


def err(msg: str) -> None:
    _log("ERROR", msg)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _resolve_az() -> str:
    """Locate the Azure CLI executable. On Windows az is installed as az.cmd
    and Python's subprocess doesn't honor PATHEXT, so plain 'az' fails."""
    for candidate in ("az", "az.cmd", "az.bat", "az.exe"):
        found = shutil.which(candidate)
        if found:
            return found
    raise RuntimeError(
        "Azure CLI ('az') not found on PATH. Install from "
        "https://aka.ms/install-azure-cli and ensure it is on PATH."
    )


_AZ_PATH: str | None = None


def az(*args: str, timeout: int = 60) -> str:
    """Run `az` and return stdout. Raises on non-zero exit."""
    global _AZ_PATH
    if _AZ_PATH is None:
        _AZ_PATH = _resolve_az()
    cmd = [_AZ_PATH, *args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        raise RuntimeError(f"Failed to invoke Azure CLI at {_AZ_PATH}: {e}") from e
    if result.returncode != 0:
        raise RuntimeError(
            f"az {' '.join(args)} failed (exit {result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()


def ensure_az_login() -> None:
    try:
        az("account", "show", "--only-show-errors")
    except RuntimeError as e:
        raise SystemExit(f"Azure CLI is not authenticated: {e}. Run `az login`.")


def acquire_apim_token(client_id: str) -> str:
    """Try a few common scope shapes for the orchestrator API audience."""
    attempts = [
        ["account", "get-access-token", "--scope", f"api://{client_id}/.default", "--query", "accessToken", "-o", "tsv"],
        ["account", "get-access-token", "--scope", f"api://{client_id}/access_as_user", "--query", "accessToken", "-o", "tsv"],
        ["account", "get-access-token", "--resource", f"api://{client_id}", "--query", "accessToken", "-o", "tsv"],
    ]
    last_err = None
    for attempt in attempts:
        try:
            tok = az(*attempt)
            if tok:
                return tok
        except RuntimeError as e:
            last_err = e
    raise SystemExit(
        f"Failed to acquire AAD token for api://{client_id}. "
        f"Run `az login --scope api://{client_id}/.default` first.\n"
        f"Last error: {last_err}"
    )


def acquire_monitor_token() -> str:
    return az(
        "account", "get-access-token",
        "--resource", "https://monitor.azure.com/",
        "--query", "accessToken", "-o", "tsv",
    )


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 30.0,
) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url=url, method=method, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body_bytes = b""
        try:
            body_bytes = e.read()
        except Exception:
            pass
        return e.code, body_bytes, dict(e.headers or {})


def http_request_with_retry(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 30.0,
    refresh_token: callable | None = None,
) -> tuple[int, bytes]:
    """Retry on 429 / 5xx with exponential backoff + jitter. On 401, optionally
    call refresh_token() once and retry. Also retries transient network errors
    (socket timeouts, connection resets, DNS hiccups)."""
    headers = dict(headers or {})
    attempt = 0
    refreshed = False
    while True:
        try:
            status, body_resp, resp_headers = http_request(
                url, method=method, headers=headers, body=body, timeout=timeout
            )
        except (TimeoutError, urllib.error.URLError, OSError) as net_err:
            if attempt < MAX_RETRIES:
                wait = BACKOFF_BASE_S * (2 ** attempt)
                wait += random.uniform(0, 0.25 * wait)
                warn(f"  Network error on {method} {url}: {net_err}; retry {attempt + 1}/{MAX_RETRIES} in {wait:.1f}s")
                time.sleep(wait)
                attempt += 1
                continue
            raise
        if status == 401 and refresh_token and not refreshed:
            tok = refresh_token()
            headers["Authorization"] = f"Bearer {tok}"
            refreshed = True
            continue
        if status in RETRYABLE_STATUS and attempt < MAX_RETRIES:
            retry_after = resp_headers.get("Retry-After")
            try:
                wait = float(retry_after) if retry_after else BACKOFF_BASE_S * (2 ** attempt)
            except ValueError:
                wait = BACKOFF_BASE_S * (2 ** attempt)
            wait += random.uniform(0, 0.25 * wait)
            warn(f"  HTTP {status} on {method} {url}; retry {attempt + 1}/{MAX_RETRIES} in {wait:.1f}s")
            time.sleep(wait)
            attempt += 1
            continue
        return status, body_resp


# ──────────────────────────────────────────────────────────────────────────────
# Event generation
# ──────────────────────────────────────────────────────────────────────────────


def _resolve_numeric(value: Any, *, integer: bool = False) -> int | float:
    """Allow `[min, max]` tuples for randomization in scenario JSON."""
    if isinstance(value, list) and len(value) == 2:
        lo, hi = value
        if integer:
            return random.randint(int(lo), int(hi))
        return round(random.uniform(float(lo), float(hi)), 4)
    if integer:
        return int(value)
    return float(value)


def build_event(
    *,
    scenario_id: str,
    run_id: str,
    agent_type: str,
    template: dict[str, Any],
    defaults: dict[str, Any],
    when: datetime,
    parent_run_id: str = "",
    seed_session_id: str,
) -> dict[str, Any]:
    """Combine scenario defaults + template overrides into a DCR-shaped row."""
    merged: dict[str, Any] = {**defaults, **template}

    # Resolve randomized numeric fields.
    if "tokens" in merged:
        merged["token_count"] = _resolve_numeric(merged.pop("tokens"), integer=True)
    if "estimated_cost_usd" in merged and merged["estimated_cost_usd"] is not None:
        merged["estimated_cost_usd"] = _resolve_numeric(merged["estimated_cost_usd"])
    if "anomaly_score" in merged and merged["anomaly_score"] is not None:
        merged["anomaly_score"] = _resolve_numeric(merged["anomaly_score"])
    if "injection_score" in merged and merged["injection_score"] is not None:
        merged["injection_score"] = _resolve_numeric(merged["injection_score"])
    if "grounding_score" in merged and merged["grounding_score"] is not None:
        merged["grounding_score"] = _resolve_numeric(merged["grounding_score"])
    if "risk_score" in merged and merged["risk_score"] is not None:
        merged["risk_score"] = _resolve_numeric(merged["risk_score"])

    # call_chain can be provided as a comma-separated string or list.
    call_chain = merged.get("call_chain", "")
    if isinstance(call_chain, list):
        call_chain = ",".join(call_chain)

    dlp_patterns = merged.get("dlp_patterns", "")
    if isinstance(dlp_patterns, list):
        dlp_patterns = ",".join(dlp_patterns)

    row: dict[str, Any] = {
        "TimeGenerated": when.astimezone(timezone.utc).isoformat(),
        "event_id": str(uuid.uuid4()),
        "run_id": run_id,
        "agent_type": agent_type,
        "action_type": merged["action_type"],
        "policy_decision": merged.get("policy_decision", "allow"),
        "path": merged.get("path", "") or "",
        "destination": merged.get("destination", "") or "",
        "content_hash": merged.get("content_hash", "") or "",
        "token_count": int(merged.get("token_count", 0) or 0),
        "risk_score": float(merged.get("risk_score", 0.0) or 0.0),
        "outcome": merged.get("outcome", "success"),
        "error_code": merged.get("error_code", "") or "",
        "classification_label": merged.get("classification_label", "") or "",
        "dlp_patterns": dlp_patterns or "",
        "content_safety_category": merged.get("content_safety_category", "") or "",
        "grounding_score": float(merged.get("grounding_score", 0.0) or 0.0),
        "data_processing_basis": merged.get("data_processing_basis", "security_monitoring"),
        "consent_status": merged.get("consent_status", "not_required"),
        "parent_run_id": parent_run_id or "",
        "correlation_id": f"{SEED_CORRELATION_PREFIX}{seed_session_id}-{scenario_id}-{uuid.uuid4().hex[:8]}",
        # Phase 1–7 uplift fields — camelCase to match to_log_analytics_row().
        "parentAgentId": merged.get("parent_agent_id", "") or "",
        "callChain": call_chain or "",
        "governanceMetadataRef": merged.get("governance_metadata_ref", "") or "",
        "injectionScore": float(merged.get("injection_score", 0.0) or 0.0),
        "toolNamespace": merged.get("tool_namespace", "") or "",
        "confirmationToken": merged.get("confirmation_token", "") or "",
        "estimatedCostUsd": float(merged.get("estimated_cost_usd", 0.0) or 0.0),
        "anomalyScore": float(merged.get("anomaly_score", 0.0) or 0.0),
    }
    return row


def expand_scenario_events(
    scenario: dict[str, Any],
    *,
    defaults: dict[str, Any],
    when: datetime,
    seed_session_id: str,
    inter_event_seconds: float = 1.5,
) -> list[dict[str, Any]]:
    """Expand a single scenario into ordered DCR rows."""
    run_id = str(uuid.uuid4())
    agent_type = scenario.get("agent_type", "data-analyst")
    scenario_id = scenario["id"]
    events = []
    for idx, tpl in enumerate(scenario.get("direct_events", [])):
        ts = when + timedelta(seconds=idx * inter_event_seconds)
        events.append(
            build_event(
                scenario_id=scenario_id,
                run_id=run_id,
                agent_type=agent_type,
                template=tpl,
                defaults=defaults,
                when=ts,
                seed_session_id=seed_session_id,
            )
        )
    return events


def weighted_scenario_pool(scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expand a scenario list by its `weight` field (default 1)."""
    pool: list[dict[str, Any]] = []
    for s in scenarios:
        weight = max(1, int(s.get("weight", 1)))
        pool.extend([s] * weight)
    return pool


def sample_backfill_timestamp(
    *,
    backfill_hours: float,
    bias_recent: float = 0.6,
) -> datetime:
    """Sample a UTC timestamp in the past `backfill_hours` window with optional
    recency bias (`bias_recent` in [0,1] — higher = more samples close to now)."""
    now = datetime.now(timezone.utc)
    # Exponential-ish: u^bias maps uniform [0,1] toward 0 (≈ now) when bias>1
    bias = max(0.1, 1.0 - bias_recent + 0.1)
    u = random.random() ** (1.0 / bias)
    offset_seconds = u * backfill_hours * 3600.0
    return now - timedelta(seconds=offset_seconds)


# ──────────────────────────────────────────────────────────────────────────────
# Direct (DCE) sender
# ──────────────────────────────────────────────────────────────────────────────


def post_events_direct(
    *,
    dce_logs: str,
    dcr_immutable_id: str,
    stream: str,
    events: list[dict[str, Any]],
    dry_run: bool = False,
) -> None:
    if not events:
        info("Direct mode: no events to send.")
        return
    if dry_run:
        info(f"Direct mode DRY RUN: would post {len(events)} events to {dce_logs} stream={stream}")
        return

    token = acquire_monitor_token()
    url = f"{dce_logs}/dataCollectionRules/{dcr_immutable_id}/streams/{stream}?api-version=2023-01-01"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Sort by TimeGenerated so the workbook trend lines look natural even when
    # we backfilled across hours.
    events.sort(key=lambda e: e["TimeGenerated"])

    total = len(events)
    info(f"Direct mode: posting {total} events to DCE in batches of {DCE_BATCH_SIZE}")
    for i in range(0, total, DCE_BATCH_SIZE):
        chunk = events[i : i + DCE_BATCH_SIZE]
        body = json.dumps(chunk).encode("utf-8")
        status, body_resp = http_request_with_retry(
            url, method="POST", headers=dict(headers), body=body, timeout=120.0,
            refresh_token=lambda: acquire_monitor_token(),
        )
        if 200 <= status < 300:
            info(f"  Posted batch {i}..{i + len(chunk) - 1} ({len(chunk)} events) → HTTP {status}")
        else:
            err(f"  Batch {i} failed: HTTP {status}: {body_resp[:300].decode('utf-8', errors='replace')}")
            raise SystemExit(2)


# ──────────────────────────────────────────────────────────────────────────────
# Runs (APIM) sender
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class RunRequest:
    label: str
    agent_type: str
    task: str
    upload_path: Path | None = None


@dataclass
class RunResult:
    label: str
    status: int
    run_id: str | None
    error: str | None = None


def post_run_via_apim(
    *,
    sandbox_url: str,
    headers: dict[str, str],
    req: RunRequest,
    refresh_token: callable,
) -> RunResult:
    url = f"{sandbox_url}/runs"
    if req.upload_path is not None:
        # multipart/form-data with task + file
        boundary = f"----seedboundary{uuid.uuid4().hex}"
        body_parts: list[bytes] = []
        def add(part: str) -> None:
            body_parts.append(part.encode("utf-8"))

        add(f"--{boundary}\r\n")
        add('Content-Disposition: form-data; name="agent_type"\r\n\r\n')
        add(f"{req.agent_type}\r\n")
        add(f"--{boundary}\r\n")
        add('Content-Disposition: form-data; name="task"\r\n\r\n')
        add(f"{req.task}\r\n")
        add(f"--{boundary}\r\n")
        filename = req.upload_path.name
        add(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n')
        add("Content-Type: application/octet-stream\r\n\r\n")
        body_parts.append(req.upload_path.read_bytes())
        add(f"\r\n--{boundary}--\r\n")
        body = b"".join(body_parts)
        req_headers = dict(headers)
        req_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    else:
        body = json.dumps({"agent_type": req.agent_type, "task": req.task}).encode("utf-8")
        req_headers = dict(headers)
        req_headers["Content-Type"] = "application/json"

    status, body_resp = http_request_with_retry(
        url, method="POST", headers=req_headers, body=body, timeout=45.0,
        refresh_token=refresh_token,
    )
    if 200 <= status < 300:
        try:
            payload = json.loads(body_resp.decode("utf-8"))
            return RunResult(label=req.label, status=status, run_id=payload.get("run_id"))
        except Exception as e:
            return RunResult(label=req.label, status=status, run_id=None, error=f"json parse: {e}")
    return RunResult(
        label=req.label, status=status, run_id=None,
        error=body_resp[:300].decode("utf-8", errors="replace"),
    )


def run_requests_parallel(
    *,
    requests: list[RunRequest],
    sandbox_url: str,
    apim_subscription_key: str | None,
    client_id: str,
    parallel: int,
) -> list[RunResult]:
    token_lock = threading.Lock()
    current_token = {"value": acquire_apim_token(client_id)}

    def refresh() -> str:
        with token_lock:
            current_token["value"] = acquire_apim_token(client_id)
            return current_token["value"]

    def base_headers() -> dict[str, str]:
        h = {"Authorization": f"Bearer {current_token['value']}"}
        if apim_subscription_key:
            h["Ocp-Apim-Subscription-Key"] = apim_subscription_key
        h["X-Seed-Session"] = SEED_CORRELATION_PREFIX + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        return h

    results: list[RunResult] = []
    info(f"Runs mode: dispatching {len(requests)} runs with parallel={parallel}")
    with cf.ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = [
            pool.submit(
                post_run_via_apim,
                sandbox_url=sandbox_url,
                headers=base_headers(),
                req=r,
                refresh_token=refresh,
            )
            for r in requests
        ]
        for fut in cf.as_completed(futures):
            res = fut.result()
            results.append(res)
            if res.error:
                warn(f"  [{res.label:<28}] HTTP {res.status} {res.error}")
            else:
                info(f"  [{res.label:<28}] HTTP {res.status} run_id={res.run_id}")
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Reset
# ──────────────────────────────────────────────────────────────────────────────


def reset_hint() -> None:
    """The DCR has no delete-by-query API; KQL purge is async + restricted.
    Print the operator-facing KQL filter and suggested purge command so the
    user can hide or remove the previously-seeded rows."""
    info("Reset hint (Log Analytics has no synchronous row delete):")
    info("  All seeded rows carry correlation_id startswith 'seed-'. To hide them:")
    info("    AiAgentAudit_CL | where correlation_id !startswith 'seed-'")
    info("  To purge (admin-only, async, can take >12h):")
    info("    az monitor log-analytics workspace purge create \\")
    info("      --workspace-id <law-id> --table AiAgentAudit_CL \\")
    info("      --filter '[{\"column\":\"correlation_id\",\"operator\":\"startswith\",\"value\":\"seed-\"}]'")
    info("  For runs-mode seeds: admin DELETE /sandbox/runs/{run_id} is available.")


# ──────────────────────────────────────────────────────────────────────────────
# Mode dispatchers
# ──────────────────────────────────────────────────────────────────────────────


def mode_direct(args, scenarios: dict[str, Any]) -> None:
    if not args.dry_run and (not args.dce_logs or not args.dcr_immutable_id):
        raise SystemExit("--mode direct|both requires --dce-logs and --dcr-immutable-id (or env DCE_LOGS / DCR_IMMUTABLE_ID).")

    defaults = scenarios.get("default_event", {})
    seed_session_id = uuid.uuid4().hex[:8]

    benign_pool = weighted_scenario_pool(scenarios["benign_runs"])
    attack_pool = weighted_scenario_pool(scenarios["attack_runs"])
    admin_pool = scenarios.get("admin_actions", [])

    events: list[dict[str, Any]] = []

    # Benign baseline: heavy mass, biased toward older history so attacks stand out.
    for _ in range(args.benign_events):
        s = random.choice(benign_pool)
        when = sample_backfill_timestamp(backfill_hours=args.backfill_hours, bias_recent=0.4)
        events.extend(expand_scenario_events(
            s, defaults=defaults, when=when, seed_session_id=seed_session_id,
        ))

    # Attacks: spread across full window with mild recency bias.
    for _ in range(args.attack_events):
        s = random.choice(attack_pool)
        when = sample_backfill_timestamp(backfill_hours=args.backfill_hours, bias_recent=0.65)
        events.extend(expand_scenario_events(
            s, defaults=defaults, when=when, seed_session_id=seed_session_id,
        ))

    # Admin actions: a small handful sprinkled in.
    admin_count = max(1, args.attack_events // 5)
    for _ in range(admin_count):
        s = random.choice(admin_pool) if admin_pool else None
        if s is None:
            break
        when = sample_backfill_timestamp(backfill_hours=args.backfill_hours, bias_recent=0.55)
        events.extend(expand_scenario_events(
            s, defaults=defaults, when=when, seed_session_id=seed_session_id,
        ))

    info(
        f"Direct mode plan: {args.benign_events} benign scenarios, "
        f"{args.attack_events} attack scenarios, {admin_count} admin actions "
        f"-> {len(events)} total events across last {args.backfill_hours:g}h "
        f"(session {seed_session_id})"
    )

    post_events_direct(
        dce_logs=args.dce_logs,
        dcr_immutable_id=args.dcr_immutable_id,
        stream=args.stream,
        events=events,
        dry_run=args.dry_run,
    )


def mode_runs(args, scenarios: dict[str, Any]) -> None:
    if not args.apim_url or not args.aad_client_id:
        raise SystemExit("--mode runs|both requires --apim-url and --aad-client-id.")

    sandbox_url = args.apim_url.rstrip("/") + "/sandbox"

    benign_pool = weighted_scenario_pool(scenarios["benign_runs"])
    attack_pool = scenarios["attack_runs"]

    requests: list[RunRequest] = []
    for i in range(args.benign_runs):
        s = benign_pool[i % len(benign_pool)]
        upload = None
        # Sprinkle in occasional multipart uploads.
        if args.upload_sample and (i % 4 == 0):
            upload = args.upload_sample
        requests.append(RunRequest(
            label=f"benign-{i + 1}",
            agent_type=s["agent_type"],
            task=s["task"],
            upload_path=upload,
        ))

    for i in range(args.attack_runs):
        s = attack_pool[i % len(attack_pool)]
        requests.append(RunRequest(
            label=s["id"],
            agent_type=s["agent_type"],
            task=s["task"],
        ))

    if args.dry_run:
        info(f"Runs mode DRY RUN: would dispatch {len(requests)} runs to {sandbox_url}")
        for r in requests:
            info(f"  - [{r.label}] agent={r.agent_type} upload={r.upload_path}")
        return

    results = run_requests_parallel(
        requests=requests,
        sandbox_url=sandbox_url,
        apim_subscription_key=args.apim_subscription_key,
        client_id=args.aad_client_id,
        parallel=args.parallel,
    )
    successes = sum(1 for r in results if r.status and 200 <= r.status < 300)
    info(f"Runs mode complete: {successes}/{len(results)} runs accepted (HTTP 2xx).")


def mode_loop(args, scenarios: dict[str, Any]) -> None:
    """Trickle a small wave of direct events every N seconds for the duration."""
    if args.loop_minutes <= 0:
        return
    if not args.dce_logs or not args.dcr_immutable_id:
        warn("--loop-minutes requested but no DCE/DCR configured; skipping drip.")
        return

    deadline = time.monotonic() + args.loop_minutes * 60.0
    interval = max(5, args.loop_interval_seconds)
    info(
        f"Loop mode: streaming a small wave every {interval}s for "
        f"{args.loop_minutes} minutes (Ctrl+C to stop early)."
    )

    defaults = scenarios.get("default_event", {})
    benign_pool = weighted_scenario_pool(scenarios["benign_runs"])
    attack_pool = weighted_scenario_pool(scenarios["attack_runs"])
    seed_session_id = "loop" + uuid.uuid4().hex[:6]

    try:
        while time.monotonic() < deadline:
            wave: list[dict[str, Any]] = []
            for _ in range(args.loop_wave_size):
                s = random.choice(benign_pool if random.random() > 0.2 else attack_pool)
                when = datetime.now(timezone.utc)
                wave.extend(expand_scenario_events(
                    s, defaults=defaults, when=when, seed_session_id=seed_session_id,
                ))
            post_events_direct(
                dce_logs=args.dce_logs,
                dcr_immutable_id=args.dcr_immutable_id,
                stream=args.stream,
                events=wave,
            )
            time.sleep(interval)
    except KeyboardInterrupt:
        info("Loop interrupted by user.")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="seed_demo_data.py",
        description="Seed the AI Security Sandbox with realistic demo data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--mode", choices=["runs", "direct", "both"], default="direct",
                   help="Which seeding path to use (default: direct).")
    p.add_argument("--scenarios-path", type=Path, default=DEFAULT_SCENARIOS_PATH,
                   help="Override the scenarios JSON file.")
    p.add_argument("--seed", type=int, default=None,
                   help="PRNG seed for reproducible runs.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print plan without contacting Azure.")
    p.add_argument("--reset", action="store_true",
                   help="Print KQL / az commands to remove previously-seeded rows, then exit.")

    # Runs mode
    runs = p.add_argument_group("runs mode")
    runs.add_argument("--apim-url", default=os.environ.get("APIM_URL"),
                      help="APIM gateway base URL, e.g. https://apim-xxx.azure-api.net")
    runs.add_argument("--aad-client-id", default=os.environ.get("AAD_CLIENT_ID"),
                      help="Orchestrator AAD app registration client id.")
    runs.add_argument("--apim-subscription-key", default=os.environ.get("APIM_SUBSCRIPTION_KEY"),
                      help="Optional APIM subscription key (Ocp-Apim-Subscription-Key).")
    runs.add_argument("--benign-runs", type=int, default=10,
                      help="Real benign runs to fire (default 10).")
    runs.add_argument("--attack-runs", type=int, default=6,
                      help="Real attack runs to fire (default 6).")
    runs.add_argument("--parallel", type=int, default=DEFAULT_PARALLEL,
                      help=f"Concurrent HTTP workers (default {DEFAULT_PARALLEL}).")
    runs.add_argument("--upload-sample", type=Path, default=None,
                      help="Optional file to attach via multipart on ~25%% of benign runs.")

    # Direct mode
    direct = p.add_argument_group("direct mode")
    direct.add_argument("--dce-logs", default=os.environ.get("DCE_LOGS"),
                        help="DCE logs ingestion endpoint, e.g. https://dce-xxx.region.ingest.monitor.azure.com")
    direct.add_argument("--dcr-immutable-id", default=os.environ.get("DCR_IMMUTABLE_ID"),
                        help="Immutable id of the AiAgentAudit DCR (dcr-...).")
    direct.add_argument("--stream", default=os.environ.get("DCR_STREAM", "Custom-AiAgentAudit_CL"),
                        help="DCR stream name (default Custom-AiAgentAudit_CL).")
    direct.add_argument("--benign-events", type=int, default=80,
                        help="Benign scenarios to expand (each yields multiple rows) (default 80).")
    direct.add_argument("--attack-events", type=int, default=12,
                        help="Attack scenarios to expand (default 12).")
    direct.add_argument("--backfill-hours", type=float, default=24.0,
                        help="Spread events across this many hours of history (default 24).")

    # Loop / continuous
    loop = p.add_argument_group("loop mode")
    loop.add_argument("--loop-minutes", type=int, default=0,
                      help="After seeding, keep dripping events for N minutes (default 0 = off).")
    loop.add_argument("--loop-interval-seconds", type=int, default=30,
                      help="Seconds between drip waves (min 5, default 30).")
    loop.add_argument("--loop-wave-size", type=int, default=2,
                      help="Scenarios expanded per drip wave (default 2).")

    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.reset:
        reset_hint()
        return

    if not args.scenarios_path.exists():
        raise SystemExit(f"Scenarios file not found: {args.scenarios_path}")
    scenarios = json.loads(args.scenarios_path.read_text(encoding="utf-8"))

    needs_az = (args.mode in ("runs", "both")) or (
        args.mode in ("direct", "both") and not args.dry_run
    )
    if needs_az and not args.dry_run:
        ensure_az_login()

    if args.mode in ("direct", "both"):
        mode_direct(args, scenarios)
    if args.mode in ("runs", "both"):
        mode_runs(args, scenarios)
    if args.loop_minutes > 0:
        mode_loop(args, scenarios)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        warn("Interrupted by user.")
        sys.exit(130)
