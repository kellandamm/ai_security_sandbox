"""
Phase 2 — agent-to-agent delegation envelope.

A :class:`DelegationToken` is a short-lived (5 min default), HMAC-SHA256
signed envelope a *parent* run hands to the orchestrator when it wants to
spawn a *child* run. The token is bound to:

* ``parent_run_id`` — the run that requested the spawn
* ``parent_agent_type`` — issuer agent type
* ``child_agent_type`` — what kind of agent the child must be
* ``allowed_tools`` — strict subset of the parent's
  ``capability_manifest.delegation_scopes`` that the child may use
* ``call_depth`` — how many spawn hops have occurred so far; orchestrator
  rejects a token whose depth would exceed :data:`MAX_CALL_DEPTH`
* ``expires_at`` — unix epoch seconds; verification rejects expired tokens
* ``nonce`` — single-use uniqueness guard (caller deduplicates)

The token is **opaque** to the parent agent: it is issued by the
orchestrator's signed-envelope helper using the same
``APIM_IDENTITY_SIGNING_SECRET`` already used for admin-route HMACs. The
parent never sees the secret; it sees the resulting base64 envelope.

Fail-closed semantics
~~~~~~~~~~~~~~~~~~~~~
* Signature mismatch → :class:`DelegationDeniedError`
* Expired token → :class:`DelegationDeniedError`
* Scope superset (child requested tool not in token) → deny
* Call depth > :data:`MAX_CALL_DEPTH` → deny
* Missing signing secret → deny (cannot verify → cannot trust)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from errors import DelegationDeniedError

# ── Tunables (env-overridable) ────────────────────────────────────────────────
DEFAULT_TTL_SECONDS = int(os.environ.get("DELEGATION_TTL_SECONDS", "300"))
MAX_CALL_DEPTH = int(os.environ.get("DELEGATION_MAX_DEPTH", "3"))


@dataclass(frozen=True)
class DelegationToken:
    """Parsed, validated delegation envelope.

    Construct via :meth:`issue` or :meth:`verify`; never instantiate
    directly outside those helpers (the dataclass is dataclass-frozen but
    has no signature on its own).
    """

    parent_run_id: str
    parent_agent_type: str
    child_agent_type: str
    allowed_tools: tuple[str, ...]
    call_depth: int
    issued_at: int
    expires_at: int
    nonce: str
    call_chain: tuple[str, ...] = field(default_factory=tuple)

    # ── factory ────────────────────────────────────────────────────────────
    @classmethod
    def issue(
        cls,
        *,
        parent_run_id: str,
        parent_agent_type: str,
        child_agent_type: str,
        allowed_tools: list[str],
        signing_secret: str,
        call_depth: int = 1,
        ttl_seconds: int | None = None,
        call_chain: list[str] | None = None,
    ) -> tuple["DelegationToken", str]:
        """Issue a new token + serialized envelope.

        Returns ``(token, envelope_str)``. The envelope is what callers
        embed in the spawn request body (or an ``X-Delegation-Token``
        header). ``verify(envelope_str, secret)`` reconstructs the token.

        Raises ``ValueError`` if ``signing_secret`` is empty — issuance
        without a verifier secret is meaningless and would always fail
        downstream verification.
        """
        if not signing_secret:
            raise ValueError("signing_secret is required to issue a delegation token")
        if call_depth < 1:
            raise ValueError("call_depth must be >= 1")
        if not parent_run_id or not parent_agent_type or not child_agent_type:
            raise ValueError(
                "parent_run_id, parent_agent_type, and child_agent_type are required"
            )
        # Deduplicate / canonicalize so signature is stable regardless of input order.
        tools = tuple(sorted(set(allowed_tools)))
        now = int(time.time())
        ttl = ttl_seconds if ttl_seconds is not None else DEFAULT_TTL_SECONDS
        token = cls(
            parent_run_id=parent_run_id,
            parent_agent_type=parent_agent_type,
            child_agent_type=child_agent_type,
            allowed_tools=tools,
            call_depth=call_depth,
            issued_at=now,
            expires_at=now + ttl,
            nonce=secrets.token_urlsafe(16),
            call_chain=tuple(call_chain or []),
        )
        envelope = _encode(token, signing_secret)
        return token, envelope

    # ── verifier ───────────────────────────────────────────────────────────
    @classmethod
    def verify(cls, envelope: str, *, signing_secret: str) -> "DelegationToken":
        """Parse + signature-verify + expiry-check + depth-check.

        Raises :class:`DelegationDeniedError` on any failure. Returns the
        validated token on success.
        """
        if not signing_secret:
            raise DelegationDeniedError(
                "Delegation signing secret not configured — failing closed"
            )
        if not envelope or not isinstance(envelope, str):
            raise DelegationDeniedError("Empty delegation envelope")

        try:
            payload_b64, sig_b64 = envelope.split(".", 1)
        except ValueError as exc:
            raise DelegationDeniedError("Malformed delegation envelope") from exc

        # Constant-time signature check against the raw payload bytes.
        expected = _sign(payload_b64.encode("ascii"), signing_secret)
        try:
            given = base64.urlsafe_b64decode(_pad(sig_b64))
        except (ValueError, TypeError) as exc:
            raise DelegationDeniedError("Malformed delegation signature") from exc
        if not hmac.compare_digest(expected, given):
            raise DelegationDeniedError("Delegation signature mismatch")

        try:
            decoded = base64.urlsafe_b64decode(_pad(payload_b64))
            payload = json.loads(decoded.decode("utf-8"))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise DelegationDeniedError("Malformed delegation payload") from exc
        if not isinstance(payload, dict):
            raise DelegationDeniedError("Delegation payload must be an object")

        try:
            token = cls(
                parent_run_id=str(payload["parent_run_id"]),
                parent_agent_type=str(payload["parent_agent_type"]),
                child_agent_type=str(payload["child_agent_type"]),
                allowed_tools=tuple(payload.get("allowed_tools", [])),
                call_depth=int(payload["call_depth"]),
                issued_at=int(payload["issued_at"]),
                expires_at=int(payload["expires_at"]),
                nonce=str(payload["nonce"]),
                call_chain=tuple(payload.get("call_chain", [])),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise DelegationDeniedError(
                "Delegation payload missing required fields"
            ) from exc

        now = int(time.time())
        if now >= token.expires_at:
            raise DelegationDeniedError(
                f"Delegation token expired at {token.expires_at} (now={now})"
            )
        if token.call_depth > MAX_CALL_DEPTH:
            raise DelegationDeniedError(
                f"Delegation call_depth {token.call_depth} exceeds max {MAX_CALL_DEPTH}"
            )
        return token

    # ── runtime authorization helpers ─────────────────────────────────────
    def authorize_tool(self, tool_name: str) -> None:
        """Raise :class:`DelegationDeniedError` if *tool_name* is outside the
        token's allowed scope."""
        if tool_name not in self.allowed_tools:
            raise DelegationDeniedError(
                f"Tool {tool_name!r} not in delegation scope "
                f"({list(self.allowed_tools)})"
            )

    def child_call_chain(self, child_run_id: str) -> list[str]:
        """Compose the call chain for the child run for audit purposes."""
        return [*self.call_chain, self.parent_run_id, child_run_id]

    def to_payload(self) -> dict[str, Any]:
        """Return the canonical JSON-serializable payload."""
        return {
            "parent_run_id": self.parent_run_id,
            "parent_agent_type": self.parent_agent_type,
            "child_agent_type": self.child_agent_type,
            "allowed_tools": list(self.allowed_tools),
            "call_depth": self.call_depth,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "call_chain": list(self.call_chain),
        }


# ── policy-side validators (used by /runs/{id}/spawn handler) ───────────────
def assert_scope_is_subset(
    *,
    requested_tools: list[str],
    parent_delegation_scopes: list[str],
) -> None:
    """Raise :class:`DelegationDeniedError` if the requested tool list is
    not a subset of the parent's manifest-declared delegation scopes.
    """
    requested = set(requested_tools)
    allowed = set(parent_delegation_scopes)
    extras = requested - allowed
    if extras:
        raise DelegationDeniedError(
            f"Requested delegation scope {sorted(extras)} not in parent "
            f"delegation_scopes {sorted(allowed)}"
        )


def assert_child_type_allowed(
    *,
    child_agent_type: str,
    allowed_child_agent_types: list[str],
) -> None:
    """Raise :class:`DelegationDeniedError` if the child agent type is not
    in the parent's manifest-declared child allowlist."""
    if child_agent_type not in allowed_child_agent_types:
        raise DelegationDeniedError(
            f"Child agent type {child_agent_type!r} not in parent's "
            f"allowed_child_agent_types ({allowed_child_agent_types})"
        )


# ── internal envelope helpers ───────────────────────────────────────────────
def _sign(payload_b64: bytes, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), payload_b64, hashlib.sha256).digest()


def _encode(token: DelegationToken, secret: str) -> str:
    # Canonical JSON: sort_keys + tight separators → same bytes on every host.
    payload_bytes = json.dumps(
        token.to_payload(), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    sig = _sign(payload_b64.encode("ascii"), secret)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    return f"{payload_b64}.{sig_b64}"


def _pad(b64: str) -> str:
    pad = (-len(b64)) % 4
    return b64 + ("=" * pad)


__all__ = [
    "DEFAULT_TTL_SECONDS",
    "MAX_CALL_DEPTH",
    "DelegationToken",
    "assert_child_type_allowed",
    "assert_scope_is_subset",
]
