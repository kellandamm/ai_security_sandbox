"""
Prompt injection / jailbreak defense — Azure AI Content Safety Prompt Shields.

This module wraps the Azure AI Content Safety **Prompt Shields** REST API:
- User prompt shield: `/contentsafety/text:shieldPrompt`
- Document shield (indirect injection in retrieved content): same endpoint
  with the ``documents`` field populated.

Design intent
-------------
- **Fail-closed.** Transport errors raise :class:`PromptInjectionError` when
  the enforcement mode is ``block``; in ``monitor`` mode they downgrade to a
  warning so the rest of the pipeline can decide what to do.
- **Defense-in-depth.** Callers must still run the deterministic regex layer
  in ``app/main.py`` (NFKC + base64 + role-impersonation patterns). Prompt
  Shields is the second line, not the only line.
- **No I/O at import time.** The client lazily acquires a Managed Identity
  token on first use and caches it for its TTL.

Configuration (environment / App Configuration)
-----------------------------------------------
- ``CONTENT_SAFETY_ENDPOINT``        — e.g. ``https://<name>.cognitiveservices.azure.com``.
                                        If empty, the client is **disabled**
                                        (degrades to a no-op that returns a
                                        clean decision). This keeps local dev
                                        and unit tests offline.
- ``PROMPT_SHIELD_ENFORCEMENT_MODE`` — ``block`` (default) or ``monitor``.
- ``PROMPT_SHIELD_TIMEOUT_SECONDS``  — HTTP timeout, default ``5.0``.
- ``PROMPT_SHIELD_DENY_SCORE``       — Float threshold (default ``0.5``) at
                                        which a Prompt Shields response is
                                        treated as an attack when only a
                                        ``severity`` field is returned.

REST contract reference: Azure AI Content Safety Prompt Shields (2024-09-01).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import httpx
from azure.core.credentials_async import AsyncTokenCredential
from azure.identity.aio import DefaultAzureCredential

from errors import PromptInjectionError

logger = logging.getLogger(__name__)

_COGNITIVE_SCOPE = "https://cognitiveservices.azure.com/.default"
_API_VERSION = "2024-09-01"
_API_PATH = "/contentsafety/text:shieldPrompt"


@dataclass(frozen=True)
class PromptShieldDecision:
    """Outcome of a single Prompt Shields evaluation."""

    attack_detected: bool
    score: float  # in [0, 1]
    categories: list[str]
    source: str  # "user_prompt" | "uploaded_file" | "http_get" | "file_read"
    enforced: bool  # True if a block was raised (or would have been in block mode)
    raw: dict | None = None


class PromptShieldClient:
    """Thin async client for Azure AI Content Safety Prompt Shields.

    The client is **safe to instantiate with no endpoint configured**; it then
    operates as a transparent no-op (every call returns ``attack_detected=False``)
    so the orchestrator can run offline / in unit tests without Azure access.

    All public methods are coroutines and fail-closed under network error when
    enforcement mode is ``block``.
    """

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        enforcement_mode: str | None = None,
        timeout_seconds: float | None = None,
        deny_score: float | None = None,
        credential: AsyncTokenCredential | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._endpoint = (
            endpoint
            if endpoint is not None
            else os.environ.get("CONTENT_SAFETY_ENDPOINT", "")
        ).rstrip("/")
        self._enforcement_mode = (
            enforcement_mode
            or os.environ.get("PROMPT_SHIELD_ENFORCEMENT_MODE", "block")
        ).strip().lower()
        self._timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else float(os.environ.get("PROMPT_SHIELD_TIMEOUT_SECONDS", "5.0"))
        )
        self._deny_score = (
            deny_score
            if deny_score is not None
            else float(os.environ.get("PROMPT_SHIELD_DENY_SCORE", "0.5"))
        )
        self._credential = credential
        self._transport = transport

    # ── Public API ───────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """Whether the client is configured to make network calls."""
        return bool(self._endpoint)

    @property
    def enforcement_mode(self) -> str:
        return self._enforcement_mode

    async def scan_user_prompt(self, text: str) -> PromptShieldDecision:
        """Scan a direct user prompt (or aggregated task + uploaded text)."""
        return await self._scan(
            user_prompt=text or "",
            documents=[],
            source="user_prompt",
        )

    async def scan_document(
        self,
        text: str,
        *,
        source: str = "uploaded_file",
    ) -> PromptShieldDecision:
        """Scan retrieved or uploaded content for **indirect** prompt injection.

        ``source`` describes provenance for audit purposes:
        ``uploaded_file``, ``http_get``, ``file_read``.
        """
        return await self._scan(
            user_prompt="",
            documents=[text or ""],
            source=source,
        )

    # ── Internal ─────────────────────────────────────────────────────────────

    async def _scan(
        self,
        *,
        user_prompt: str,
        documents: list[str],
        source: str,
    ) -> PromptShieldDecision:
        # Disabled (no endpoint): transparent allow. Caller still has the
        # deterministic regex layer in main.py as the floor.
        if not self.enabled:
            return PromptShieldDecision(
                attack_detected=False,
                score=0.0,
                categories=[],
                source=source,
                enforced=False,
                raw=None,
            )

        # Empty payloads are not informative — skip the network round-trip.
        if not user_prompt and not any(documents):
            return PromptShieldDecision(
                attack_detected=False,
                score=0.0,
                categories=[],
                source=source,
                enforced=False,
                raw=None,
            )

        body: dict = {}
        if user_prompt:
            body["userPrompt"] = user_prompt
        if documents:
            body["documents"] = [d for d in documents if d]

        try:
            response_json = await self._post(body)
        except Exception as exc:  # network / auth failure — fail-closed
            logger.warning("Prompt Shields call failed: %s", exc)
            if self._enforcement_mode == "block":
                raise PromptInjectionError(
                    "Prompt Shields unreachable; failing closed",
                    score=1.0,
                    categories=["transport_error"],
                    source=source,
                ) from exc
            return PromptShieldDecision(
                attack_detected=False,
                score=0.0,
                categories=["transport_error"],
                source=source,
                enforced=False,
                raw=None,
            )

        attack, score, categories = _parse_shield_response(
            response_json, deny_score=self._deny_score
        )
        decision = PromptShieldDecision(
            attack_detected=attack,
            score=score,
            categories=categories,
            source=source,
            enforced=attack and self._enforcement_mode == "block",
            raw=response_json,
        )

        if decision.enforced:
            raise PromptInjectionError(
                f"Prompt injection attack detected in {source}",
                score=score,
                categories=categories,
                source=source,
            )

        return decision

    async def _post(self, body: dict) -> dict:
        owns_credential = False
        credential = self._credential
        if credential is None:
            credential = DefaultAzureCredential()
            owns_credential = True

        try:
            token = await credential.get_token(_COGNITIVE_SCOPE)
            headers = {
                "Authorization": f"Bearer {token.token}",
                "Content-Type": "application/json",
            }
            url = f"{self._endpoint}{_API_PATH}?api-version={_API_VERSION}"
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport
            ) as client:
                resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            return resp.json()
        finally:
            if owns_credential:
                await credential.close()


def _parse_shield_response(
    payload: dict,
    *,
    deny_score: float,
) -> tuple[bool, float, list[str]]:
    """Normalize an Azure Content Safety Prompt Shields response.

    The API returns either ``userPromptAnalysis`` or per-document analyses
    under ``documentsAnalysis``. Each item carries ``attackDetected: bool``
    (preferred) and optionally a ``severity`` 0–7 scale we map to [0, 1].

    Returns (attack_detected, max_score, category_labels).
    """
    attack = False
    max_score = 0.0
    categories: list[str] = []

    items: list[tuple[str, dict]] = []
    upa = payload.get("userPromptAnalysis")
    if isinstance(upa, dict):
        items.append(("user_prompt", upa))
    for idx, doc in enumerate(payload.get("documentsAnalysis") or []):
        if isinstance(doc, dict):
            items.append((f"document[{idx}]", doc))

    for label, item in items:
        if item.get("attackDetected") is True:
            attack = True
            categories.append(label)
        severity = item.get("severity")
        if isinstance(severity, (int, float)):
            score = max(0.0, min(1.0, float(severity) / 7.0))
            max_score = max(max_score, score)
            if score >= deny_score:
                attack = True
                if label not in categories:
                    categories.append(label)

    if attack and max_score == 0.0:
        # Boolean attack with no severity — assign a conservative high score.
        max_score = 0.95

    return attack, max_score, sorted(set(categories))


__all__ = [
    "PromptShieldClient",
    "PromptShieldDecision",
]
