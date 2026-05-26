"""
Phase 7 — output sanitization helpers (OWASP LLM02 — Insecure Output Handling).

Defense in depth: even though the frontend renders agent output as code/text,
the orchestrator must not emit raw output that can be weaponized when copied
into Excel, pasted into a browser, or piped into a downstream system that
expects strict JSON.

Three pure functions:

* :func:`sanitize_for_csv` — neutralizes formula-injection leads ``= + - @ |``
* :func:`sanitize_for_html` — escapes HTML special characters
* :func:`sanitize_for_json` — strict round-trip with deterministic separators

None of the helpers raise; they always return a string (or, for JSON, a
``str``). Callers should pick the helper that matches the immediate sink.
"""

from __future__ import annotations

import html
import json
from typing import Any

# Characters that Excel/LibreOffice/Google Sheets interpret as the start of a
# formula. Prefixing a single quote forces literal interpretation in every
# major spreadsheet app. ``|`` is included because it triggers DDE in legacy
# Excel exports (`=cmd|' /C calc'!A0`).
_CSV_FORMULA_LEADS = ("=", "+", "-", "@", "|", "\t", "\r")


def sanitize_for_csv(text: str) -> str:
    """Neutralize formula-injection prefixes in a CSV cell value.

    Empty / non-string inputs are coerced to ``str`` and returned. A leading
    formula character is prefixed with ``'`` so the cell renders as literal
    text. Internal characters are left untouched — they are not exploitable
    unless they appear at position zero.
    """
    if text is None:
        return ""
    s = str(text)
    if not s:
        return s
    if s[0] in _CSV_FORMULA_LEADS:
        return "'" + s
    return s


def sanitize_for_html(text: str) -> str:
    """HTML-escape *text* including quotes. Never emit raw markup."""
    if text is None:
        return ""
    return html.escape(str(text), quote=True)


def sanitize_for_json(obj: Any) -> str:
    """Strict, deterministic JSON encoding.

    * ``separators=(",", ":")`` keeps payloads compact and prevents
      whitespace-based smuggling.
    * ``ensure_ascii=True`` neutralizes RTL-override and other Unicode
      direction tricks in serialized output.
    * ``default=str`` ensures unknown types degrade to a safe string
      instead of raising — Phase 7 sanitization must never throw on the
      response path.
    """
    return json.dumps(
        obj,
        separators=(",", ":"),
        ensure_ascii=True,
        sort_keys=True,
        default=str,
    )


def sanitize_agent_result(result: Any) -> Any:
    """Sanitize the orchestrator's final ``result`` dict in place-style.

    The agent returns a JSON-able dict; we apply HTML escaping to the
    ``output`` field (the only free-text payload exposed to the UI) and
    leave structural fields alone. Returns the same dict for chaining.
    """
    if not isinstance(result, dict):
        return result
    output = result.get("output")
    if isinstance(output, str):
        result["output"] = sanitize_for_html(output)
    return result


__all__ = [
    "sanitize_agent_result",
    "sanitize_for_csv",
    "sanitize_for_html",
    "sanitize_for_json",
]
