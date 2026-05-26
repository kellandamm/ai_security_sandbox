"""
Phase 7 — sliding-window loop detector.

LLM-driven agents can wedge into infinite tool loops (re-reading the same
file, retrying the same fetch, oscillating between two tools). The
:class:`LoopDetector` keeps a per-run rolling window of the last K tool
calls keyed on ``(tool_name, sha256(canonical_args))``; if the same key
appears at least ``threshold`` times within the window it raises
:class:`LoopDetectedError`, which the agent loop surfaces and halts.

Design notes:

* Pure in-process state, no external dependency. Each
  :class:`EphemeralWorkspace` should hold its own detector instance — they
  are not shared between runs.
* The hash uses a canonical JSON form (sort_keys, tight separators) so
  semantically equivalent argument dicts produce the same key regardless
  of key ordering.
* Threshold is configurable per call to make the detector reusable for
  more aggressive policies (e.g. ``threshold=2`` for risky tools).
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from typing import Any

from errors import LoopDetectedError

DEFAULT_WINDOW = 8


def _arg_hash(tool_args: Any) -> str:
    """Canonical hash of tool arguments."""
    try:
        canonical = json.dumps(
            tool_args, sort_keys=True, separators=(",", ":"), default=str
        )
    except (TypeError, ValueError):
        canonical = repr(tool_args)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class LoopDetector:
    """Rolling-window detector for repeated identical tool calls."""

    def __init__(self, *, max_depth: int, window: int = DEFAULT_WINDOW) -> None:
        if max_depth < 2:
            # A threshold below 2 would block every tool on its first call.
            raise ValueError("max_depth must be >= 2")
        self._threshold = max_depth
        self._window: deque[str] = deque(maxlen=max(window, max_depth))

    def observe(self, tool_name: str, tool_args: Any) -> None:
        """Record a tool call. Raises :class:`LoopDetectedError` if the same
        ``(tool_name, args)`` pair has appeared ``max_depth`` times in the
        rolling window.
        """
        key = f"{tool_name}::{_arg_hash(tool_args)}"
        self._window.append(key)
        # Counting on a small deque is O(window) which is bounded and tiny.
        count = self._window.count(key)
        if count >= self._threshold:
            raise LoopDetectedError(
                f"Loop detected: tool {tool_name!r} called "
                f"{count} times with identical arguments",
                tool_name=tool_name,
                repetitions=count,
            )

    @property
    def window_size(self) -> int:
        return len(self._window)


__all__ = ["LoopDetector", "DEFAULT_WINDOW"]
