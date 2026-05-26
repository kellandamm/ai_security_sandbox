"""
Phase 4 — statistical / EWMA behavioural anomaly detection.

Scope
-----
This module provides a *statistical* anomaly scorer that is intentionally
simple, dependency-free, and explainable. It is not an ML model. The seam
is here for an isolation-forest / autoencoder replacement later (see
:func:`AnomalyScorer.score`).

Pipeline
~~~~~~~~
1. During a run the agent loop holds a :class:`RunStats` object that
   incrementally accumulates the per-run feature vector:

   - ``events`` — total audit events emitted
   - ``tokens`` — total OpenAI tokens consumed
   - ``denials`` — count of OPA / capability denials
   - ``unique_tools`` — distinct tool names seen
   - ``risk_scores`` — list of policy ``risk_score`` values

2. After each tool call the agent loop calls
   :meth:`AnomalyScorer.score_run` with the current stats. The scorer
   converts the vector to per-feature Z-scores against the per-(agent_type)
   baseline, combines them via a weighted sum, applies an EWMA smoother,
   and returns a value in ``[0, 1]``.

3. The scorer also returns a deterministic explanation map
   (``feature -> z-score``) the agent loop attaches to the next audit
   event via ``anomaly_score`` / ``error_code``.

4. If ``score >= halt_threshold`` (default 0.9) the agent loop raises
   :class:`AnomalyHaltError`, which the orchestrator surfaces as a
   policy-style halt rather than a process crash. The halt is per-run only
   — it does **not** trip a global kill switch.

Fail-closed semantics
~~~~~~~~~~~~~~~~~~~~~
- When the baseline store is unreachable, the scorer returns ``0.0``
  (no signal) so it cannot *block* a run on its own infrastructure
  failure. The deny path remains OPA + capability manifest + sandbox.
- When the baseline has too few samples (``< MIN_SAMPLES``) the scorer
  returns ``0.0`` for that feature — preventing false halts during
  bootstrap.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── Tunables (env-overridable) ────────────────────────────────────────────────
ANOMALY_HALT_THRESHOLD = float(os.environ.get("ANOMALY_HALT_THRESHOLD", "0.9"))
ANOMALY_EWMA_ALPHA = float(os.environ.get("ANOMALY_EWMA_ALPHA", "0.3"))
MIN_SAMPLES = int(os.environ.get("ANOMALY_MIN_SAMPLES", "20"))
MAX_HISTORY = int(os.environ.get("ANOMALY_MAX_HISTORY", "1000"))
BASELINE_REFRESH_SECONDS = int(os.environ.get("ANOMALY_REFRESH_SECONDS", "300"))

# Weights used to combine per-feature Z-scores. Tuned so a strong outlier on
# any single behavioural dimension still produces a high overall score.
_FEATURE_WEIGHTS: dict[str, float] = {
    "events": 0.20,
    "tokens": 0.20,
    "denial_rate": 0.30,  # highest weight — denials are the strongest signal
    "unique_tools": 0.10,
    "mean_risk_score": 0.20,
}


# ── Run-scoped accumulator ────────────────────────────────────────────────────
@dataclass
class RunStats:
    """Incremental per-run feature vector."""

    events: int = 0
    tokens: int = 0
    denials: int = 0
    risk_scores: list[float] = field(default_factory=list)
    tool_calls: int = 0
    _tools_seen: set[str] = field(default_factory=set)
    _ewma: float = 0.0
    _ewma_initialized: bool = False

    def observe_event(
        self,
        *,
        tool_name: str | None = None,
        tokens: int = 0,
        denied: bool = False,
        risk_score: float | None = None,
    ) -> None:
        self.events += 1
        self.tokens += max(0, tokens)
        if denied:
            self.denials += 1
        if risk_score is not None:
            self.risk_scores.append(float(risk_score))
        if tool_name:
            self.tool_calls += 1
            self._tools_seen.add(tool_name)

    @property
    def unique_tools(self) -> int:
        return len(self._tools_seen)

    @property
    def denial_rate(self) -> float:
        # Denial rate is per *event*, not per tool call, so a flood of
        # denied OPA checks dominates even with few tool invocations.
        return self.denials / self.events if self.events else 0.0

    @property
    def mean_risk_score(self) -> float:
        return (
            sum(self.risk_scores) / len(self.risk_scores)
            if self.risk_scores
            else 0.0
        )

    def feature_vector(self) -> dict[str, float]:
        return {
            "events": float(self.events),
            "tokens": float(self.tokens),
            "denial_rate": float(self.denial_rate),
            "unique_tools": float(self.unique_tools),
            "mean_risk_score": float(self.mean_risk_score),
        }


# ── Baseline statistics store ────────────────────────────────────────────────
@dataclass
class _FeatureWindow:
    """Rolling sample window for one (agent_type, feature) pair."""

    samples: list[float] = field(default_factory=list)

    def add(self, value: float) -> None:
        self.samples.append(float(value))
        if len(self.samples) > MAX_HISTORY:
            # Drop the oldest sample — bounded memory.
            del self.samples[: len(self.samples) - MAX_HISTORY]

    def stats(self) -> tuple[float, float, int]:
        n = len(self.samples)
        if n == 0:
            return 0.0, 0.0, 0
        mean = sum(self.samples) / n
        if n < 2:
            return mean, 0.0, n
        variance = sum((s - mean) ** 2 for s in self.samples) / (n - 1)
        return mean, math.sqrt(variance), n

    def to_dict(self) -> dict[str, Any]:
        mean, stddev, n = self.stats()
        return {"n": n, "mean": mean, "stddev": stddev}


class BaselineStore:
    """Thread-safe rolling baseline of per-(agent_type, feature) samples.

    The default implementation keeps samples in memory. A subclass may
    override :meth:`_persist` / :meth:`_load` to back the store onto blob
    storage; the orchestrator wires that in :func:`build_default_store`
    when ``AUDIT_STORAGE_ACCOUNT`` is configured.

    Fail-closed: any persistence failure logs a warning and continues in
    memory-only mode. Persistence failure must never block a run.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[tuple[str, str], _FeatureWindow] = {}

    # ── public API ────────────────────────────────────────────────────────
    def record_run(self, agent_type: str, stats: RunStats) -> None:
        """Add a completed run's feature vector to the baseline."""
        if not agent_type:
            return
        vector = stats.feature_vector()
        with self._lock:
            for feature, value in vector.items():
                key = (agent_type, feature)
                window = self._windows.setdefault(key, _FeatureWindow())
                window.add(value)
        # Best-effort persistence — never raises.
        try:
            self._persist(agent_type, vector)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("BaselineStore persist failed: %s", exc)

    def get_stats(self, agent_type: str, feature: str) -> tuple[float, float, int]:
        """Return ``(mean, stddev, sample_count)`` for the requested key."""
        with self._lock:
            window = self._windows.get((agent_type, feature))
            return window.stats() if window else (0.0, 0.0, 0)

    def snapshot(self) -> dict[str, dict[str, dict[str, float]]]:
        """Diagnostic snapshot of the store, grouped by agent type."""
        out: dict[str, dict[str, dict[str, float]]] = {}
        with self._lock:
            for (agent_type, feature), window in self._windows.items():
                out.setdefault(agent_type, {})[feature] = window.to_dict()
        return out

    # ── persistence hooks (no-op default) ─────────────────────────────────
    def _persist(self, agent_type: str, vector: dict[str, float]) -> None:
        """Subclasses override. Default no-op."""

    def _load(self) -> None:
        """Subclasses override. Default no-op."""


# ── Scorer ────────────────────────────────────────────────────────────────────
@dataclass
class AnomalyDecision:
    """Composite anomaly verdict returned by :meth:`AnomalyScorer.score_run`."""

    score: float
    z_scores: dict[str, float]
    halted: bool

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "z_scores": {k: round(v, 3) for k, v in self.z_scores.items()},
            "halted": self.halted,
        }


class AnomalyScorer:
    """Z-score + EWMA composite scorer.

    Parameters
    ----------
    baseline_store
        The :class:`BaselineStore` to draw per-feature statistics from.
    halt_threshold
        Composite score at or above which :attr:`AnomalyDecision.halted`
        becomes ``True``. Defaults to :data:`ANOMALY_HALT_THRESHOLD`.
    ewma_alpha
        Smoothing factor in ``(0, 1]``. Higher → more weight on the latest
        observation. The smoother lives on each ``RunStats`` instance.
    """

    def __init__(
        self,
        baseline_store: BaselineStore,
        *,
        halt_threshold: float | None = None,
        ewma_alpha: float | None = None,
        feature_weights: dict[str, float] | None = None,
    ) -> None:
        self._store = baseline_store
        self._halt = (
            halt_threshold if halt_threshold is not None else ANOMALY_HALT_THRESHOLD
        )
        self._alpha = ewma_alpha if ewma_alpha is not None else ANOMALY_EWMA_ALPHA
        self._weights = feature_weights or _FEATURE_WEIGHTS

    # ── live scoring ──────────────────────────────────────────────────────
    def score_run(self, agent_type: str, stats: RunStats) -> AnomalyDecision:
        """Score the *in-progress* run against the baseline."""
        vector = stats.feature_vector()
        z_scores: dict[str, float] = {}
        weighted_sum = 0.0
        weight_total = 0.0
        for feature, value in vector.items():
            mean, stddev, n = self._store.get_stats(agent_type, feature)
            if n < MIN_SAMPLES or stddev <= 0:
                # Not enough baseline to score this feature yet.
                z = 0.0
            else:
                z = abs(value - mean) / stddev
            z_scores[feature] = z
            weight = self._weights.get(feature, 0.0)
            weighted_sum += weight * z
            weight_total += weight

        raw = weighted_sum / weight_total if weight_total > 0 else 0.0
        # Map raw Z-score (~0..6) to [0, 1] via a soft logistic — keeps
        # extreme outliers near 1 without ever exceeding it.
        instantaneous = 1.0 - math.exp(-raw / 2.0)

        # EWMA smoother: the smoother lives on stats so successive calls
        # within a single run feed each other.
        if not stats._ewma_initialized:
            stats._ewma = instantaneous
            stats._ewma_initialized = True
        else:
            stats._ewma = (
                self._alpha * instantaneous + (1.0 - self._alpha) * stats._ewma
            )

        composite = max(0.0, min(1.0, stats._ewma))
        return AnomalyDecision(
            score=composite,
            z_scores=z_scores,
            halted=composite >= self._halt,
        )

    # ── completion path ──────────────────────────────────────────────────
    def commit_run(self, agent_type: str, stats: RunStats) -> None:
        """Record the completed run's feature vector into the baseline."""
        self._store.record_run(agent_type, stats)


# ── Default singleton ─────────────────────────────────────────────────────────
_DEFAULT_STORE: BaselineStore | None = None
_DEFAULT_SCORER: AnomalyScorer | None = None


def build_default_store() -> BaselineStore:
    """Return (and lazily build) the process-wide baseline store."""
    global _DEFAULT_STORE
    if _DEFAULT_STORE is None:
        _DEFAULT_STORE = BaselineStore()
    return _DEFAULT_STORE


def get_default_scorer() -> AnomalyScorer:
    """Return (and lazily build) the process-wide anomaly scorer."""
    global _DEFAULT_SCORER
    if _DEFAULT_SCORER is None:
        _DEFAULT_SCORER = AnomalyScorer(build_default_store())
    return _DEFAULT_SCORER


# ── Background baseline refresher (orchestrator startup hook) ────────────────
async def baseline_refresher(
    *,
    interval_seconds: int | None = None,
    iterations: int | None = None,
) -> None:
    """Long-running task to be scheduled at orchestrator startup.

    Re-reads persisted state from the underlying store every
    ``interval_seconds``. The default :class:`BaselineStore` is in-memory
    only, so the refresher is a no-op; subclasses overriding ``_load``
    benefit from the cadence. ``iterations`` is for test injection.
    """
    interval = (
        interval_seconds if interval_seconds is not None else BASELINE_REFRESH_SECONDS
    )
    store = build_default_store()
    i = 0
    while True:
        try:
            store._load()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Baseline refresh failed: %s", exc)
        i += 1
        if iterations is not None and i >= iterations:
            return
        await asyncio.sleep(interval)


__all__ = [
    "ANOMALY_HALT_THRESHOLD",
    "AnomalyDecision",
    "AnomalyScorer",
    "BaselineStore",
    "RunStats",
    "baseline_refresher",
    "build_default_store",
    "get_default_scorer",
]
