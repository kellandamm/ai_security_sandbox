"""
Phase 4 — statistical anomaly detection unit tests.

Covers:
 - RunStats accumulator semantics
 - BaselineStore rolling-window arithmetic + bounded memory
 - AnomalyScorer Z-score combination, EWMA smoothing, halt threshold
 - Fail-closed: insufficient samples → no signal (cannot block)
 - commit_run / score_run round-trip
 - baseline_refresher integration shape
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "app"))

os.environ.setdefault("APIM_IDENTITY_SIGNING_SECRET", "test-signing-secret")

import anomaly  # noqa: E402
from anomaly import (  # noqa: E402
    AnomalyScorer,
    BaselineStore,
    RunStats,
    baseline_refresher,
    get_default_scorer,
)


# ── RunStats ──────────────────────────────────────────────────────────────────
def test_run_stats_initial_state():
    s = RunStats()
    v = s.feature_vector()
    assert v["events"] == 0
    assert v["tokens"] == 0
    assert v["denial_rate"] == 0.0
    assert v["unique_tools"] == 0
    assert v["mean_risk_score"] == 0.0


def test_run_stats_observes_tools_tokens_and_denials():
    s = RunStats()
    s.observe_event(tool_name="file_read", tokens=100, risk_score=0.2)
    s.observe_event(tool_name="file_read", tokens=50, denied=True, risk_score=0.6)
    s.observe_event(tool_name="http_get", tokens=200, risk_score=0.1)
    v = s.feature_vector()
    assert v["events"] == 3
    assert v["tokens"] == 350
    assert v["unique_tools"] == 2  # file_read + http_get
    assert v["denial_rate"] == pytest.approx(1 / 3)
    assert v["mean_risk_score"] == pytest.approx((0.2 + 0.6 + 0.1) / 3)


def test_run_stats_token_floor_at_zero():
    # Negative tokens are clamped — defensive.
    s = RunStats()
    s.observe_event(tokens=-10)
    assert s.tokens == 0


# ── BaselineStore ─────────────────────────────────────────────────────────────
def test_baseline_store_returns_zero_for_unseen_keys():
    store = BaselineStore()
    mean, stddev, n = store.get_stats("data-analyst", "events")
    assert (mean, stddev, n) == (0.0, 0.0, 0)


def test_baseline_store_record_run_accumulates_features():
    store = BaselineStore()
    for tokens in [100, 200, 300, 400, 500]:
        s = RunStats()
        s.observe_event(tool_name="file_read", tokens=tokens)
        store.record_run("data-analyst", s)
    mean, stddev, n = store.get_stats("data-analyst", "tokens")
    assert n == 5
    assert mean == pytest.approx(300.0)
    assert stddev > 0


def test_baseline_store_bounded_history(monkeypatch):
    monkeypatch.setattr(anomaly, "MAX_HISTORY", 3)
    store = BaselineStore()
    for v in range(10):
        s = RunStats()
        s.observe_event(tool_name="t", tokens=v)
        store.record_run("a", s)
    # Only the last 3 retained.
    _, _, n = store.get_stats("a", "tokens")
    assert n == 3


def test_baseline_store_snapshot_groups_by_agent_type():
    store = BaselineStore()
    s = RunStats()
    s.observe_event(tool_name="file_read", tokens=10)
    store.record_run("a", s)
    store.record_run("b", s)
    snap = store.snapshot()
    assert set(snap.keys()) == {"a", "b"}
    assert "tokens" in snap["a"]


# ── Bootstrap / insufficient samples ─────────────────────────────────────────
def test_scorer_returns_no_signal_during_bootstrap(monkeypatch):
    # Real-world-tunable: with fewer than MIN_SAMPLES the scorer must not
    # halt — protects new agent types from immediate false positives.
    monkeypatch.setattr(anomaly, "MIN_SAMPLES", 20)
    store = BaselineStore()
    # Only 5 samples → below MIN_SAMPLES.
    for tokens in [100, 200, 300, 400, 500]:
        s = RunStats()
        s.observe_event(tool_name="t", tokens=tokens)
        store.record_run("a", s)
    scorer = AnomalyScorer(store, halt_threshold=0.9)
    outlier = RunStats()
    outlier.observe_event(tool_name="t", tokens=100_000)
    decision = scorer.score_run("a", outlier)
    assert decision.halted is False
    assert decision.score == 0.0


# ── Scorer correctness on synthetic distributions ────────────────────────────
def _populate_store(store: BaselineStore, agent_type: str, *, n: int = 100) -> None:
    """Add n typical 'data-analyst' shaped runs with mild natural jitter
    so the baseline stddev is positive."""
    import random

    rng = random.Random(0xC0FFEE)
    for _ in range(n):
        s = RunStats()
        events = rng.randint(4, 6)
        for _ in range(events):
            s.observe_event(
                tool_name="file_read",
                tokens=rng.randint(80, 120),
                risk_score=rng.uniform(0.05, 0.15),
            )
        store.record_run(agent_type, s)


def test_scorer_flags_clear_outlier(monkeypatch):
    monkeypatch.setattr(anomaly, "MIN_SAMPLES", 20)
    store = BaselineStore()
    _populate_store(store, "data-analyst", n=100)
    scorer = AnomalyScorer(store, halt_threshold=0.9, ewma_alpha=1.0)

    # 50x normal token volume + many unique tools + high denial rate.
    rogue = RunStats()
    for tool in ("file_read", "http_get", "openai_call", "file_write"):
        rogue.observe_event(tool_name=tool, tokens=20_000, denied=True, risk_score=0.9)
    decision = scorer.score_run("data-analyst", rogue)
    assert decision.score > 0.8, decision
    # With ewma_alpha=1 (no smoothing) the first call should already trip.
    assert decision.halted is True


def test_scorer_passes_typical_run(monkeypatch):
    monkeypatch.setattr(anomaly, "MIN_SAMPLES", 20)
    store = BaselineStore()
    _populate_store(store, "data-analyst", n=100)
    scorer = AnomalyScorer(store, halt_threshold=0.9, ewma_alpha=1.0)

    typical = RunStats()
    for _ in range(5):
        typical.observe_event(tool_name="file_read", tokens=100, risk_score=0.1)
    decision = scorer.score_run("data-analyst", typical)
    assert decision.score < 0.2
    assert decision.halted is False


def test_ewma_smooths_single_burst(monkeypatch):
    """A single anomalous tick should not halt under a low alpha if the run
    is otherwise normal."""
    monkeypatch.setattr(anomaly, "MIN_SAMPLES", 20)
    store = BaselineStore()
    _populate_store(store, "data-analyst", n=100)
    # Low alpha → strong smoothing.
    scorer = AnomalyScorer(store, halt_threshold=0.9, ewma_alpha=0.1)
    stats = RunStats()
    # Warm up with normal observations.
    for _ in range(5):
        stats.observe_event(tool_name="file_read", tokens=100, risk_score=0.1)
        scorer.score_run("data-analyst", stats)
    # Single burst.
    stats.observe_event(tool_name="http_get", tokens=20_000, denied=True, risk_score=0.9)
    decision = scorer.score_run("data-analyst", stats)
    # Should be elevated but not at 0.9 yet thanks to smoothing.
    assert decision.score < 0.9


# ── Decision payload shape ───────────────────────────────────────────────────
def test_decision_to_audit_dict_keys():
    store = BaselineStore()
    scorer = AnomalyScorer(store)
    decision = scorer.score_run("a", RunStats())
    payload = decision.to_audit_dict()
    assert set(payload.keys()) == {"score", "z_scores", "halted"}


# ── commit_run round-trip ────────────────────────────────────────────────────
def test_commit_run_updates_baseline():
    store = BaselineStore()
    scorer = AnomalyScorer(store)
    s = RunStats()
    s.observe_event(tool_name="t", tokens=42)
    scorer.commit_run("a", s)
    _, _, n = store.get_stats("a", "tokens")
    assert n == 1


# ── Default singletons stable across calls ───────────────────────────────────
def test_default_scorer_is_singleton():
    a = get_default_scorer()
    b = get_default_scorer()
    assert a is b


# ── Baseline refresher coroutine completes when bounded ──────────────────────
def test_baseline_refresher_runs_bounded():
    # interval=0 + iterations=2 → finishes quickly without hanging.
    asyncio.new_event_loop().run_until_complete(
        baseline_refresher(interval_seconds=0, iterations=2)
    )


# ── Halt threshold respected ────────────────────────────────────────────────
def test_custom_halt_threshold_lowers_trigger(monkeypatch):
    monkeypatch.setattr(anomaly, "MIN_SAMPLES", 5)
    store = BaselineStore()
    _populate_store(store, "x", n=10)
    # Very low threshold → even mild deviation halts.
    scorer = AnomalyScorer(store, halt_threshold=0.05, ewma_alpha=1.0)
    s = RunStats()
    s.observe_event(tool_name="file_read", tokens=2000, risk_score=0.5)
    decision = scorer.score_run("x", s)
    assert decision.halted is True
