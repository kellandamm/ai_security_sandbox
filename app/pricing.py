"""
Phase 7 — pricing table + cost estimator.

The cost estimator computes USD spend for Azure OpenAI prompts based on a
static price table. Prices are stored per **1,000 tokens** to match Azure's
billing unit. Unknown models fall back to a deliberately conservative
default (the highest priced row) so a missing model entry never
under-counts spend — fail-closed for budgets.

The table is intentionally small and easy to update; production callers
should refresh it from Azure's published pricing or override via
environment if needed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ModelPrice:
    """USD price per 1,000 tokens, split by prompt vs completion."""

    prompt_per_1k: float
    completion_per_1k: float


# Conservative defaults. Numbers are illustrative; override via
# ``COST_PRICING_OVERRIDES`` env var (JSON string) if needed.
_DEFAULT_PRICING: dict[str, ModelPrice] = {
    "gpt-4o":          ModelPrice(prompt_per_1k=0.0050, completion_per_1k=0.0150),
    "gpt-4o-mini":     ModelPrice(prompt_per_1k=0.00015, completion_per_1k=0.0006),
    "gpt-4-turbo":     ModelPrice(prompt_per_1k=0.0100, completion_per_1k=0.0300),
    "gpt-5":           ModelPrice(prompt_per_1k=0.0125, completion_per_1k=0.0375),
    "gpt-5-mini":      ModelPrice(prompt_per_1k=0.00025, completion_per_1k=0.0010),
    "gpt-35-turbo":    ModelPrice(prompt_per_1k=0.0005, completion_per_1k=0.0015),
}

# The fallback row picks the most expensive model so unknown deployments
# cannot accidentally bypass a budget cap.
_FALLBACK = ModelPrice(prompt_per_1k=0.0125, completion_per_1k=0.0375)


def _load_pricing() -> dict[str, ModelPrice]:
    overrides_raw = os.environ.get("COST_PRICING_OVERRIDES", "")
    if not overrides_raw:
        return dict(_DEFAULT_PRICING)
    try:
        import json

        parsed = json.loads(overrides_raw)
        if not isinstance(parsed, dict):
            return dict(_DEFAULT_PRICING)
        merged = dict(_DEFAULT_PRICING)
        for name, prices in parsed.items():
            if (
                isinstance(prices, dict)
                and isinstance(prices.get("prompt_per_1k"), (int, float))
                and isinstance(prices.get("completion_per_1k"), (int, float))
            ):
                merged[str(name)] = ModelPrice(
                    prompt_per_1k=float(prices["prompt_per_1k"]),
                    completion_per_1k=float(prices["completion_per_1k"]),
                )
        return merged
    except (ValueError, TypeError):
        # Malformed override → ignore (fail-closed: use stricter defaults).
        return dict(_DEFAULT_PRICING)


_PRICING: dict[str, ModelPrice] = _load_pricing()


def get_price(model_name: str) -> ModelPrice:
    """Return pricing for *model_name*; fall back conservatively if unknown."""
    if not model_name:
        return _FALLBACK
    # Exact match first.
    if model_name in _PRICING:
        return _PRICING[model_name]
    # Strip provider/deployment suffixes — e.g. "gpt-4o-2024-08-06".
    base = model_name.split("-20")[0]  # strip "-YYYY..." version dates
    if base in _PRICING:
        return _PRICING[base]
    return _FALLBACK


def estimate_cost(
    *,
    model_name: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    """Return USD for the call. Negative inputs are clamped to 0."""
    pt = max(0, int(prompt_tokens))
    ct = max(0, int(completion_tokens))
    price = get_price(model_name)
    return (pt / 1000.0) * price.prompt_per_1k + (ct / 1000.0) * price.completion_per_1k


__all__ = ["ModelPrice", "estimate_cost", "get_price"]
