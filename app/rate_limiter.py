"""
In-process token-bucket rate limiter — backstop behind APIM.

APIM is the primary rate-limiting enforcement point (100 req/60s per agent-id).
This provides a second layer inside the process itself, guarding against cases
where internal endpoints are called directly (e.g., health check bypass).

Also enforces per-run token budget for Azure OpenAI calls.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict


class RateLimitExceeded(Exception):
    def __init__(self, identifier: str, retry_after: float):
        self.identifier = identifier
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded for {identifier!r}. Retry after {retry_after:.1f}s"
        )


class TokenBucket:
    """
    Standard token-bucket algorithm.
    Thread-safe for use within a single process.
    """

    def __init__(self, capacity: int, refill_rate: float):
        """
        capacity: max burst size (tokens)
        refill_rate: tokens added per second
        """
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> float:
        """
        Attempt to consume `tokens`.
        Returns 0.0 on success, or seconds-until-available on failure.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._capacity, self._tokens + elapsed * self._refill_rate
            )
            self._last_refill = now

            if self._tokens >= tokens:
                self._tokens -= tokens
                return 0.0
            else:
                deficit = tokens - self._tokens
                return deficit / self._refill_rate


class RateLimiter:
    """
    Per-identifier rate limiter backed by token buckets.

    Each agent_id gets its own bucket. Limits:
      - 100 requests per 60 seconds (matches APIM policy)
    """

    # 100 requests per 60 seconds = 100/60 ≈ 1.67 tokens/second
    CAPACITY = 100
    REFILL_RATE = 100 / 60.0

    def __init__(self):
        self._buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self.CAPACITY, self.REFILL_RATE)
        )
        self._lock = threading.Lock()

    def check(self, identifier: str) -> None:
        """Raises RateLimitExceeded if the identifier is over limit."""
        with self._lock:
            bucket = self._buckets[identifier]
        wait = bucket.consume()
        if wait > 0:
            raise RateLimitExceeded(identifier, wait)


class TokenBudget:
    """
    Per-run token budget for Azure OpenAI calls.
    Prevents prompt injection loops and runaway costs.
    """

    def __init__(self, max_tokens: int):
        self._max = max_tokens
        self._used = 0
        self._lock = threading.Lock()

    def consume(self, tokens: int) -> None:
        """Raises QuotaExceededError if budget is exhausted."""
        from sandbox import QuotaExceededError

        with self._lock:
            if self._used + tokens > self._max:
                raise QuotaExceededError(
                    "Token budget exhausted: "
                    f"used={self._used}, requested={tokens}, max={self._max}"
                )
            self._used += tokens

    @property
    def remaining(self) -> int:
        return self._max - self._used
