"""Token usage counter with quota enforcement.

Thread-safe accumulator for LLM token usage across the v3 pipeline.
Provides a ``QuotaExceededException`` that halts processing when the
configured budget is exceeded — preventing runaway token spend during
large-scale parallel audits.
"""

from __future__ import annotations

import threading


class QuotaExceededException(Exception):
    """Raised when the token budget has been exceeded."""

    def __init__(
        self,
        total_used: int,
        budget: int,
    ) -> None:
        self.total_used = total_used
        self.budget = budget
        super().__init__(
            f"Token budget exceeded: {total_used}/{budget} tokens used"
        )


class TokenCounter:
    """Thread-safe token usage accumulator.

    Usage::

        counter = TokenCounter(budget=1_000_000)
        try:
            counter.add(prompt_tokens=150, completion_tokens=50)
        except QuotaExceededException:
            # Halt pipeline
            ...
    """

    def __init__(self, budget: int = 1_000_000) -> None:
        self._lock = threading.Lock()
        self._budget = budget
        self._prompt_tokens = 0
        self._completion_tokens = 0
        self._total_tokens = 0

    @property
    def budget(self) -> int:
        return self._budget

    @property
    def total_tokens(self) -> int:
        with self._lock:
            return self._total_tokens

    @property
    def prompt_tokens(self) -> int:
        with self._lock:
            return self._prompt_tokens

    @property
    def completion_tokens(self) -> int:
        with self._lock:
            return self._completion_tokens

    def add(
        self,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: int = 0,
    ) -> None:
        """Accumulate token usage and check quota.

        Raises ``QuotaExceededException`` if the cumulative total exceeds
        the configured budget after this addition.
        """
        with self._lock:
            self._prompt_tokens += prompt_tokens
            self._completion_tokens += completion_tokens
            self._total_tokens += total_tokens or (prompt_tokens + completion_tokens)

            if self._budget > 0 and self._total_tokens > self._budget:
                raise QuotaExceededException(self._total_tokens, self._budget)

    def __repr__(self) -> str:
        with self._lock:
            return (
                f"TokenCounter(total={self._total_tokens}, "
                f"prompt={self._prompt_tokens}, "
                f"completion={self._completion_tokens}, "
                f"budget={self._budget})"
            )
