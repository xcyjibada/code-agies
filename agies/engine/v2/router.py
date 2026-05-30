"""Priority Router — budget-aware task gating between Brain and Runner.

The Router is a stateless "traffic gate" that:
1. Computes dynamic percentile thresholds for card classification
2. Maps risk scores to LLM iteration budgets (hot/warm/cold)
3. Tracks token consumption and enforces budget limits (QuotaMonitor)
4. Validates tool call parameters before they reach the LLM (CrashDefender)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default model cost rates (per 1K tokens, USD)
# ---------------------------------------------------------------------------
# These are approximate; override via QuotaMonitor(cost_per_1k_input=...)
# DeepSeek-chat (default), rates as of 2026-05
DEFAULT_COST_PER_1K_INPUT = 0.00015
DEFAULT_COST_PER_1K_OUTPUT = 0.0006


# ---------------------------------------------------------------------------
# Percentile (pure Python, no numpy)
# ---------------------------------------------------------------------------


def percentile(values: list[float], pct: float) -> float:
    """Pure-Python percentile calculation.

    Parameters
    ----------
    values : list[float]
        Non-empty list of numeric scores.
    pct : float
        Percentile to compute (0-100).  E.g. 80 = 80th percentile.

    Returns
    -------
    float
        The value at the given percentile.  Returns 0.0 for empty input.
    """
    if not values:
        return 0.0
    sorted_v = sorted(values)
    n = len(sorted_v)
    # Use (n-1) interpolation so p80 of [1,2,3,4,5] = 4 (value at index 3)
    idx = int((n - 1) * pct / 100)
    idx = max(0, min(idx, n - 1))
    return sorted_v[idx]


# ---------------------------------------------------------------------------
# Card classification
# ---------------------------------------------------------------------------

CARD_CLASS_HOT = "hot"
CARD_CLASS_WARM = "warm"
CARD_CLASS_COLD = "cold"

HOT_PCT = 80     # top 20 % → hot
WARM_PCT = 40    # 40 %–80 % → warm
# bottom 40 % → cold


def classify_card(
    score: float,
    p80: float,
    p40: float,
) -> str:
    """Classify a single card by its final_score.

    Returns ``"hot"``, ``"warm"``, or ``"cold"``.
    """
    if score >= p80:
        return CARD_CLASS_HOT
    elif score >= p40:
        return CARD_CLASS_WARM
    return CARD_CLASS_COLD


def classify_cards(
    scores: list[float],
) -> tuple[float, float]:
    """Compute dynamic thresholds for card classification.

    Parameters
    ----------
    scores : list[float]
        All ``final_score`` values from ``analysis_cards``.

    Returns
    -------
    (p80, p40) : tuple[float, float]
        The 80th and 40th percentile thresholds.
        Both return 0.0 for empty input.
    """
    if not scores:
        return (0.0, 0.0)
    p80 = percentile(scores, HOT_PCT)
    p40 = percentile(scores, WARM_PCT)
    return (p80, p40)


# ---------------------------------------------------------------------------
# Urgency Evaluator — map card class to LLM iteration budget
# ---------------------------------------------------------------------------

def map_max_iterations(
    card_class: str,
    base_iterations: int = 10,
) -> int:
    """Map card classification to max LLM tool-loop iterations.

    - hot:  full depth (base_iterations)
    - warm: shallow (3 iterations)
    - cold: 0 (no LLM dispatch)
    """
    return {
        CARD_CLASS_HOT: base_iterations,
        CARD_CLASS_WARM: 3,
        CARD_CLASS_COLD: 0,
    }.get(card_class, 0)


# ---------------------------------------------------------------------------
# QuotaMonitor — token budget enforcement
# ---------------------------------------------------------------------------


class QuotaMonitor:
    """Real-time token budget monitor.

    Tracks cumulative token consumption across all agents and computes
    estimated USD cost.  When the budget is exhausted, ``is_budget_exhausted()``
    returns ``True`` and the Brain should stop submitting new tasks.

    Usage::

        quota = QuotaMonitor(budget_usd=5.0)
        quota.record_usage(input_tokens=500, output_tokens=200)
        if quota.is_budget_exhausted():
            logger.warning("Budget exhausted, stopping.")
    """

    def __init__(
        self,
        budget_usd: float = 0.0,
        cost_per_1k_input: float = DEFAULT_COST_PER_1K_INPUT,
        cost_per_1k_output: float = DEFAULT_COST_PER_1K_OUTPUT,
    ) -> None:
        self.budget_usd = budget_usd
        self.cost_per_1k_input = cost_per_1k_input
        self.cost_per_1k_output = cost_per_1k_output

        self.input_tokens: int = 0
        self.output_tokens: int = 0
        self.total_cost_usd: float = 0.0

    def record_usage(self, input_tokens: int, output_tokens: int) -> None:
        """Record token usage from one agent run and accumulate cost."""
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.total_cost_usd += (
            input_tokens / 1000 * self.cost_per_1k_input
            + output_tokens / 1000 * self.cost_per_1k_output
        )
        logger.debug(
            "Quota: +%d in / +%d out = $%.6f (total $%.6f / $%.2f)",
            input_tokens,
            output_tokens,
            input_tokens / 1000 * self.cost_per_1k_input
            + output_tokens / 1000 * self.cost_per_1k_output,
            self.total_cost_usd,
            self.budget_usd,
        )

    def is_budget_exhausted(self) -> bool:
        """Return ``True`` if total cost has exceeded the budget."""
        if self.budget_usd <= 0:
            return False  # 0 or negative = unlimited
        return self.total_cost_usd >= self.budget_usd

    def remaining_budget(self) -> float:
        """Return remaining budget in USD (negative if over-budget)."""
        if self.budget_usd <= 0:
            return float("inf")
        return max(0.0, self.budget_usd - self.total_cost_usd)

    def summary(self) -> str:
        """Human-readable budget summary."""
        if self.budget_usd <= 0:
            return (
                f"Quota: {self.input_tokens} in / {self.output_tokens} out "
                f"= ${self.total_cost_usd:.6f} (unlimited budget)"
            )
        return (
            f"Quota: {self.input_tokens} in / {self.output_tokens} out "
            f"= ${self.total_cost_usd:.4f} / ${self.budget_usd:.2f} "
            f"({self.total_cost_usd / self.budget_usd * 100:.0f}% used)"
        )


# ---------------------------------------------------------------------------
# Tool parameter validation (Crash Defender)
# ---------------------------------------------------------------------------

TOOL_PARAM_RULES: dict[str, dict[str, tuple]] = {
    "grep_search": {"pattern": (str,), "glob": (str, type(None))},
    "read_file": {"file_path": (str,)},
    "list_directory": {"path": (str, type(None))},
    "lookup_function": {"name": (str,)},
    "find_callers": {"name": (str,)},
    "find_callees": {"name": (str,)},
}


def validate_tool_call(tool_name: str, kwargs: dict[str, Any]) -> str | None:
    """Validate tool call parameters.  Returns ``None`` if valid, error string if not.

    Checks:
    - Required params exist and are non-empty strings.
    - No extra unknown params (LLMs often hallucinate them).

    This is called at the tool function entry point (``tools/search.py`` etc.),
    not at the Router layer.
    """
    rules = TOOL_PARAM_RULES.get(tool_name)
    if rules is None:
        return None  # unknown tool — let it pass

    for param, expected_types in rules.items():
        val = kwargs.get(param)
        if val is None:
            continue  # optional param
        if not isinstance(val, expected_types):
            return (
                f"Tool '{tool_name}': param '{param}' has wrong type "
                f"{type(val).__name__}, expected {expected_types}"
            )
        if isinstance(val, str) and not val.strip():
            return f"Tool '{tool_name}': param '{param}' is empty string"

    return None
