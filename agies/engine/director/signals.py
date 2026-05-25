"""Signal weight configuration for risk-weighted PageRank.

SIGNAL_MUL defines how much each SAST signal type amplifies a function's
importance in the PageRank graph.  These are applied as multipliers on
edges involving functions that emit the given signal.

Negative signals (mul <= 0.3) suppress a function's importance — e.g.
test code, dead code, and pure helpers.
"""

SIGNAL_MUL: dict[str, float] = {
    # Entry point bonus (applied separately via mul=100 in repomap.py)
    "entry_point": 100,
    # High-risk SAST signals
    "sql_sink": 80,
    "cmd_exec": 80,
    "dynamic_exec": 80,
    # Critical sink pre-scan (100x boost — applied via personalization
    # in build_graph, defined here for consistency)
    "critical_sink": 500,
    # Medium-risk
    "file_io": 10,
    "serialization": 20,
    "network_operation": 5,
    "recursion": 30,
    # Low-risk / informational
    "regex_operation": 15,
    "crypto_operation": 5,
    "auth_check": 20,
    # Negative signals — these suppress importance
    "test_code": 0.0,
    "dead_code": 0.1,
    "pure_helper": 0.3,
}


def compute_confidence(hit_count: int, risk_weight: float) -> float:
    """Compute a confidence score from signal hit count and risk weight.

    The more times a signal fires, the more confident we are in its
    importance.  Lightly-hit signals get discounted.
    """
    if hit_count >= 5:
        return risk_weight * 1.0
    if hit_count >= 2:
        return risk_weight * 0.7
    return risk_weight * 0.3


def has_negative_signal(signal_type: str) -> bool:
    """Return True if *signal_type* suppresses importance."""
    return SIGNAL_MUL.get(signal_type, 1.0) <= 0.3
