"""Tests for engine/router.py — Priority Router."""

from __future__ import annotations

from agies.engine.router import (
    percentile,
    classify_card,
    classify_cards,
    map_max_iterations,
    validate_tool_call,
)


class TestPercentile:
    def test_empty(self):
        assert percentile([], 80) == 0.0

    def test_single_value(self):
        assert percentile([42], 80) == 42

    def test_even_distribution(self):
        values = [1, 2, 3, 4, 5]
        assert percentile(values, 0) == 1
        assert percentile(values, 40) == 2
        assert percentile(values, 80) == 4
        assert percentile(values, 100) == 5

    def test_duplicates(self):
        values = [5, 5, 5, 5, 5]
        assert percentile(values, 80) == 5

    def test_two_values(self):
        values = [10, 20]
        assert percentile(values, 50) == 10


class TestClassifyCard:
    def test_hot(self):
        assert classify_card(95, 80, 40) == "hot"
        assert classify_card(80, 80, 40) == "hot"

    def test_warm(self):
        assert classify_card(60, 80, 40) == "warm"
        assert classify_card(40, 80, 40) == "warm"

    def test_cold(self):
        assert classify_card(30, 80, 40) == "cold"
        assert classify_card(0, 80, 40) == "cold"


class TestClassifyCards:
    def test_empty(self):
        p80, p40 = classify_cards([])
        assert p80 == 0.0
        assert p40 == 0.0

    def test_small_set(self):
        scores = [1, 2, 3, 4, 5]
        p80, p40 = classify_cards(scores)
        assert p80 == 4  # 80th percentile
        assert p40 == 2  # 40th percentile

    def test_large_set(self):
        scores = list(range(1, 101))  # 1..100
        p80, p40 = classify_cards(scores)
        assert p80 == 80
        assert p40 == 40


class TestMapMaxIterations:
    def test_hot_default(self):
        assert map_max_iterations("hot") == 10

    def test_hot_custom_base(self):
        assert map_max_iterations("hot", 15) == 15
        assert map_max_iterations("hot", 20) == 20

    def test_warm(self):
        assert map_max_iterations("warm") == 3

    def test_cold(self):
        assert map_max_iterations("cold") == 0

    def test_unknown(self):
        assert map_max_iterations("unknown") == 0


class TestValidateToolCall:
    def test_valid_grep(self):
        assert validate_tool_call("grep_search", {"pattern": "foo"}) is None

    def test_grep_empty_pattern(self):
        result = validate_tool_call("grep_search", {"pattern": ""})
        assert result is not None
        assert "empty" in result.lower()

    def test_valid_read_file(self):
        assert validate_tool_call("read_file", {"file_path": "/tmp/test.py"}) is None

    def test_find_callers_valid(self):
        assert validate_tool_call("find_callers", {"name": "foo"}) is None

    def test_unknown_tool(self):
        assert validate_tool_call("unknown_tool", {}) is None
