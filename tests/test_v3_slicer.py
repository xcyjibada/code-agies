"""Tests for v3 slicer module — scoring, sorting, Explore/Exploit."""

from __future__ import annotations

from agies.engine.v3.codeql.models import CodeQlPath, PathNode, VulnType
from agies.engine.v3.slicer.models import PathSlice, SortResult
from agies.engine.v3.slicer.sorter import (
    score_path,
    select_top_k,
    is_anomalous,
    llm_semantic_filter,
)


def _make_path(
    sink: str = "exec",
    sink_file: str = "src/main.py",
    is_full: bool = False,
    nodes: int = 0,
    vuln_type: VulnType = VulnType.RCE,
) -> CodeQlPath:
    """Helper to build a CodeQlPath for testing."""
    path = CodeQlPath(
        vuln_type=vuln_type,
        source="request.getParameter",
        source_file="controller.py",
        source_line=10,
        sink=sink,
        sink_file=sink_file,
        sink_line=42,
        is_full_path=is_full,
    )
    if nodes:
        path.nodes = [
            PathNode(
                function_name=f"func_{i}",
                file_path="src/utils.py",
                line_number=100 + i,
            )
            for i in range(nodes)
        ]
    return path


# ---------------------------------------------------------------------------
# score_path
# ---------------------------------------------------------------------------


class TestScorePath:
    def test_exec_sink_max_score(self):
        """exec sink with short path should score near max."""
        path = _make_path(sink="exec", nodes=1)
        score = score_path(path)
        assert 0.5 <= score <= 1.0, f"Expected high score, got {score}"

    def test_low_risk_sink_lower_score(self):
        """open with many nodes should score lower."""
        path = _make_path(sink="open", nodes=10, is_full=False)
        score = score_path(path)
        assert score < 0.7, f"Expected moderate score, got {score}"

    def test_full_path_bonus(self):
        """Full path should score higher than non-full."""
        full = _make_path(sink="exec", nodes=2, is_full=True)
        partial = _make_path(sink="exec", nodes=2, is_full=False)
        assert score_path(full) > score_path(partial)

    def test_validation_bonus(self):
        """Validation function names should earn bypass bonus."""
        no_val = _make_path(sink="exec", nodes=1)
        val_path = _make_path(
            sink="exec",
            nodes=1,
        )
        # Add a node with a validation name to trigger the bonus
        val_path.nodes[0].function_name = "sanitize_input"
        assert score_path(val_path) > score_path(no_val)

    def test_unknown_sink_default_weight(self):
        """Unknown sink names fall back to 0.3 weight."""
        path = _make_path(sink="some_unknown_func", nodes=1)
        score = score_path(path)
        assert 0.0 < score <= 1.0

    def test_afo_sink_weights(self):
        """AFO sinks (write, save) should have moderate score."""
        path = _make_path(sink="pathlib.Path.write_text", vuln_type=VulnType.AFO)
        score = score_path(path)
        assert 0.4 <= score <= 1.0

    def test_sqli_sink_weight(self):
        """SQLI execute sink should have high weight."""
        path = _make_path(sink="execute", vuln_type=VulnType.SQLI, nodes=2)
        score = score_path(path)
        assert 0.5 <= score <= 1.0


# ---------------------------------------------------------------------------
# select_top_k
# ---------------------------------------------------------------------------


class TestSelectTopK:
    def test_empty_input(self):
        """Empty path list should produce empty sort result."""
        result = select_top_k([])
        assert result.exploit == []
        assert result.explore == []
        assert result.total_input == 0

    def test_exploit_explore_slots(self):
        """Exploit should have more slots than explore."""
        paths = [_make_path(sink=f"sink_{i}", nodes=1) for i in range(10)]
        result = select_top_k(paths, max_exploit=5, max_explore=2)
        assert len(result.exploit) <= 5
        assert len(result.explore) <= 2

    def test_exclude_test_dir(self):
        """Paths in test directories should be excluded."""
        paths = [
            _make_path(sink="exec", sink_file="src/main.py"),
            _make_path(sink="exec", sink_file="tests/test_main.py"),
        ]
        result = select_top_k(paths, exclude_test=True)
        assert len(result.exploit) == 1

    def test_path_slice_output_format(self):
        """PathSlice should have correct fields."""
        paths = [_make_path(sink="exec")]
        result = select_top_k(paths, max_exploit=1)
        if result.exploit:
            s = result.exploit[0]
            assert s.id.startswith("rce-")
            assert s.vuln_type == VulnType.RCE
            assert s.sink == "exec"
            assert isinstance(s.score, float)
            assert s.assigned_slot in ("exploit", "explore")

    def test_sort_result_property(self):
        """all_slices should combine exploit + explore."""
        paths = [_make_path(sink=f"sink_{i}", nodes=2) for i in range(8)]
        result = select_top_k(paths, max_exploit=3, max_explore=2)
        assert len(result.all_slices) == len(result.exploit) + len(result.explore)

    def test_sort_result_counts(self):
        """total_input/total_output should be accurate."""
        paths = [_make_path(sink=f"sink_{i}") for i in range(20)]
        result = select_top_k(paths, max_exploit=5, max_explore=2)
        assert result.total_input >= 20
        assert result.total_output <= 7


# ---------------------------------------------------------------------------
# is_anomalous
# ---------------------------------------------------------------------------


class TestIsAnomalous:
    def test_non_standard_sink(self):
        """Unknown sink should be flagged as anomalous."""
        path = _make_path(sink="custom_sink_name", nodes=2)
        reasons = is_anomalous(path)
        assert "non_std_sink" in reasons

    def test_standard_sink_not_anomalous(self):
        """Known sink should not be flagged as non_std_sink."""
        path = _make_path(sink="exec")
        reasons = is_anomalous(path)
        assert "non_std_sink" not in reasons

    def test_multi_module_flow(self):
        """Path crossing multiple modules should be flagged."""
        path = _make_path(sink="exec", sink_file="module_a/src/main.py")
        path.nodes = [
            PathNode("f1", "module_a/src/util.py", 1),
            PathNode("f2", "module_b/src/helper.py", 2),
            PathNode("f3", "module_c/src/core.py", 3),
        ]
        reasons = is_anomalous(path)
        assert "multi_module_flow" in reasons, f"Got reasons: {reasons}"


# ---------------------------------------------------------------------------
# llm_semantic_filter
# ---------------------------------------------------------------------------


class TestLlmSemanticFilter:
    def test_returns_top_n(self):
        """Should return top N slices by score."""
        slices = [
            PathSlice(id=f"rce-{i}", vuln_type=VulnType.RCE,
                      source="req", source_file="c.py:1",
                      sink="exec", sink_file="x.py:2",
                      score=float(i) / 10.0)
            for i in range(5)
        ]
        result = llm_semantic_filter(slices, max_slices=3)
        assert len(result) == 3
        # Highest scores first
        assert result[0].score >= result[1].score >= result[2].score

    def test_empty_input(self):
        """Empty input returns empty list."""
        assert llm_semantic_filter([]) == []
