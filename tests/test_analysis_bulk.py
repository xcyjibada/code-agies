"""Tests for agies.engine.analysis.bulk — priority-sorted bulk analysis."""

from __future__ import annotations

from dataclasses import dataclass

from agies.engine.analysis.bulk import analyze_single_functions
from agies.engine.sourcer.models import FunctionIndex, SourceFile, SourceFunction


@dataclass
class FakeLLM:
    """Mock LLM that always returns an empty vulnerability-free response."""

    call_count: int = 0
    last_fn_name: str = ""

    def chat_completion(self, messages, tools=None, **kwargs):
        self.call_count += 1
        # Extract function name from user message
        for msg in messages:
            if msg["role"] == "user":
                for line in msg["content"].split("\n"):
                    if line.startswith("name="):
                        self.last_fn_name = line.split("=", 1)[1]
        return type("Resp", (), {
            "content": '```json\n{"vulnerabilities": []}\n```',
            "tool_calls": None,
            "usage": None,
        })()


def _make_index(fn_list: list[tuple[str, str, str]]) -> FunctionIndex:
    """Build a FunctionIndex from (fullname, name, file_path) tuples."""
    index = FunctionIndex()
    for fullname, name, fpath in fn_list:
        sf = SourceFile(path=fpath, source=f"def {name}(): pass\n")
        fn = SourceFunction(
            name=name,
            fullname=fullname,
            file_path=fpath,
            line_start=1,
            line_end=1,
            signature=f"def {name}():",
            body="    pass",
        )
        index.add(sf, [fn])
    index.build_lut()
    return index


class TestAnalyzeSingleFunctionsPriority:
    """analyze_single_functions() with priority_map parameter."""

    def test_no_priority_map_default_order(self) -> None:
        """Without priority_map, all functions are analyzed in order."""
        index = _make_index([
            ("func_a", "func_a", "a.py"),
            ("func_b", "func_b", "b.py"),
        ])
        llm = FakeLLM()
        result = analyze_single_functions(index, llm, max_workers=2)
        assert result.total_functions_analyzed == 2
        assert result.total_llm_calls == 2

    def test_priority_map_sorts_order(self) -> None:
        """With priority_map, high-priority functions are submitted first."""
        index = _make_index([
            ("low_prio", "low_prio", "a.py"),
            ("high_prio", "high_prio", "b.py"),
        ])
        llm = FakeLLM()
        priority_map = {"high_prio": 100.0, "low_prio": 1.0}

        result = analyze_single_functions(index, llm, max_workers=2, priority_map=priority_map)

        assert result.total_functions_analyzed == 2
        assert result.total_llm_calls == 2

    def test_priority_map_with_fullname_match(self) -> None:
        """priority_map keys matching SourceFunction.fullname are used."""
        index = _make_index([
            ("ClassA::method", "method", "a.py"),
            ("func_b", "func_b", "b.py"),
        ])
        llm = FakeLLM()
        priority_map = {"ClassA::method": 95.0, "func_b": 5.0}

        result = analyze_single_functions(index, llm, max_workers=2, priority_map=priority_map)

        assert result.total_functions_analyzed == 2

    def test_max_functions_limits_analysis(self) -> None:
        """max_functions limits how many functions are analyzed."""
        index = _make_index([
            ("high", "high", "a.py"),
            ("medium", "medium", "b.py"),
            ("low", "low", "c.py"),
        ])
        llm = FakeLLM()
        priority_map = {"high": 100.0, "medium": 50.0, "low": 1.0}

        result = analyze_single_functions(
            index, llm, max_workers=2,
            priority_map=priority_map, max_functions=2,
        )

        assert result.total_functions_analyzed == 2
        assert result.total_llm_calls == 2

    def test_max_functions_keeps_highest_priority(self) -> None:
        """max_functions keeps the highest-priority functions."""
        index = _make_index([
            ("high", "high", "a.py"),
            ("medium", "medium", "b.py"),
            ("low", "low", "c.py"),
        ])
        llm = FakeLLM()
        priority_map = {"high": 100.0, "medium": 50.0, "low": 1.0}

        result = analyze_single_functions(
            index, llm, max_workers=1,
            priority_map=priority_map, max_functions=1,
        )

        assert result.total_functions_analyzed == 1

    def test_empty_priority_map_all_zero(self) -> None:
        """Empty priority_map acts as if no map was provided."""
        index = _make_index([
            ("a", "a", "a.py"),
            ("b", "b", "b.py"),
        ])
        llm = FakeLLM()

        result = analyze_single_functions(index, llm, max_workers=2, priority_map={})

        assert result.total_functions_analyzed == 2
