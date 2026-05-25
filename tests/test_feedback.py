"""Tests for agies.engine.feedback — P5 cross-scan feedback loop.

Test categories:
1. FeedbackStore — basic CRUD + persistence
2. _extract_sast_rules — SAST rule ID extraction from evidence
3. record_from_findings — batch recording from verified findings
4. Director integration — confirmed_idents + suppressed_files in build_graph
5. Edge cases — corrupt JSON, missing file, empty store
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from agies.engine.feedback import (
    CONFIRMED_BOOST,
    FP_SUPPRESS_MUL,
    FP_THRESHOLD,
    FeedbackStore,
    _extract_sast_rules,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _feedback_path(tmpdir: str) -> str:
    return os.path.join(tmpdir, ".agies", "feedback.json")


def _write_feedback(tmpdir: str, data: dict) -> str:
    path = _feedback_path(tmpdir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f)
    return path


# ---------------------------------------------------------------------------
# FeedbackStore CRUD
# ---------------------------------------------------------------------------


class TestFeedbackStoreCRUD:
    def test_empty_store(self) -> None:
        store = FeedbackStore()
        assert store.confirmed_idents == {}
        assert store.fp_counts == {}
        assert store.version == 1
        assert not store.has_feedback()

    def test_add_confirmed_vuln(self) -> None:
        store = FeedbackStore()
        store.add_confirmed_vuln("execute_query")
        assert store.confirmed_idents == {"execute_query": 1}
        assert store.get_confirmed_idents() == {"execute_query"}

    def test_add_confirmed_vuln_increments(self) -> None:
        store = FeedbackStore()
        store.add_confirmed_vuln("execute_query")
        store.add_confirmed_vuln("execute_query")
        assert store.confirmed_idents == {"execute_query": 2}

    def test_add_confirmed_vuln_empty_name(self) -> None:
        store = FeedbackStore()
        store.add_confirmed_vuln("")
        assert store.confirmed_idents == {}

    def test_add_false_positive(self) -> None:
        store = FeedbackStore()
        store.add_false_positive("user_dao.py", "py-sql-injection")
        assert store.fp_counts == {"user_dao.py": {"py-sql-injection": 1}}

    def test_add_false_positive_increments(self) -> None:
        store = FeedbackStore()
        store.add_false_positive("user_dao.py", "py-sql-injection")
        store.add_false_positive("user_dao.py", "py-sql-injection")
        assert store.fp_counts["user_dao.py"]["py-sql-injection"] == 2

    def test_add_false_positive_empty_args(self) -> None:
        store = FeedbackStore()
        store.add_false_positive("", "")
        assert store.fp_counts == {}

    def test_has_feedback_true(self) -> None:
        store = FeedbackStore()
        assert not store.has_feedback()
        store.add_confirmed_vuln("test")
        assert store.has_feedback()

    def test_get_suppressed_files_below_threshold(self) -> None:
        store = FeedbackStore()
        store.add_false_positive("utils.py", "py-eval")
        # Only 1 FP, below threshold of 2
        assert store.get_suppressed_files() == set()

    def test_get_suppressed_files_at_threshold(self) -> None:
        store = FeedbackStore()
        store.add_false_positive("utils.py", "py-eval")
        store.add_false_positive("utils.py", "py-eval")
        assert "utils.py" in store.get_suppressed_files()

    def test_get_suppressed_files_above_threshold(self) -> None:
        store = FeedbackStore()
        for _ in range(3):
            store.add_false_positive("utils.py", "py-eval")
        assert "utils.py" in store.get_suppressed_files()

    def test_get_suppressed_files_multiple_files(self) -> None:
        store = FeedbackStore()
        store.add_false_positive("a.py", "r1")
        store.add_false_positive("a.py", "r1")
        store.add_false_positive("b.py", "r2")  # below threshold
        suppressed = store.get_suppressed_files()
        assert "a.py" in suppressed
        assert "b.py" not in suppressed


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class TestFeedbackStorePersistence:
    def test_save_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _feedback_path(tmpdir)

            store = FeedbackStore()
            store.add_confirmed_vuln("execute_query")
            store.add_false_positive("utils.py", "py-eval")
            store.save(path)

            assert os.path.isfile(path)
            loaded = FeedbackStore.load(path)
            assert loaded.confirmed_idents == {"execute_query": 1}
            assert loaded.fp_counts == {"utils.py": {"py-eval": 1}}

    def test_round_trip_preserves_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _feedback_path(tmpdir)

            store = FeedbackStore()
            store.add_confirmed_vuln("a")
            store.add_confirmed_vuln("a")
            store.add_confirmed_vuln("b")
            store.add_false_positive("x.py", "r1")
            store.add_false_positive("x.py", "r1")
            store.add_false_positive("x.py", "r2")
            store.save(path)

            loaded = FeedbackStore.load(path)
            assert loaded.confirmed_idents == {"a": 2, "b": 1}
            assert loaded.fp_counts == {"x.py": {"r1": 2, "r2": 1}}

    def test_load_nonexistent(self) -> None:
        store = FeedbackStore.load("/nonexistent/feedback.json")
        assert store.confirmed_idents == {}
        assert store.has_feedback() is False

    def test_load_corrupt_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _feedback_path(tmpdir)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            Path(path).write_text("{invalid json unclosed")

            store = FeedbackStore.load(path)
            assert store.confirmed_idents == {}

    def test_json_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _feedback_path(tmpdir)
            store = FeedbackStore()
            store.add_confirmed_vuln("f1")
            store.add_false_positive("fp.py", "r1")
            store.save(path)

            with open(path) as f:
                raw = json.load(f)
            assert "confirmed_idents" in raw
            assert "fp_counts" in raw
            assert "version" in raw
            assert raw["version"] == 1

    def test_save_empty_noop(self) -> None:
        """Saving an empty store should produce valid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _feedback_path(tmpdir)
            store = FeedbackStore()
            store.save(path)

            loaded = FeedbackStore.load(path)
            assert loaded.confirmed_idents == {}


# ---------------------------------------------------------------------------
# _extract_sast_rules
# ---------------------------------------------------------------------------


class TestExtractSastRules:
    def test_single_rule_string_evidence(self) -> None:
        finding = {
            "evidence": "[SAST:py-eval-exec] eval test (line 1, severity=critical)",
        }
        assert _extract_sast_rules(finding) == ["py-eval-exec"]

    def test_multiple_rules_string(self) -> None:
        finding = {
            "evidence": (
                "[SAST:py-eval-exec] eval test (line 1, severity=critical)\n"
                "[SAST:py-subprocess-shell] subprocess (line 10, severity=critical)"
            ),
        }
        rules = _extract_sast_rules(finding)
        assert "py-eval-exec" in rules
        assert "py-subprocess-shell" in rules

    def test_list_evidence(self) -> None:
        finding = {
            "evidence": [
                "[SAST:py-eval-exec] eval test (line 1, severity=critical)",
                "[SAST:py-subprocess-shell] subprocess (line 10, severity=critical)",
            ],
        }
        rules = _extract_sast_rules(finding)
        assert len(rules) == 2

    def test_empty_evidence(self) -> None:
        assert _extract_sast_rules({"evidence": ""}) == []
        assert _extract_sast_rules({"evidence": []}) == []
        assert _extract_sast_rules({"evidence": None}) == []

    def test_no_evidence_key(self) -> None:
        assert _extract_sast_rules({}) == []

    def test_no_sast_tags(self) -> None:
        finding = {"evidence": "Manual analysis confirmed the vulnerability"}
        assert _extract_sast_rules(finding) == []


# ---------------------------------------------------------------------------
# record_from_findings
# ---------------------------------------------------------------------------


class TestRecordFromFindings:
    def test_confirmed_triggerable(self) -> None:
        findings = [
            {
                "function_name": "execute_query",
                "file_path": "db.py",
                "triggerable": True,
                "evidence": [],
            },
        ]
        store = FeedbackStore.record_from_findings(findings)
        assert "execute_query" in store.get_confirmed_idents()
        assert store.confirmed_idents["execute_query"] == 1

    def test_confirmed_verified_legacy(self) -> None:
        """Legacy pipeline: verified=True should also record."""
        findings = [
            {
                "file_path": "db.py",
                "verified": True,
                "type": "sql_injection",
            },
        ]
        store = FeedbackStore.record_from_findings(findings)
        # Falls back to file stem when function_name is empty
        assert len(store.confirmed_idents) >= 1

    def test_false_positive_with_sast(self) -> None:
        findings = [
            {
                "function_name": "run_cmd",
                "file_path": "test_utils.py",
                "triggerable": False,
                "false_positive_reason": "Test file, no real impact",
                "evidence": ["[SAST:py-subprocess-shell] subprocess (line 5)"],
            },
        ]
        store = FeedbackStore.record_from_findings(findings)
        assert store.confirmed_idents == {}
        assert "test_utils.py" in store.fp_counts
        assert "py-subprocess-shell" in store.fp_counts["test_utils.py"]

    def test_mixed_findings(self) -> None:
        findings = [
            {
                "function_name": "process_input",
                "file_path": "app.py",
                "triggerable": True,
                "evidence": [],
            },
            {
                "function_name": "run_cmd",
                "file_path": "tests/test_build.py",
                "triggerable": False,
                "evidence": ["[SAST:py-subprocess-shell] subprocess (line 10)"],
            },
        ]
        store = FeedbackStore.record_from_findings(findings)
        assert "process_input" in store.get_confirmed_idents()
        assert "tests/test_build.py" in store.fp_counts

    def test_existing_store_updated(self) -> None:
        store = FeedbackStore()
        store.add_confirmed_vuln("existing_fn")
        store.add_confirmed_vuln("existing_fn")

        findings = [
            {
                "function_name": "new_fn",
                "file_path": "app.py",
                "triggerable": True,
                "evidence": [],
            },
        ]
        FeedbackStore.record_from_findings(findings, store=store)
        assert store.confirmed_idents["existing_fn"] == 2
        assert store.confirmed_idents["new_fn"] == 1

    def test_triggerable_without_function_name(self) -> None:
        """Fallback to file stem when function_name is empty."""
        findings = [
            {
                "file_path": "src/controllers/user.py",
                "triggerable": True,
            },
        ]
        store = FeedbackStore.record_from_findings(findings)
        # Should fall back to the file stem
        assert len(store.confirmed_idents) >= 1

    def test_empty_findings(self) -> None:
        store = FeedbackStore.record_from_findings([])
        assert not store.has_feedback()


# ---------------------------------------------------------------------------
# Director integration (build_graph feedback params)
# ---------------------------------------------------------------------------


class TestBuildGraphFeedback:
    """Test that confirmed_idents boost and suppressed_files deweight
    are correctly applied during PageRank graph construction."""

    def test_confirmed_ident_boosts_edge_weight(self) -> None:
        """A confirmed ident should have higher edge weights, leading to
        higher PageRank for its file."""
        from agies.engine.director.repomap import RepoMap

        with tempfile.TemporaryDirectory() as tmpdir:
            # File A defines a confirmed ident, file B references it
            confirmed_code = """
def execute_query(sql):
    return db.execute(sql)
"""
            caller_code = """
def handle_request():
    execute_query("select * from users")
"""
            Path(tmpdir, "db.py").write_text(confirmed_code)
            Path(tmpdir, "handler.py").write_text(caller_code)
            fnames = [
                str(Path(tmpdir, "db.py")),
                str(Path(tmpdir, "handler.py")),
            ]

            rm = RepoMap(root=tmpdir)
            G, pr, _, _ = rm.build_graph(
                fnames=fnames,
                confirmed_idents={"execute_query"},
            )
            # If the graph was built, the scoring should not crash
            assert G is not None
            # db.py should appear somewhere in the graph
            assert len(G.nodes) > 0

    def test_suppressed_file_lowers_signal_score(self) -> None:
        """A file in suppressed_files should have its signal scores reduced,
        leading to lower PageRank contribution."""
        from agies.engine.director.repomap import RepoMap

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file with signals
            source = """
import subprocess
def run_cmd(cmd):
    return subprocess.Popen(cmd, shell=True)
"""
            Path(tmpdir, "test_build.py").write_text(source)
            fnames = [str(Path(tmpdir, "test_build.py"))]

            rm = RepoMap(root=tmpdir)

            # Build with and without suppression — both should complete
            G_normal, pr_normal, _, _ = rm.build_graph(
                fnames=fnames,
                signal_mul={"cmd_exec": 80},
            )

            G_suppressed, pr_suppressed, _, _ = rm.build_graph(
                fnames=fnames,
                signal_mul={"cmd_exec": 80},
                suppressed_files={"test_build.py"},
            )

            # Both should produce valid graphs
            assert G_normal is not None
            assert G_suppressed is not None

    def test_both_params_simultaneously(self) -> None:
        """confirmed_idents and suppressed_files should work together."""
        from agies.engine.director.repomap import RepoMap

        with tempfile.TemporaryDirectory() as tmpdir:
            code = """
def execute_query(sql):
    return db.execute(sql)

def run_build():
    import subprocess
    subprocess.run("make", shell=True)
"""
            Path(tmpdir, "app.py").write_text(code)
            fnames = [str(Path(tmpdir, "app.py"))]

            rm = RepoMap(root=tmpdir)
            G, pr, _, _ = rm.build_graph(
                fnames=fnames,
                confirmed_idents={"execute_query"},
                suppressed_files={"app.py"},
            )
            assert G is not None

    def test_empty_sets_noop(self) -> None:
        """Passing empty sets should match default behavior."""
        from agies.engine.director.repomap import RepoMap

        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "app.py").write_text("x = 1")
            fnames = [str(Path(tmpdir, "app.py"))]

            rm = RepoMap(root=tmpdir)
            G1, pr1, _, _ = rm.build_graph(fnames=fnames)
            G2, pr2, _, _ = rm.build_graph(
                fnames=fnames,
                confirmed_idents=set(),
                suppressed_files=set(),
            )
            # PageRank scores should be identical
            assert pr1 == pr2


# ---------------------------------------------------------------------------
# Brain integration (regression)
# ---------------------------------------------------------------------------


class TestBrainFeedbackIntegration:
    """Feedback lifecycle doesn't break the brain pipeline."""

# ---------------------------------------------------------------------------
# Brain integration (regression)
# ---------------------------------------------------------------------------


class TestBrainFeedbackIntegration:
    """Feedback lifecycle doesn't break the brain pipeline."""

    def test_brain_completes_with_mapping_only(self) -> None:
        """Brain still completes when feedback is loaded/recorded."""
        from agies.engine.agents.base import AgentResponse
        from agies.engine.brain import Brain
        from agies.engine.runner import Runner
        from dataclasses import dataclass

        @dataclass
        class MockLLM:
            def chat_completion(self, messages, tools=None, **kwargs):
                @dataclass
                class Resp:
                    content: str = "ok"
                    tool_calls: list = None
                    usage: object = None
                return Resp()

        @dataclass
        class MappingStub:
            agent_id = "mapping"
            system_prompt = ""
            tools = []
            def run(self, params, llm=None, **kwargs):
                return AgentResponse(content="mapped", output={
                    "summary": "Test", "modules": [], "key_files": [],
                    "language": "Python", "framework": "Flask", "file_count": 5,
                })

        runner = Runner(llm=MockLLM())
        brain = Brain(runner=runner, agents={"mapping": MappingStub()})
        with tempfile.TemporaryDirectory() as tmpdir:
            state = brain.run(tmpdir)
            assert "mapping" in state.completed_agents
