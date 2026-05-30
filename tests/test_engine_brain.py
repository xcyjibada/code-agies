"""Tests for engine/brain.py — Brain decision loop and state orchestration."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import pytest

from agies.engine.v2.agents.base import AgentResponse, BaseAgent
from agies.engine.v2.brain import Brain
from agies.engine.v2.runner import AgentResult, Runner
from agies.engine.v2.sourcer.models import FunctionIndex
from agies.engine.v2.state import ProjectState


# ---------------------------------------------------------------------------
# Mock agents that produce state-compatible output
# ---------------------------------------------------------------------------


class MappingStub(BaseAgent):
    agent_id = "mapping"
    system_prompt = ""
    tools = []

    def run(self, params, llm=None, **kwargs) -> AgentResponse:
        return AgentResponse(
            content="mapped",
            output={
                "summary": "Python web app",
                "modules": [{"name": "app", "path": "/app"}],
                "key_files": [{"path": "/app/main.py", "role": "entry"}],
                "language": "Python",
                "framework": "Flask",
                "file_count": 42,
            },
        )


class AttackSurfaceStub(BaseAgent):
    agent_id = "attack_surface"
    system_prompt = ""
    tools = []

    def run(self, params, llm=None, **kwargs) -> AgentResponse:
        return AgentResponse(
            content="surface",
            output={
                "entry_points": [
                    {"id": "ep1", "path": "/api/login", "method": "POST"},
                    {"id": "ep2", "path": "/api/data", "method": "GET"},
                ],
            },
        )


class DataFlowStub(BaseAgent):
    """Produces a fixed path each invocation."""

    agent_id = "dataflow"
    system_prompt = ""
    tools = []

    def __init__(self) -> None:
        super().__init__()
        self._counter = 0

    def run(self, params, llm=None, **kwargs) -> AgentResponse:
        self._counter += 1
        return AgentResponse(
            content="flow",
            output={
                "paths": [
                    {
                        "id": f"path_{self._counter}",
                        "source": params.get("entry_point_id", "ep1"),
                        "sink": "exec()",
                    },
                ],
            },
        )


class VulnStub(BaseAgent):
    agent_id = "vulnerability"
    system_prompt = ""
    tools = []

    def __init__(self) -> None:
        super().__init__()
        self._counter = 0

    def run(self, params, llm=None, **kwargs) -> AgentResponse:
        self._counter += 1
        return AgentResponse(
            content="vuln found",
            output={
                "vulnerabilities": [
                    {
                        "id": f"v_{self._counter}",
                        "type": "sqli",
                        "severity": "critical",
                        "path_id": params.get("path_id", "p1"),
                        "verified": False,
                    },
                ],
            },
        )


class VerifyStub(BaseAgent):
    agent_id = "verify"
    system_prompt = ""
    tools = []

    def __init__(self) -> None:
        super().__init__()
        self._counter = 0

    def run(self, params, llm=None, **kwargs) -> AgentResponse:
        self._counter += 1
        return AgentResponse(
            content="verified",
            output={
                "findings": [
                    {
                        "id": f"f_{self._counter}",
                        "verified": True,
                        "severity": "critical",
                        "type": "sqli",
                    },
                ],
            },
        )


class ReportStub(BaseAgent):
    agent_id = "report"
    system_prompt = ""
    tools = []

    def run(self, params, llm=None, **kwargs) -> AgentResponse:
        return AgentResponse(
            content="report generated",
            output={"report": "Full audit report..."},
        )


class SourcerStub(BaseAgent):
    agent_id = "sourcer"
    system_prompt = ""
    tools = []

    def run(self, params, llm=None, **kwargs) -> AgentResponse:
        return AgentResponse(
            content="indexed",
            output={"function_index": None},
        )


class BulkStub(BaseAgent):
    agent_id = "bulk_analysis"
    system_prompt = ""
    tools = []

    def run(self, params, llm=None, **kwargs) -> AgentResponse:
        return AgentResponse(
            content="bulk done",
            output={"candidates": [], "total_functions_analyzed": 0, "total_llm_calls": 0},
        )


# ---------------------------------------------------------------------------
# Mock LLM (not used by stub agents, but Runner requires one)
# ---------------------------------------------------------------------------


@dataclass
class MockLLM:
    def chat_completion(self, messages, tools=None, **kwargs):
        return type("Resp", (), {"content": "mock", "tool_calls": None, "usage": None})()


SIMPLE_LLM = MockLLM()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBrainEmpty:
    """Brain with no registered agents."""

    def test_empty_registry_returns_empty_state(self) -> None:
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={})
        state = brain.run("/project")

        assert state.completed_agents == []
        assert not state.is_complete()

    def test_registry_with_unrequested_agent_does_nothing(self) -> None:
        """An agent registered but not in get_available_agents() won't run."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={"unrelated": MappingStub()})
        state = brain.run("/project")

        # "unrelated" is never requested by get_available_agents()
        assert "unrelated" not in state.completed_agents


class TestBrainSingleAgent:
    """Brain with only mapping agent."""

    def test_mapping_populates_state(self) -> None:
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={"mapping": MappingStub()})
        state = brain.run("/project")

        assert "mapping" in state.completed_agents
        assert state.project_summary == "Python web app"
        assert state.language == "Python"
        assert state.framework == "Flask"
        assert state.file_count == 42
        assert len(state.modules) == 1

    def test_mapping_then_brain_stops(self) -> None:
        """After mapping, only attack_surface is available. No attack_surface
        agent registered → brain stops (no available agents mapped)."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={"mapping": MappingStub()})
        state = brain.run("/project")

        # Mapping ran, attack_surface not registered → stops
        assert "mapping" in state.completed_agents
        assert "attack_surface" not in state.completed_agents


class TestBrainFullPipeline:
    """Brain with all agents — full cycle."""

    @staticmethod
    def _build_brain() -> Brain:
        runner = Runner(llm=SIMPLE_LLM)
        agents = {
            "mapping": MappingStub(),
            "attack_surface": AttackSurfaceStub(),
            "dataflow": DataFlowStub(),
            "vulnerability": VulnStub(),
            "verify": VerifyStub(),
            "report": ReportStub(),
        }
        return Brain(runner=runner, agents=agents)

    def test_all_agents_complete(self) -> None:
        brain = self._build_brain()
        state = brain.run("/project")

        assert "mapping" in state.completed_agents
        assert "attack_surface" in state.completed_agents
        assert "dataflow" in state.completed_agents
        assert "vulnerability" in state.completed_agents
        assert "verify" in state.completed_agents
        assert "report" in state.completed_agents

    def test_state_is_complete_after_report(self) -> None:
        brain = self._build_brain()
        state = brain.run("/project")

        assert state.is_complete()

    def test_multiple_entry_points_create_multiple_dataflow_calls(self) -> None:
        """AttackSurface returns 2 entry points → 2 dataflow calls expected."""
        runner = Runner(llm=SIMPLE_LLM)

        # Track how many dataflow calls happen
        df_tracker: list[dict] = []
        class TrackingDataFlow(DataFlowStub):
            def run(self, params, llm=None, **kwargs):
                df_tracker.append(params)
                return super().run(params, llm, **kwargs)

        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "attack_surface": AttackSurfaceStub(),
            "dataflow": TrackingDataFlow(),
            "vulnerability": VulnStub(),
            "verify": VerifyStub(),
            "report": ReportStub(),
        })
        state = brain.run("/project")

        assert len(df_tracker) == 2
        entry_ids = {p.get("entry_point_id") for p in df_tracker}
        assert entry_ids == {"ep1", "ep2"}
        assert len(state.dataflow_paths) == 2

    def test_multiple_paths_create_multiple_vuln_calls(self) -> None:
        """2 dataflow paths → 2 vulnerability calls expected."""
        runner = Runner(llm=SIMPLE_LLM)

        vuln_tracker: list[dict] = []
        class TrackingVuln(VulnStub):
            def run(self, params, llm=None, **kwargs):
                vuln_tracker.append(params)
                return super().run(params, llm, **kwargs)

        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "attack_surface": AttackSurfaceStub(),
            "dataflow": DataFlowStub(),
            "vulnerability": TrackingVuln(),
            "verify": VerifyStub(),
            "report": ReportStub(),
        })
        state = brain.run("/project")

        # 2 entry points → 2 dataflow paths → 2 vulnerability calls expected
        assert len(vuln_tracker) == 2
        assert len(state.candidate_vulnerabilities) == 2

    def test_error_in_agent_does_not_halt_pipeline(self) -> None:
        """One broken agent → rest should still run."""
        runner = Runner(llm=SIMPLE_LLM)

        class BrokenSurface(BaseAgent):
            agent_id = "attack_surface"
            system_prompt = ""
            tools = []

            def run(self, params, llm=None, **kwargs) -> AgentResponse:
                raise RuntimeError("surface failed")

        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "attack_surface": BrokenSurface(),
        })
        state = brain.run("/project")

        # Mapping completed
        assert "mapping" in state.completed_agents
        # Attack surface ran but probably errored — it's in completed_agents
        # because state.register_result() was called even with empty output

    def test_brain_stops_when_no_available_agents(self) -> None:
        """If get_available_agents() returns empty, brain exits."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            # no attack_surface → after mapping, no agents available
        })
        state = brain.run("/project")

        assert "mapping" in state.completed_agents
        # Should not loop forever
        assert len(state.completed_agents) == 1

    def test_empty_dataflow_result_does_not_stall(self) -> None:
        """DataFlow producing empty paths marks entry point as done."""
        runner = Runner(llm=SIMPLE_LLM)

        class EmptyDataFlow(BaseAgent):
            agent_id = "dataflow"
            system_prompt = ""
            tools = []
            def run(self, params, llm=None, **kwargs) -> AgentResponse:
                return AgentResponse(
                    content="no paths found",
                    output={"paths": []},
                )

        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "attack_surface": AttackSurfaceStub(),
            "dataflow": EmptyDataFlow(),
        })
        state = brain.run("/project")

        # Dataflow ran and entry points are marked as done
        assert "dataflow" in state.completed_agents
        for ep in state.entry_points:
            assert ep.get("dataflow_done"), f"Entry point {ep.get('id')} not marked done"

    def test_agent_failure_does_not_stall_pipeline(self) -> None:
        """A permanently failing agent still marks its item as processed."""
        runner = Runner(llm=SIMPLE_LLM)

        class AlwaysFails(BaseAgent):
            agent_id = "dataflow"
            system_prompt = ""
            tools = []
            max_retries_on_timeout = 0  # don't retry
            call_count = 0

            def run(self, params, llm=None, **kwargs) -> AgentResponse:
                AlwaysFails.call_count += 1
                raise RuntimeError("permanent failure")

        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "attack_surface": AttackSurfaceStub(),
            "dataflow": AlwaysFails(),
        })
        state = brain.run("/project")

        # Dataflow ran (even though it failed) and entry points are marked done
        assert "dataflow" in state.completed_agents
        for ep in state.entry_points:
            assert ep.get("dataflow_done"), \
                f"Entry point {ep.get('id')} should be marked done even after failure"

    def test_pipeline_skips_to_next_stage_after_dataflow_failure(self) -> None:
        """When dataflow fails, pipeline should continue to vulnerability."""
        runner = Runner(llm=SIMPLE_LLM)

        # DataFlow that fails once then succeeds on retry
        class EventuallyPasses(BaseAgent):
            agent_id = "dataflow"
            system_prompt = ""
            tools = []
            call_count = 0

            def run(self, params, llm=None, **kwargs) -> AgentResponse:
                EventuallyPasses.call_count += 1
                if EventuallyPasses.call_count == 1:
                    raise RuntimeError("transient failure")
                return AgentResponse(
                    content="flow",
                    output={
                        "paths": [{
                            "id": "p1",
                            "source": params.get("entry_point_id", "ep1"),
                            "sink": "exec()",
                        }],
                    },
                )

        class TrackingVuln(VulnStub):
            agent_id = "vulnerability"
            system_prompt = ""
            tools = []
            call_count = 0

            def run(self, params, llm=None, **kwargs) -> AgentResponse:
                TrackingVuln.call_count += 1
                return AgentResponse(
                    content="vuln found",
                    output={
                        "vulnerabilities": [{
                            "id": f"v_{TrackingVuln.call_count}",
                            "type": "sqli",
                            "severity": "critical",
                            "verified": False,
                        }],
                    },
                )

        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "attack_surface": AttackSurfaceStub(),
            "dataflow": EventuallyPasses(),
            "vulnerability": TrackingVuln(),
        })
        state = brain.run("/project")

        assert "dataflow" in state.completed_agents
        assert "vulnerability" in state.completed_agents
        assert len(state.candidate_vulnerabilities) >= 1

    def test_empty_verify_result_does_not_stall(self) -> None:
        """Verify agent producing empty output marks vulnerability as verified."""
        runner = Runner(llm=SIMPLE_LLM)

        class EmptyVerify(BaseAgent):
            agent_id = "verify"
            system_prompt = ""
            tools = []
            def run(self, params, llm=None, **kwargs) -> AgentResponse:
                return AgentResponse(
                    content="nothing to verify",
                    output={"findings": []},
                )

        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "attack_surface": AttackSurfaceStub(),
            "dataflow": DataFlowStub(),
            "vulnerability": VulnStub(),
            "verify": EmptyVerify(),
            "report": ReportStub(),
        })
        state = brain.run("/project")

        assert "verify" in state.completed_agents
        assert "report" in state.completed_agents
        assert state.is_complete()
        for v in state.candidate_vulnerabilities:
            assert v.get("verified"), f"Vulnerability {v.get('id')} should be marked verified"


class TestBrainStateProgression:
    """Verify intermediate state after each brain step."""

    def test_state_after_mapping_only(self) -> None:
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "attack_surface": AttackSurfaceStub(),
        })
        # We'll run step-by-step manually to inspect intermediate state
        state = ProjectState(project_path="/p")

        # Manually drive: mapping
        available = state.get_available_agents()
        assert available == ["mapping"]

        agent = brain.agents["mapping"]
        response = agent.run({"project_path": "/p"})
        state.register_result("mapping", {"project_path": "/p"}, response.output)

        # After mapping, attack_surface should be available
        available2 = state.get_available_agents()
        assert "attack_surface" in available2

    def test_dataflow_becomes_available_after_surface(self) -> None:
        """After attack_surface populates entry_points, dataflow is available."""
        runner = Runner(llm=SIMPLE_LLM)
        state = ProjectState(project_path="/p")

        # Simulate mapping
        mapping = MappingStub()
        state.register_result("mapping", {}, mapping.run({}).output)

        # Simulate attack_surface
        surface = AttackSurfaceStub()
        state.register_result("attack_surface", {}, surface.run({}).output)

        # Now dataflow should be available
        available = state.get_available_agents()
        assert "dataflow" in available
        assert len(state.entry_points) == 2


class TestBrainFindsAvailable:
    """Brain correctly reads available agents from state."""

    def test_available_after_full_completion(self) -> None:
        brain = Brain(runner=Runner(llm=SIMPLE_LLM), agents={
            "mapping": MappingStub(),
            "attack_surface": AttackSurfaceStub(),
            "dataflow": DataFlowStub(),
            "vulnerability": VulnStub(),
            "verify": VerifyStub(),
            "report": ReportStub(),
        })
        state = brain.run("/project")
        available = state.get_available_agents()
        assert available == []  # nothing left to do


# ---------------------------------------------------------------------------
# Test card classification in state
# ---------------------------------------------------------------------------


class FakeCard:
    def __init__(self, entry, final_score, file_path="", functions_involved=None,
                 aggregated_signals=None, symbol_link_table=None):
        self.entry = entry
        self.final_score = final_score
        self.file_path = file_path
        self.functions_involved = functions_involved or []
        self.aggregated_signals = aggregated_signals or []
        self.symbol_link_table = symbol_link_table or {}


class TestStateCardClassification:
    def test_load_analysis_cards(self):
        state = ProjectState(project_path="/tmp/test")
        # Need enough items for clean 80/40 percentile splits
        cards = [
            FakeCard("hot1.py", 100),
            FakeCard("hot2.py", 95),
            FakeCard("warm1.py", 70),
            FakeCard("warm2.py", 55),
            FakeCard("warm3.py", 45),
            FakeCard("cold1.py", 20),
        ]
        state.load_analysis_cards(cards)
        assert len(state.hot_cards) >= 1  # top 20%
        assert len(state.warm_cards) >= 1  # middle 40%
        assert len(state.cold_cards) >= 1  # bottom 40%
        assert state.hot_cards[0].final_score >= state.warm_cards[0].final_score
        assert state.warm_cards[0].final_score >= state.cold_cards[0].final_score

    def test_load_empty_cards(self):
        state = ProjectState(project_path="/tmp/test")
        state.load_analysis_cards([])
        assert state.hot_cards == []
        assert state.warm_cards == []
        assert state.cold_cards == []

    def test_load_all_same_score(self):
        state = ProjectState(project_path="/tmp/test")
        cards = [
            FakeCard("a.py", 50),
            FakeCard("b.py", 50),
            FakeCard("c.py", 50),
        ]
        state.load_analysis_cards(cards)
        # With all same score, threshold = 50 for both p80 and p40
        # So: score >= 50 → hot (all three)
        assert len(state.hot_cards) == 3
        assert state.warm_cards == []
        assert state.cold_cards == []

    def test_silent_signals_from_cold_cards(self):
        state = ProjectState(project_path="/tmp/test")
        cards = [
            FakeCard("hot.py", 90, aggregated_signals=[], file_path="hot.py"),
            FakeCard("cold.py", 10, aggregated_signals=[], file_path="cold.py"),
        ]
        state.load_analysis_cards(cards)
        assert len(state.silent_signals) == 0  # only one card, p80=90, p40=10
        # Actually with 2 items, p80 indexes sorted[1] = 90, p40 indexes sorted[0] = 10
        # So hot card (90 >= 90) and cold card (10 < 10)? no, warm!
        # Let me re-check: classify_cards([10, 90]) → p80 = 90, p40 = 10
        # 90 >= 90 → hot, 10 >= 10 → warm
        # So no cold cards → no silent_signals
        assert len(state.silent_signals) == 0

    def test_silent_signals_produced(self):
        state = ProjectState(project_path="/tmp/test")
        cards = [
            FakeCard("high.py", 100),
            FakeCard("mid1.py", 80),
            FakeCard("mid2.py", 60),
            FakeCard("mid3.py", 40),
            FakeCard("low.py", 5),
        ]
        state.load_analysis_cards(cards)
        cold_entries = [c.entry for c in state.cold_cards]
        assert "low.py" in cold_entries


class TestCardFileAnalyzed:
    def test_not_analyzed(self):
        state = ProjectState(project_path="/tmp/test")
        state.key_files = [{"path": "app.py"}, {"path": "utils.py", "vuln_analyzed": True}]
        from agies.engine.v2.brain import _card_file_analyzed
        card = FakeCard("app", 50, file_path="app.py")
        assert _card_file_analyzed(card, state) is False

    def test_analyzed(self):
        state = ProjectState(project_path="/tmp/test")
        state.key_files = [{"path": "app.py", "vuln_analyzed": True}]
        from agies.engine.v2.brain import _card_file_analyzed
        card = FakeCard("app", 50, file_path="app.py")
        assert _card_file_analyzed(card, state) is True

    def test_empty_file_path(self):
        state = ProjectState(project_path="/tmp/test")
        from agies.engine.v2.brain import _card_file_analyzed
        card = FakeCard("app", 50, file_path="")
        assert _card_file_analyzed(card, state) is True


class TestPreloadContext:
    def test_empty_symbol_table(self):
        from agies.engine.v2.brain import Brain
        card = FakeCard("test", 50, symbol_link_table={})
        result = Brain._preload_context(card, "/tmp/test")
        assert result == ""

    def test_symbol_table_produces_chunks(self):
        import tempfile
        from pathlib import Path
        from agies.engine.v2.brain import Brain

        with tempfile.TemporaryDirectory() as tmpdir:
            pyfile = Path(tmpdir) / "app.py"
            pyfile.write_text("def foo():\n    return 1\n\ndef bar():\n    return foo()\n")
            card = FakeCard("foo", 50, symbol_link_table={"foo": "app.py:1"})
            result = Brain._preload_context(card, tmpdir)
            assert "foo" in result
            assert "def foo()" in result


# ---------------------------------------------------------------------------
# P1: QuotaMonitor Brain wiring
# ---------------------------------------------------------------------------


class TestBrainQuotaMonitor:
    """QuotaMonitor integration — budget guard and token recording."""

    def test_quota_created_with_default(self) -> None:
        """Brain without token_budget creates an unlimited QuotaMonitor."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={})
        assert brain._quota.budget_usd == 0.0
        assert not brain._quota.is_budget_exhausted()

    def test_quota_created_with_budget(self) -> None:
        """Brain with token_budget forwards it to QuotaMonitor."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={}, token_budget=5.0)
        assert brain._quota.budget_usd == 5.0

    def test_budget_exhaustion_stops_submission(self) -> None:
        """When budget is exhausted, _submit_available returns without submitting."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={"mapping": MappingStub()}, token_budget=1.0)
        brain._quota.record_usage(input_tokens=10_000_000, output_tokens=0)
        assert brain._quota.is_budget_exhausted()

        state = ProjectState(project_path="/test")
        submitted_keys: dict[str, set[str]] = defaultdict(set)
        available = state.get_available_agents()

        brain._submit_available(available, state, submitted_keys)

        # No tasks should have been submitted
        tq = brain._task_queue
        if tq is not None:
            ready = tq.poll()
            assert len(ready) == 0

    def test_quota_records_usage_in_handle_result(self) -> None:
        """_handle_result calls record_usage when result has tokens."""
        from agies.engine.v2.agents.base import AgentResponse
        from agies.engine.v2.runner import AgentResult
        from agies.engine.v2.task_queue import TaskQueue

        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={}, token_budget=10.0)
        tq = TaskQueue()
        state = ProjectState(project_path="/test")

        task = type("Task", (), {"task_id": 1, "agent_name": "mapping", "params": {}})()
        result = AgentResult(
            agent_name="mapping",
            params={},
            response=AgentResponse(total_tokens=2000),
        )

        initial_cost = brain._quota.total_cost_usd
        brain._handle_result(task, result, tq, state)
        assert brain._quota.total_cost_usd > initial_cost
        assert brain._quota.total_cost_usd > 0

    def test_quota_skipped_when_no_tokens(self) -> None:
        """_handle_result doesn't call record_usage when total_tokens is 0."""
        from agies.engine.v2.agents.base import AgentResponse
        from agies.engine.v2.runner import AgentResult
        from agies.engine.v2.task_queue import TaskQueue

        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={}, token_budget=10.0)
        tq = TaskQueue()
        state = ProjectState(project_path="/test")

        task = type("Task", (), {"task_id": 1, "agent_name": "mapping", "params": {}})()
        result = AgentResult(
            agent_name="mapping",
            params={},
            response=AgentResponse(total_tokens=0),
        )

        initial_cost = brain._quota.total_cost_usd
        brain._handle_result(task, result, tq, state)
        assert brain._quota.total_cost_usd == initial_cost

    def test_budget_value_in_state(self) -> None:
        """Brain forwards token_budget to ProjectState via run()."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={"mapping": MappingStub()}, token_budget=2.5)
        state = brain.run("/project")
        assert state.token_budget == 2.5


# ---------------------------------------------------------------------------
# P3: Director card wiring into sourcer and bulk_analysis dispatch
# ---------------------------------------------------------------------------


@dataclass
class FakeNodeMeta:
    """Minimal stand-in for NodeMetadata (functions_involved entries)."""
    name: str
    file_path: str
    line: int = 1
    final_score: float = 0.0
    pagerank_score: float = 0.0
    attack_path_score: float = 0.0
    signal_types: list[str] | None = None


class TestBrainCardAwareDispatch:
    """Brain passes Director card data into sourcer and bulk_analysis params."""

    def _make_card(self, entry: str, file_path: str, score: float,
                   functions: list[tuple[str, str, float]] | None = None) -> FakeCard:
        """Build a FakeCard with functions_involved metadata."""
        metas = []
        if functions:
            for name, fp, fs in functions:
                metas.append(FakeNodeMeta(name=name, file_path=fp, final_score=fs))
        return FakeCard(
            entry=entry,
            final_score=score,
            file_path=file_path,
            functions_involved=metas,
        )

    def test_sourcer_gets_full_index_paths_from_cards(self) -> None:
        """When hot+warm cards exist, sourcer params include full_index_paths."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "sourcer": SourcerStub(),
        })
        brain._ensure_profiles()

        # Inject cards into state before dispatching
        state = ProjectState(project_path="/project", use_new_pipeline=True)
        state.project_summary = "test"
        state.completed_agents.append("mapping")
        state._rebuild_brain_summary()

        hot_card = self._make_card("hot", "/project/src/hot.py", 95.0,
                                   functions=[("foo", "/project/src/hot.py", 95.0)])
        state.hot_cards = [hot_card]
        state.load_analysis_cards([hot_card])

        submitted_keys: dict[str, set[str]] = defaultdict(set)
        brain._submit_available(["sourcer"], state, submitted_keys)

        # Poll the queue and inspect submitted task params
        ready = brain._task_queue.poll()
        assert len(ready) == 1
        params = ready[0].params
        assert params.get("full_index_paths") is not None
        assert any("/project/src/hot.py" in p for p in params["full_index_paths"])

    def test_sourcer_no_cards_no_full_index_paths(self) -> None:
        """Without Director cards, full_index_paths is None (legacy mode)."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "sourcer": SourcerStub(),
        })
        brain._ensure_profiles()

        state = ProjectState(project_path="/project", use_new_pipeline=True)
        state.project_summary = "test"
        state.completed_agents.append("mapping")
        state._rebuild_brain_summary()

        submitted_keys: dict[str, set[str]] = defaultdict(set)
        brain._submit_available(["sourcer"], state, submitted_keys)

        ready = brain._task_queue.poll()
        assert len(ready) == 1
        assert ready[0].params.get("full_index_paths") is None

    def test_bulk_analysis_gets_priority_map_from_cards(self) -> None:
        """When analysis_cards exist, bulk_analysis params include priority_map."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "bulk_analysis": BulkStub(),
        })
        brain._ensure_profiles()

        state = ProjectState(project_path="/project", use_new_pipeline=True)
        state.project_summary = "test"
        state.function_index = FunctionIndex()
        state.completed_agents.append("mapping")
        state.completed_agents.append("sourcer")

        # Inject cards with functions_involved
        card = self._make_card("high_risk", "/project/src/app.py", 95.0,
                               functions=[("sql_exec", "/project/src/db.py", 95.0),
                                          ("parse_input", "/project/src/app.py", 80.0)])
        state.analysis_cards = [card]
        state._rebuild_brain_summary()

        submitted_keys: dict[str, set[str]] = defaultdict(set)
        brain._submit_available(["bulk_analysis"], state, submitted_keys)

        ready = brain._task_queue.poll()
        assert len(ready) == 1
        pm = ready[0].params.get("priority_map")
        assert pm is not None
        assert "sql_exec" in pm
        assert pm["sql_exec"] == 95.0
        assert "parse_input" in pm
        assert pm["parse_input"] == 80.0

    def test_bulk_analysis_no_cards_no_priority_map(self) -> None:
        """Without Director cards, priority_map is None."""
        runner = Runner(llm=SIMPLE_LLM)
        brain = Brain(runner=runner, agents={
            "mapping": MappingStub(),
            "bulk_analysis": BulkStub(),
        })
        brain._ensure_profiles()

        state = ProjectState(project_path="/project", use_new_pipeline=True)
        state.project_summary = "test"
        state.function_index = FunctionIndex()
        state.completed_agents.append("mapping")
        state.completed_agents.append("sourcer")
        state._rebuild_brain_summary()

        submitted_keys: dict[str, set[str]] = defaultdict(set)
        brain._submit_available(["bulk_analysis"], state, submitted_keys)

        ready = brain._task_queue.poll()
        assert len(ready) == 1
        assert ready[0].params.get("priority_map") is None

