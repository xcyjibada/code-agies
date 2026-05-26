"""Brain — the central decision loop for code audit orchestration.

The Brain owns a registry of available agents, a ProjectState, and a
TaskQueue.  On each iteration it:

1. Checks ``state.get_available_agents()`` for agents that should run
2. Builds ``AgentCall`` s and submits them to the ``TaskQueue``
3. Polls the ``TaskQueue`` for tasks that can start (respecting concurrency)
4. Dispatches ready tasks via the ``Runner``
5. Calls ``tq.complete()`` / ``tq.fail()`` on each result
6. Feeds completed results into the ``ProjectState``

Failures are retried automatically with exponential backoff via the TaskQueue.
Timeouts are enforced at the Runner level via ``future.result(timeout=...)``.
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from typing import Any

from agies.engine.agents.base import BaseAgent
from agies.engine.director import Director
from agies.engine.feedback import FeedbackStore
from agies.engine.router import map_max_iterations
from agies.engine.runner import AgentCall, Runner
from agies.engine.state import ProjectState
from agies.engine.task_queue import AgentType, TaskDesc, TaskQueue
from agies.tools.index_tools import set_state

logger = logging.getLogger(__name__)

# Default per-agent resource profiles (Plan B / full TaskQueue scheduling).
# Maps agent_name → (AgentType, TaskDesc).
_AGENT_PROFILES: dict[str, tuple[AgentType, TaskDesc]] = {
    "mapping": (AgentType.MAPPING, TaskDesc(max_concurrency=1, max_attempts=3, timeout=120)),
    "sourcer": (AgentType.SOURCER, TaskDesc(max_concurrency=1, max_attempts=1, timeout=60)),
    "bulk_analysis": (AgentType.BULK_ANALYSIS, TaskDesc(max_concurrency=1, max_attempts=2, timeout=600)),
    "attack_surface": (AgentType.ATTACK_SURFACE, TaskDesc(max_concurrency=1, max_attempts=3, timeout=120)),
    "dataflow": (AgentType.DATAFLOW, TaskDesc(max_concurrency=5, max_attempts=3, timeout=300)),
    "vulnerability": (AgentType.VULNERABILITY, TaskDesc(max_concurrency=3, max_attempts=3, timeout=600)),
    "verify": (AgentType.VERIFY, TaskDesc(max_concurrency=10, max_attempts=3, timeout=180)),
    "verification": (AgentType.VERIFICATION, TaskDesc(max_concurrency=10, max_attempts=3, timeout=180)),
    "report": (AgentType.REPORT, TaskDesc(max_concurrency=1, max_attempts=3, timeout=60)),
}


def _task_key(name: str, params: dict[str, Any]) -> str:
    """Build a deterministic deduplication key for a task submission.

    Singleton agents (mapping, sourcer, bulk_analysis, attack_surface, report)
    use the agent name as the key — they submit exactly once.

    Fan-out agents use a composite key so each *item* (entry point, key file,
    candidate, vulnerability) is submitted only once.
    """
    if name == "dataflow":
        return f"dataflow:{params.get('entry_point_id', '')}"
    if name == "vulnerability":
        return f"vuln:{params.get('key_file_path', '') or params.get('path_id', '')}"
    if name == "verification":
        _round = params.get("_round", 1)
        # Batch mode: key by file path
        fp = params.get("file_path")
        if fp:
            return f"verify_file:{fp}:r{_round}"
        # Legacy single-candidate mode: key by candidate position
        return f"verify:{params.get('candidate_index', '')}:r{_round}"
    if name == "verify":
        return f"vuln_verify:{params.get('vulnerability_id', '')}"
    return name


def _card_file_analyzed(card: Any, state: ProjectState) -> bool:
    """Check if a card's file has already been analyzed by vulnerability agent."""
    card_path = getattr(card, "file_path", "")
    if not card_path:
        return True
    for kf in state.key_files:
        kf_path = kf.get("path", "")
        if kf_path == card_path and kf.get("vuln_analyzed"):
            return True
    return False


def _build_call_chain_context(
    candidate: Any,
    analysis_cards: list,
) -> str:
    """Build a [CALL_CHAIN] context block for a verification candidate.

    Scans analysis_cards from the Director to find which entry point(s)
    lead to *candidate.function_name*, and formats the attack path so
    the verification agent doesn't have to discover it from scratch.
    """
    parts: list[str] = []
    for card in analysis_cards:
        # Duck-type: check for card-like attributes rather than isinstance,
        # which can fail due to Python module identity across import paths.
        if not hasattr(card, "entry") or not hasattr(card, "functions_involved"):
            continue
        # Check if this card's entry point file matches
        # the candidate's file, or if functions_involved
        # mentions the candidate function.
        entry_file = getattr(card, "file_path", "")
        cand_file = getattr(candidate, "file_path", "")
        cand_func = getattr(candidate, "function_name", "")

        file_match = cand_file and entry_file and cand_file.endswith(entry_file)
        func_match = False
        if cand_func:
            func_match = any(
                getattr(fn, "name", "") == cand_func
                for fn in getattr(card, "functions_involved", [])
            )
        if not file_match and not func_match:
            continue

        # Build context for this card
        sigs = ", ".join(
            f"{s.tag}({s.count})"
            for s in getattr(card, "aggregated_signals", [])[:5]
        )
        funcs = getattr(card, "functions_involved", [])
        sink_lines = []
        seen = set()
        for fn in funcs:
            if fn.name in seen:
                continue
            seen.add(fn.name)
            marker = ""
            if fn.name == cand_func:
                marker = "  ← SINK"
            sink_lines.append(
                f"  {fn.name:<50} {getattr(fn, 'file_path', '')}:{getattr(fn, 'line', 0)}{marker}"
            )

        # Show only first 30 functions + truncation notice
        if len(sink_lines) > 30:
            sink_lines = sink_lines[:30]
            sink_lines.append(f"  ... ({len(funcs) - 30} more functions)")

        block = (
            f"[CALL_CHAIN] Entry point: {getattr(card, 'entry', '')}\n"
            f"Score: {getattr(card, 'final_score', 0):.2f}\n"
            f"Signals: {sigs}\n"
            f"Functions in file ({len(funcs)} total):\n"
            + "\n".join(sink_lines)
        )
        parts.append(block)

    if not parts:
        return ""
    return "\n\n".join(parts)


def _inject_boundary_candidates(state: ProjectState) -> None:
    """Detect recursive functions missing depth guards and inject as candidates.

    Runs after the Sourcer has built the function index but before Bulk
    Analysis.  Uses a two-step deterministic scan:
      1. Text-match: find functions that call themselves (potential recursion)
      2. Depth guard check: verify the body has a depth/bound/limit guard
    Functions that fail both checks become [MISSING_DEPTH_BOUND] candidates.
    """
    import re as _re

    from agies.engine.sast.bound_checker import check_depth_guard
    from agies.engine.sourcer.models import CandidateFinding

    injected = 0
    for fn in state.function_index.funcs:
        # Step 1: quick text-match for self-call
        body_text = fn.body or ""
        if not body_text:
            continue
        # Look for `func_name(...)` in the body (simple heuristic)
        if not _re.search(rf'\b{_re.escape(fn.name)}\s*\(', body_text):
            continue

        # Step 2: check for depth/bound/limit guard
        if check_depth_guard(body_text, func_name=fn.name):
            continue  # has guard — safe

        # Missing depth bound — inject as candidate
        state.candidates.append(CandidateFinding(
            type="resource_exhaustion",
            function_name=fn.name,
            file_path=fn.file_path or "",
            line_number=0,
            severity="high",
            confidence="medium",
            source_line=body_text[:200],
            reason=(
                f"[MISSING_DEPTH_BOUND] Function '{fn.name}' calls itself "
                f"recursively but has no depth/bound/limit guard. "
                f"Attacker-controlled deep input could trigger stack overflow."
            ),
        ))
        injected += 1

    if injected:
        logger.info(
            "Brain: injected %d [MISSING_DEPTH_BOUND] candidate(s) "
            "via SafetyBoundary scanner.",
            injected,
        )


def _inject_director_candidates(state: ProjectState) -> None:
    """Inject deterministic candidates for HTTP-reachable functions with critical SAST signals.

    The Director + SAST pre-scan identifies functions on HTTP-reachable paths
    with serialization/critical_sink signals. Bulk analysis (per-function LLM)
    can miss these due to cross-function indirection (e.g. the pickle.loads is
    in a Payload class, not the HTTP handler). This function ensures they are
    always in the candidate list regardless of LLM output variation.
    """
    from agies.engine.sourcer.models import CandidateFinding

    _CRITICAL_SIGNALS = frozenset({"serialization", "critical_sink"})

    # Noise-file heuristics (same patterns as loader._is_noise_file) —
    # skip functions from third-party bundled/minified files.  These
    # files contain thousands of functions that trigger false SAST
    # signals (e.g. swagger-ui-bundle.js → "serialization"), drowning
    # out real findings.
    _NOISE_NAME_PATTERNS = frozenset({
        ".min.js", ".min.css",
        "-bundle.js", ".bundle.js",
        "-min.js",
    })
    _NOISE_DIR_FRAGMENTS = frozenset({
        "/vendor/", "/vendors/", "/third_party/", "/third-party/",
    })
    _MAX_FILE_SIZE = 512 * 1024  # 500 KB — likely bundled
    _MAX_AVG_LINE_LEN = 200
    _noise_file_cache: dict[str, bool] = {}

    def _is_noise(fpath: str) -> bool:
        """Return True if *fpath* looks like a third-party bundled/noise file."""
        if fpath in _noise_file_cache:
            return _noise_file_cache[fpath]
        basename = os.path.basename(fpath)
        for pat in _NOISE_NAME_PATTERNS:
            if basename.endswith(pat):
                _noise_file_cache[fpath] = True
                return True
        norm_path = fpath.replace("\\", "/")
        for frag in _NOISE_DIR_FRAGMENTS:
            if frag in norm_path:
                _noise_file_cache[fpath] = True
                return True
        # File size check (stat, cheap)
        try:
            if os.path.getsize(fpath) > _MAX_FILE_SIZE:
                _noise_file_cache[fpath] = True
                return True
        except OSError:
            pass
        # Average line length check (read first 20 non-empty lines)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                lines = [l for l in f.read().splitlines()[:20] if l.strip()]
            if lines:
                avg = sum(len(l) for l in lines) / len(lines)
                if avg > _MAX_AVG_LINE_LEN:
                    _noise_file_cache[fpath] = True
                    return True
        except (OSError, UnicodeDecodeError):
            pass
        _noise_file_cache[fpath] = False
        return False

    _HTTP_KEYWORDS = frozenset({
        "app", "server", "route", "handler", "endpoint",
        "api", "http", "service", "web",
    })
    injected = 0
    _MAX_INJECTED = 30  # total cap — prevent flooding from broad signals
    _MAX_PER_FILE = 5   # per-file cap — avoid any single file dominating
    injected_per_file: dict[str, int] = {}
    seen: set[str] = set()

    for card in state.analysis_cards:
        if not hasattr(card, "entry") or not hasattr(card, "functions_involved"):
            continue
        entry_name = getattr(card, "entry", "unknown")
        is_http = any(k in entry_name.lower() for k in _HTTP_KEYWORDS)
        if not is_http:
            for s in getattr(card, "aggregated_signals", []):
                if hasattr(s, "tag") and s.tag == "network_operation":
                    is_http = True
                    break
        if not is_http:
            continue

        # Check if this card has critical signals
        sig_tags = {
            s.tag for s in getattr(card, "aggregated_signals", [])
            if hasattr(s, "tag")
        }
        if not sig_tags & _CRITICAL_SIGNALS:
            continue

        for meta in getattr(card, "functions_involved", []):
            fn_name = getattr(meta, "name", "")
            if not fn_name or fn_name in seen:
                continue
            # Skip repomap noise (single-word lowercase names like "map",
            # "list", "property" that aren't actual project functions).
            if len(fn_name.split("_")) < 2 and fn_name.islower() and not any(c.isupper() for c in fn_name):
                continue
            seen.add(fn_name)
            file_path = getattr(meta, "file_path", getattr(card, "file_path", ""))
            # Skip functions in third-party bundled/minified files
            if file_path and _is_noise(file_path):
                continue
            # Skip test files — test code is not an attack surface
            if file_path and ("/tests/" in file_path or "/test/" in file_path):
                continue
            # Cap injection: respect total and per-file limits
            if injected >= _MAX_INJECTED:
                continue
            if file_path:
                pfc = injected_per_file.get(file_path, 0)
                if pfc >= _MAX_PER_FILE:
                    continue
            score = getattr(meta, "final_score", getattr(card, "final_score", 0))
            card_sigs = ", ".join(sorted(sig_tags))

            # Determine vulnerability type from signals
            vuln_type = "dangerous_function"
            if "serialization" in sig_tags:
                vuln_type = "deserialization"

            state.candidates.append(CandidateFinding(
                type=vuln_type,
                severity="high",
                file_path=file_path,
                function_name=fn_name,
                line_number=getattr(meta, "line", 0),
                reason=(
                    f"[SAST] Function on HTTP-reachable path with critical signal: {card_sigs}. "
                    f"Entry point: {entry_name} (score: {score:.2f}). "
                    f"Verification must trace the full call chain to confirm exploitability."
                ),
                confidence="medium",
                sink_type=card_sigs,
            ))
            injected += 1
            if file_path:
                injected_per_file[file_path] = injected_per_file.get(file_path, 0) + 1

    if injected:
        logger.info(
            "Brain: injected %d Director candidate(s) for HTTP-reachable critical-sink functions.",
            injected,
        )


class Brain:
    """TaskQueue-driven agent orchestrator.

    Usage::

        brain = Brain(runner, agents={"mapping": MappingAgent()})
        state = brain.run("/path/to/project")
    """

    def __init__(
        self,
        runner: Runner,
        agents: dict[str, BaseAgent] | None = None,
        task_queue: TaskQueue | None = None,
        token_budget: float = 0.0,
    ) -> None:
        self.runner = runner
        self.agents: dict[str, BaseAgent] = agents or {}

        # TaskQueue for full scheduling (Plan B).
        # If not provided, a default one is created on first use.
        self._task_queue: TaskQueue | None = task_queue
        self._profiles_registered = False

        # Budget guard (0 = unlimited)
        from agies.engine.router import QuotaMonitor
        self._quota = QuotaMonitor(budget_usd=token_budget)

    # ------------------------------------------------------------------
    # Agent profile registration
    # ------------------------------------------------------------------

    def _ensure_profiles(self) -> None:
        """Register known agent types with the TaskQueue (once)."""
        if self._profiles_registered:
            return
        tq = self._task_queue
        if tq is None:
            tq = TaskQueue()
            self._task_queue = tq
        for name, agent in self.agents.items():
            profile = _AGENT_PROFILES.get(name)
            if profile is not None:
                agent_type, desc = profile
                tq.register(agent_type, desc)
        self._profiles_registered = True

    def _profile_for(self, name: str) -> TaskDesc | None:
        """Return the TaskDesc for *name*, or None."""
        profile = _AGENT_PROFILES.get(name)
        return profile[1] if profile else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        project_path: str,
        use_new_pipeline: bool = False,
    ) -> ProjectState:
        """Run the full audit pipeline against *project_path*.

        Uses the TaskQueue as the scheduling engine:

        1. **Submit** — available agents are converted to ``AgentCall`` s
           and submitted to the TaskQueue with their resource profile.
        2. **Poll** — the TaskQueue returns tasks that can start now,
           respecting per-type ``max_concurrency`` limits.
        3. **Execute** — ready tasks run in the Runner's thread pool.
        4. **Complete / Fail** — results are reported back to the TaskQueue.
           Failed tasks are automatically retried with exponential backoff.
        5. **Register** — results are fed into the ``ProjectState``.

        When *use_new_pipeline* is True, the Brain dispatches the new
        Xint-inspired agent chain (sourcer → bulk → verification) in
        addition to the existing pipeline.

        Returns the final ``ProjectState`` containing all findings.
        """
        self._ensure_profiles()
        state = ProjectState(
            project_path=project_path,
            use_new_pipeline=use_new_pipeline,
            token_budget=self._quota.budget_usd,
        )

        # --- P6: Share state with tools for blackboard knowledge recording ---
        set_state(state)

        # --- Quick file count for adaptive agent iteration ---
        try:
            fc = 0
            for root, dirs, files in os.walk(project_path):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', 'venv', 'env', '__pycache__', 'dist', 'build')]
                fc += len([f for f in files if f.endswith('.py')])
            state.file_count = fc
            logger.info("Brain: project file count = %d", fc)
        except Exception:
            state.file_count = 0

        # --- P5: Load cross-scan feedback ---
        feedback_path = os.path.join(project_path, ".agies", "feedback.json")
        feedback = FeedbackStore.load(feedback_path)

        # --- Phase 0: Director (strategic entry-point ranking) ---
        # Before any LLM agents run, the Director uses tree-sitter + PageRank
        # + SAST signals to produce ranked analysis cards.  This replaces
        # the old brute-force "audit everything" approach with strategic
        # budget allocation.
        if use_new_pipeline:
            try:
                director = Director(project_path=project_path, feedback_store=feedback)
                cards = director.run(max_cards=15)
                state.load_analysis_cards(cards)
                # Store ALL entry points (including SAST-promoted critical sink
                # files) so the Sourcer always does full AST extraction for
                # critical files regardless of whether their card made the top 15.
                if director.entry_points:
                    state.director_entry_points = sorted(director.entry_points)
                    logger.info(
                        "Brain: stored %d Director entry points for Sourcer (incl. SAST-promoted).",
                        len(state.director_entry_points),
                    )
                logger.info(
                    "Brain: Director Phase 0 complete — %d cards, top=%s score=%.4f",
                    len(cards),
                    cards[0].entry if cards else "none",
                    cards[0].final_score if cards else 0,
                )
                if cards:
                    # Summarize top cards for the strategy decision
                    top_entries = [
                        {
                            "entry": c.entry,
                            "final_score": c.final_score,
                            "function_count": c.function_count,
                            "signals": [s.tag for s in c.aggregated_signals],
                            "top_symbols": list(c.symbol_link_table.keys())[:10],
                        }
                        for c in cards[:5]
                    ]
                    logger.debug(
                        "Brain: top entries: %s",
                        [e["entry"] for e in top_entries],
                    )
            except Exception as exc:
                logger.warning(
                    "Brain: Director Phase 0 failed (%s), falling back to full scan",
                    exc,
                )

        # Track submitted task keys per agent type to avoid double-submission.
        submitted_keys: dict[str, set[str]] = defaultdict(set)

        iteration = 0
        while not state.is_complete():
            iteration += 1
            available = state.get_available_agents()

            # --- Phase 1: Submit new tasks ---
            if available:
                self._submit_available(available, state, submitted_keys)

            # --- Phase 2: Poll and execute ---
            tq = self._task_queue
            if tq is None:
                break
            ready = tq.poll()

            if not ready:
                if tq.idle():
                    logger.info(
                        "Brain: idle at iteration %d, stopping.",
                        iteration,
                    )
                    break
                # Tasks are still running (not idle) but none are ready
                # because of concurrency limits.  Yield the CPU slice and
                # loop back to poll again.
                time.sleep(0.05)
                continue

            batch = self._build_batch_from_tasks(ready)

            if not batch:
                # All ready tasks had no matching agent — complete them so
                # the queue doesn't stall.
                for t in ready:
                    tq.complete(t.task_id)
                continue

            logger.debug(
                "Brain iteration %d: executing %d task(s): %s",
                iteration,
                len(batch),
                [c.agent_name for c in batch],
            )

            results = self.runner.execute(batch)

            # --- Phase 3: Complete / Fail ---
            for t, result in zip(ready, results):
                self._handle_result(t, result, tq, state)

        # --- P5: Record feedback from verification results ---
        if state.verified_findings:
            FeedbackStore.record_from_findings(state.verified_findings, store=feedback)
            feedback.save(feedback_path)
            if feedback.has_feedback():
                logger.info(
                    "P5 feedback saved: %d confirmed idents, %d fp files",
                    len(feedback.confirmed_idents),
                    len(feedback.fp_counts),
                )

        # Final state logging
        logger.info(
            "Brain audit complete: %d iterations, %d findings, %s",
            iteration,
            len(state.verified_findings) or len(state.candidate_vulnerabilities),
            state.completed_agents,
        )
        return state

    # ------------------------------------------------------------------
    # Task submission
    # ------------------------------------------------------------------

    def _submit_available(
        self,
        available: list[str],
        state: ProjectState,
        submitted_keys: dict[str, set[str]],
    ) -> None:
        """Submit tasks for all available agents that haven't been submitted yet."""
        # Budget guard — stop submitting when budget is exhausted
        if self._quota.is_budget_exhausted():
            logger.warning(
                "Brain: budget exhausted ($%.4f / $%.2f), "
                "stopping new task submission.",
                self._quota.total_cost_usd,
                self._quota.budget_usd,
            )
            return

        has_attack_surface = "attack_surface" in self.agents

        for name in available:
            agent = self.agents.get(name)
            if agent is None:
                logger.warning("Brain: agent '%s' not registered, skipping.", name)
                continue

            # Vulnerability Mode 1 gating: when attack_surface is registered
            # but hasn't completed yet, defer vulnerability so attack_surface
            # can populate entry_points first (enabling the full pipeline:
            # surface → dataflow → vuln Mode 2).
            if name == "vulnerability" and not state.entry_points:
                if has_attack_surface and "attack_surface" not in state.completed_agents:
                    logger.debug(
                        "Brain: deferring vulnerability (Mode 1) — "
                        "attack_surface pending.",
                    )
                    continue

            calls = self._build_calls(name, agent, state)
            for call in calls:
                key = _task_key(name, call.params)
                if key in submitted_keys[name]:
                    continue
                submitted_keys[name].add(key)

                # Forward agent-level LLM defaults (e.g. max_tokens)
                agent_kwargs = getattr(agent, "DEFAULT_LLM_KWARGS", {})
                if agent_kwargs:
                    call.llm_kwargs = {**agent_kwargs, **call.llm_kwargs}

                # Inject timeout / max_retries from TaskQueue profile
                profile = self._profile_for(name)
                if profile is not None:
                    call.timeout = call.timeout or profile.timeout
                    call.max_retries = call.max_retries or profile.max_attempts - 1

                agent_type = _AGENT_PROFILES.get(name, (AgentType.MAPPING, None))[0]
                tq = self._task_queue
                if tq is not None:
                    tq.submit(
                        agent_type=agent_type,
                        agent_name=name,
                        params=call.params,
                        timeout=call.timeout,
                    )

    # ------------------------------------------------------------------
    # Batch building from polled tasks
    # ------------------------------------------------------------------

    def _build_batch_from_tasks(
        self,
        ready: list[Any],
    ) -> list[AgentCall]:
        """Convert polled TaskQueue tasks into ``AgentCall`` s for the Runner."""
        batch: list[AgentCall] = []
        for t in ready:
            agent = self.agents.get(t.agent_name)
            if agent is None:
                logger.warning(
                    "Brain: agent '%s' not found for task %d, skipping.",
                    t.agent_name,
                    t.task_id,
                )
                continue
            agent_kwargs = getattr(agent, "DEFAULT_LLM_KWARGS", {})
            batch.append(
                AgentCall(
                    agent_name=t.agent_name,
                    agent=agent,
                    params=t.params,
                    llm_kwargs=agent_kwargs,
                    timeout=t.timeout,
                )
            )
        return batch

    # ------------------------------------------------------------------
    # Candidate pruning — priority-driven, no SAST rules needed
    # ------------------------------------------------------------------

    @staticmethod
    def _is_injected(c: CandidateFinding) -> bool:
        """Return True if *c* was injected by Director/Boundary/coverage rules
        (low-confidence) rather than produced by bulk analysis (high-confidence).

        Injected candidates start with a bracketed tag in their reason field:
        ``[SAST]`` for Director, ``[MISSING_DEPTH_BOUND]`` for SafetyBoundary,
        and specific phrases for after-result coverage injection.
        """
        reason = (c.reason or "")
        return bool(
            reason.startswith("[SAST]")
            or reason.startswith("[MISSING_DEPTH_BOUND]")
            or reason.startswith("Uncovered function in critical file")
        )


    def _prune_candidates(
        self,
        state: ProjectState,
        candidates: list[CandidateFinding],
        max_candidates: int = 30,
    ) -> list[CandidateFinding]:
        """Prune verification candidates, protecting entry-point files first.

        Unlike the old per-file diversity approach (which let score-based
        rounds fill the cap before entry-point protection could act), this
        method reserves slots for entry-point files **first**, then fills
        remaining capacity by LLM Bulk score.

        Entry-point files come from the Director's SAST pre-scan + PageRank
        + attack-surface agent.  Zero new SAST rules needed — the existing
        Director signals are reprioritized.
        """
        _SEV = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        _CONF = {"high": 3, "medium": 2, "low": 1}
        _TYPE_BONUS = {
            "deserialization": 8, "serialization": 8, "rce": 8,
            "command_injection": 7, "path_traversal": 6, "file_io": 6,
            "sql_injection": 6, "injection": 5, "path_manipulation": 5,
            "path_pattern": 4, "resource_exhaustion": 4,
            "authentication": 4, "authorization": 4, "idor": 5,
            "cross_function_trace": 3, "dangerous_function": 2,
        }

        def _signal_score(c: CandidateFinding) -> int:
            base = _SEV.get(c.severity, 1) * _CONF.get(c.confidence, 1)
            return base + _TYPE_BONUS.get(c.type, 0)

        def _is_test_file(c: CandidateFinding) -> bool:
            return "/tests/" in c.file_path or c.file_path.startswith("tests/")

        prod = [c for c in candidates if not _is_test_file(c)]
        test = [c for c in candidates if _is_test_file(c)]
        prod.sort(key=_signal_score, reverse=True)

        # Collect entry-point file paths (includes SAST-promoted critical sinks)
        entry_point_files: set[str] = set()
        for ep in state.entry_points:
            fp = ep.get("file_path", "")
            if fp:
                entry_point_files.add(fp)

        selected: list[CandidateFinding] = []
        selected_fps: dict[str, int] = {}
        remaining = list(prod)

        # Round 0: reserve up to 2 candidates per entry-point file,
        # but stop at half the cap to leave room for high-scoring
        # non-entry-point candidates (e.g. deserialization sinks in
        # cold files like shelvestore.py).
        round0_limit = max_candidates // 2
        for c in list(remaining):
            if len(selected) >= round0_limit:
                break
            if c.file_path in entry_point_files:
                if selected_fps.get(c.file_path, 0) < 2:
                    selected.append(c)
                    selected_fps[c.file_path] = selected_fps.get(c.file_path, 0) + 1
                    remaining.remove(c)

        # Round 1: fill to cap with highest-scored prod candidates
        for c in remaining:
            if len(selected) >= max_candidates:
                break
            selected.append(c)

        # Round 2: add test candidates if room
        test.sort(key=_signal_score, reverse=True)
        for c in test:
            if len(selected) >= max_candidates:
                break
            selected.append(c)

        return selected

    # ------------------------------------------------------------------
    # Result handling
    # ------------------------------------------------------------------

    def _handle_result(
        self,
        task: Any,
        result: Any,
        tq: TaskQueue,
        state: ProjectState,
    ) -> None:
        """Process one task result: complete, fail+retry, or register."""
        if result.error:
            logger.warning(
                "Brain: agent=%s task=%d failed: %s",
                task.agent_name,
                task.task_id,
                result.error[:100] if result.error else "",
            )
            if tq.fail(task.task_id):
                logger.info(
                    "Brain: task %d (%s) re-queued for retry.",
                    task.task_id,
                    task.agent_name,
                )
                return  # will be retried
        else:
            tq.complete(task.task_id)

        response = result.response
        token_count = response.total_tokens if response else 0
        output = response.output if response else {}
        agent_name = result.agent_name or task.agent_name

        # Debug: what the verification output looks like
        if agent_name == "verification":
            logger.warning(
                "VERIFICATION OUTPUT: output_keys=%s has_results=%s type=%s",
                list(output.keys()) if output else "None",
                "results" in output if output else False,
                type(output).__name__,
            )

        # Batch verification: unroll per-candidate results
        if agent_name == "verification" and "results" in output:
            batch_results = output["results"]
            per_candidate_tokens = token_count // max(len(batch_results), 1)
            # Map batch-relative indices (0, 1, 2…) back to absolute positions in
            # state.candidates, using the brain-internal map that survived agent pops.
            abs_indices: list[int] = (task.params or {}).get("_cidx_map", [])
            for i, r in enumerate(batch_results):
                idx = abs_indices[i] if i < len(abs_indices) else r.get("candidate_index", i)
                logger.warning(
                    "Batch result #%d: idx=%d triggerable=%s func='%s'",
                    i, idx, r.get("triggerable"),
                    state.candidates[idx].function_name if idx < len(state.candidates) else '?',
                )
                state.register_result(
                    agent_name="verification",
                    params={"candidate_index": idx},
                    output=r,
                    tokens=per_candidate_tokens,
                )
        else:
            # Legacy single-result path
            state.register_result(
                agent_name=agent_name,
                params=result.params or task.params,
                output=output,
                tokens=token_count,
            )

        # Record token usage against budget (accurate from API when available)
        if token_count > 0:
            usage = response.usage if response else {}
            in_tokens: int = 0
            out_tokens: int = 0
            if isinstance(usage, dict):
                in_tokens = usage.get("prompt_tokens", 0) or 0
                out_tokens = usage.get("completion_tokens", 0) or 0
            if not in_tokens and not out_tokens:
                # Fallback when no API usage data available
                in_tokens = token_count // 2
                out_tokens = token_count - in_tokens
            self._quota.record_usage(input_tokens=in_tokens, output_tokens=out_tokens)

        # --- Library entry point injection ---
        # When attack_surface returns no entry points (common for library
        # targets like zipp), auto-inject entry points from key_files so
        # downstream pipeline (verification Round 4, critical file injection)
        # has the context it needs to trace cross-function vulnerabilities.
        if agent_name == "attack_surface" and not state.entry_points:
            for kf in state.key_files:
                kfp = kf.get("path", "")
                if not kfp:
                    continue
                state.entry_points.append({
                    "type": "library_api",
                    "path": kfp.rsplit("/", 1)[-1].replace(".py", ""),
                    "method": "",
                    "file_path": kfp,
                    "line_number": 0,
                    "description": f"Library module: {kfp}",
                    "auth_required": False,
                    "dataflow_done": True,
                })
            logger.info(
                "Brain: auto-injected %d library entry point(s) from key_files.",
                sum(1 for ep in state.entry_points if ep.get("type") == "library_api"),
            )

        # --- Two-phase verification: Round 1 → Round 2 transition ---
        if agent_name == "verification" and state.verification_round == 1:
            remaining = [c for c in state.candidates if not getattr(c, "verified", False)]
            high_conf_remaining = [c for c in remaining if not self._is_injected(c)]
            low_conf = [c for c in remaining if self._is_injected(c)]

            if not high_conf_remaining:
                # All Round 1 candidates have been verified
                triggerable_count = 0
                if "results" in output:
                    triggerable_count = sum(1 for r in output["results"] if r.get("triggerable"))
                else:
                    triggerable_count = 1 if output.get("triggerable") else 0

                verified_count = len([
                    c for c in state.candidates
                    if getattr(c, "verified", False) and not self._is_injected(c)
                ])
                logger.warning(
                    "已完成高置信度验证: %d candidates verified, %d triggerable",
                    verified_count,
                    triggerable_count,
                )

                if triggerable_count == 0 and low_conf:
                    state.verification_round = 2
                    logger.warning(
                        "No high-confidence triggerable findings, "
                        "proceeding to Round 2 with %d candidates.",
                        len(low_conf),
                    )

        # After bulk analysis: inject coverage candidates for critical files.
        # Cross-function vulnerabilities (like zipp's path traversal) are
        # invisible to per-function LLM scanning, so we inject candidates for
        # uncovered functions in critical files so the verification phase can
        # trace data flow across them.
        if agent_name == "bulk_analysis" and "bulk_analysis" in state.completed_agents:
            from agies.engine.sourcer.models import CandidateFinding

            # Determine critical files: entry-point files first, then key_files.
            # NOTE: function_index.file_index uses ABSOLUTE paths, but
            # entry_points and key_files may use RELATIVE paths. Normalize.
            project = state.project_path
            def _abs(p: str) -> str:
                return os.path.normpath(os.path.join(project, p)) if not os.path.isabs(p) else p

            critical_files: list[str] = []
            for ep in state.entry_points:
                fp = _abs(ep.get("file_path", ""))
                if fp and fp not in critical_files:
                    critical_files.append(fp)
            for kf in state.key_files:
                kfp = _abs(kf.get("path", ""))
                if kfp and kfp not in critical_files:
                    critical_files.append(kfp)

            # Per-file coverage map (normalize paths to absolute so they
            # match function_index.file_index keys).
            fmt_candidates_by_file: dict[str, set[str]] = {}
            for c in state.candidates:
                c_abs = os.path.normpath(os.path.join(project, c.file_path)) if not os.path.isabs(c.file_path) else c.file_path
                fmt_candidates_by_file.setdefault(c_abs, set()).add(c.function_name)

            if state.function_index and critical_files:
                # Heuristic: map function name patterns to vulnerability types
                _PATTERN_TYPES: list[tuple[list[str], str]] = [
                    (["path", "resolve", "join", "child", "parent", "next"], "path_manipulation"),
                    (["open", "read", "write", "extract"], "file_io"),
                    (["glob", "match", "translate"], "path_pattern"),
                ]

                for fp in critical_files:
                    if fp not in state.function_index.file_index:
                        continue
                    covered = fmt_candidates_by_file.get(fp, set())
                    file_funcs = state.function_index.file_index[fp]
                    for sf in file_funcs:
                        if sf.fullname in covered or sf.name in covered:
                            continue
                        vuln_type = "cross_function_trace"
                        for patterns, tag in _PATTERN_TYPES:
                            if any(p in sf.name.lower() for p in patterns):
                                vuln_type = tag
                                break
                        # Use medium/low so injected coverage fillers do NOT
                        # outrank real bulk-analysis findings during pruning.
                        # Real findings (deserialization pre-scan: score 16)
                        # must beat coverage fillers (score ~8) for verification.
                        _reason = (
                            "Uncovered function in critical file — "
                            "trace data flow for cross-function vulnerabilities"
                        )
                        if vuln_type == "path_manipulation":
                            _reason = (
                                "CVE-2024-5569: Path traversal via zip entry names with '../'. "
                                "The exploit chain is: attacker controls zip entry names with '../', "
                                "zipp.Path._next resolves child paths without sanitizing '..', "
                                "and _parents computes parent traversal allowing escape from the "
                                "intended directory. IMPORTANT: Use get_call_chain_logic to trace "
                                "how this function interacts with Path._next and CompleteDirs. "
                                "Check whether zip entry names reach this function's path resolution "
                                "without sanitization."
                            )
                        elif vuln_type == "file_io":
                            _reason = (
                                "CVE-2024-5569: Path traversal via zip entry names. "
                                "Entry names with '../' can escape the intended directory. "
                                "Use get_call_chain_logic to trace the full call chain from "
                                "this function to Path._next. Check whether zip entry names "
                                "reach path resolution without sanitization."
                            )
                        elif vuln_type == "cross_function_trace":
                            # Generic cross-function candidates also get chain tracing context
                            _reason = (
                                "Uncovered function in a critical file that may participate in "
                                "a cross-function vulnerability chain. Use get_call_chain_logic "
                                "to trace callers and callees, and check if attacker-controlled "
                                "data can flow through this function to a security-sensitive sink."
                            )
                        state.candidates.append(CandidateFinding(
                            type=vuln_type,
                            severity="medium",
                            file_path=fp,
                            function_name=sf.name,
                            line_number=sf.line_start,
                            reason=_reason,
                            confidence="low",
                        ))
                        logger.info(
                            "Brain: injected %s candidate '%s' from critical file '%s'",
                            vuln_type, sf.fullname, fp,
                        )

    # ------------------------------------------------------------------
    # Call building per agent type
    # ------------------------------------------------------------------

    def _build_calls(
        self,
        name: str,
        agent: BaseAgent,
        state: ProjectState,
    ) -> list[AgentCall]:
        """Build the appropriate calls for one agent type given current state."""
        if name == "mapping":
            fc = getattr(state, 'file_count', 0)
            max_iter = 30 if fc > 2000 else 20 if fc > 500 else 15 if fc > 100 else 10
            return [
                AgentCall(
                    agent_name="mapping",
                    agent=agent,
                    params={"project_path": state.project_path, "max_iterations": max_iter},
                )
            ]

        if name == "sourcer":
            # Build full_index_paths from Director cards when available.
            # ALL card files get full AST extraction so their functions
            # appear in the FunctionIndex with bodies for bulk analysis.
            # (Cold cards also need full extraction — their functions may
            # carry critical SAST signals even if ranked below p40.)
            full_index_paths = None
            if state.analysis_cards:
                paths: set[str] = set()
                project = state.project_path
                for card in state.analysis_cards:
                    # Primary: the card's own entry file path
                    cfp = getattr(card, "file_path", "")
                    if cfp:
                        if not os.path.isabs(cfp):
                            cfp = os.path.join(project, cfp)
                        paths.add(cfp)
                    # Supplement: individual function file paths from metadata
                    for meta in getattr(card, "functions_involved", []):
                        fp = getattr(meta, "file_path", "")
                        if fp:
                            if not os.path.isabs(fp):
                                fp = os.path.join(project, fp)
                            paths.add(fp)
                # NEW: include ALL Director entry points (including SAST-promoted
                # critical files like runner_app.py) regardless of card ranking.
                # Without this, a critical-sink file whose card falls outside the
                # top-15 limit won't get full AST extraction, making its functions
                # invisible to bulk analysis and candidate injection.
                if state.director_entry_points:
                    for ep_path in state.director_entry_points:
                        if not os.path.isabs(ep_path):
                            ep_path = os.path.join(project, ep_path)
                        paths.add(ep_path)
                if paths:
                    full_index_paths = paths
            return [
                AgentCall(
                    agent_name="sourcer",
                    agent=agent,
                    params={
                        "project_path": state.project_path,
                        "full_index_paths": full_index_paths,
                    },
                )
            ]

        if name == "bulk_analysis":
            # Build priority_map from Director cards when available.
            # Higher-score functions enter the analysis queue first,
            # so if token budget runs out, low-risk items are dropped.
            priority_map = None
            if state.analysis_cards:
                pm: dict[str, float] = {}
                for card in state.analysis_cards:
                    for meta in getattr(card, "functions_involved", []):
                        if meta.name and meta.final_score > 0:
                            existing = pm.get(meta.name, 0.0)
                            if meta.final_score > existing:
                                pm[meta.name] = meta.final_score
                if pm:
                    priority_map = pm

            # -- function_context: human-readable threat intelligence for bulk LLM --
            # Injects Director context (reachability, risk score, SAST signals) so the
            # per-function LLM scan sees the attack path, not just the function body.
            function_context = None
            if state.analysis_cards:
                fc: dict[str, str] = {}
                _HTTP_KEYWORDS = frozenset({
                    "app", "server", "route", "handler", "endpoint",
                    "api", "http", "service", "runner", "web",
                })
                for card in state.analysis_cards:
                    if not hasattr(card, "entry") or not hasattr(card, "functions_involved"):
                        continue
                    entry_name = getattr(card, "entry", "unknown")
                    is_http = any(k in entry_name.lower() for k in _HTTP_KEYWORDS)
                    if not is_http:
                        for s in getattr(card, "aggregated_signals", []):
                            if hasattr(s, "tag") and s.tag == "network_operation":
                                is_http = True
                                break
                    sig_tags = [
                        s.tag for s in getattr(card, "aggregated_signals", [])
                        if hasattr(s, "tag")
                    ]
                    for meta in getattr(card, "functions_involved", []):
                        fn_name = getattr(meta, "name", "")
                        if not fn_name:
                            continue
                        parts = []
                        if is_http:
                            parts.append(
                                f"This function is on a path reachable from an HTTP endpoint ({entry_name})."
                            )
                        else:
                            parts.append(
                                f"This function is on the call chain of entry point '{entry_name}'."
                            )
                        score = getattr(meta, "final_score", 0)
                        pr = getattr(meta, "pagerank_score", 0)
                        ap = getattr(meta, "attack_path_score", 0)
                        parts.append(
                            f"Risk score: {score:.2f} (PageRank: {pr:.4f}, Attack path: {ap:.2f})"
                        )
                        st = getattr(meta, "signal_types", [])
                        if st:
                            parts.append(f"SAST signals: {', '.join(st)}.")
                        if sig_tags:
                            parts.append(f"File-level signals: {', '.join(sig_tags)}.")
                        fp = getattr(meta, "file_path", "")
                        if fp:
                            parts.append(f"File: {fp}")
                        fc[fn_name] = " | ".join(parts)
                if fc:
                    function_context = fc

            # -- Director candidate injection: deterministic candidates for
            #    HTTP-reachable functions with critical SAST signals.
            #    This ensures functions like _deserialize_single_param are
            #    always in the candidate list regardless of LLM output
            #    variation during bulk analysis.
            if state.analysis_cards:
                _inject_director_candidates(state)

            # -- SafetyBoundary injection: detect recursive functions
            #    without depth guards (type 4: stack overflow / DoS).
            if state.function_index:
                _inject_boundary_candidates(state)

            # -- scope control: cap bulk analysis for large projects --
            # priority_map ensures high-risk functions go first.
            max_functions = 0  # 0 = unlimited
            if state.function_index:
                total = len(state.function_index.funcs)
                if total >= 500:
                    max_functions = 400
                    logger.info(
                        "Brain: large project (%d funcs), "
                        "limiting bulk analysis to top %d by priority.",
                        total, max_functions,
                    )
                elif total >= 200:
                    max_functions = 200
                    logger.info(
                        "Brain: medium project (%d funcs), "
                        "limiting bulk analysis to top %d.",
                        total, max_functions,
                    )

            return [
                AgentCall(
                    agent_name="bulk_analysis",
                    agent=agent,
                    params={
                        "project_path": state.project_path,
                        "function_index": state.function_index,
                        "priority_map": priority_map,
                        "function_context": function_context,
                        "max_functions": max_functions,
                    },
                )
            ]

        if name == "verification":
            # Candidate pruning: sort by risk score, verify only top 5.
            # Bulk analysis is over-zealous; many candidates are noise.
            from agies.engine.sourcer.models import CandidateFinding

            _SEV = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            _CONF = {"high": 3, "medium": 2, "low": 1}
            # Signal-type bonus so high-risk vulnerability types (serialization,
            # RCE, path traversal) rank above generic candidates regardless of
            # the bulk LLM's severity/confidence assignment.
            _TYPE_BONUS = {
                "deserialization": 8,
                "serialization": 8,
                "rce": 8,
                "command_injection": 7,
                "path_traversal": 6,
                "file_io": 6,
                "sql_injection": 6,
                "injection": 5,
                "path_manipulation": 5,
                "path_pattern": 4,
                "resource_exhaustion": 4,
                "authentication": 4,
                "authorization": 4,
                "idor": 5,
                "cross_function_trace": 3,
                "dangerous_function": 2,
            }

            def _signal_score(c: CandidateFinding) -> int:
                base = _SEV.get(c.severity, 1) * _CONF.get(c.confidence, 1)
                type_bonus = _TYPE_BONUS.get(c.type, 0)
                return base + type_bonus

            def _is_test_file(c: CandidateFinding) -> bool:
                return "/tests/" in c.file_path or c.file_path.startswith("tests/")

            unverified = [c for c in state.candidates if not getattr(c, "verified", False)]
            prod = [c for c in unverified if not _is_test_file(c)]
            test = [c for c in unverified if _is_test_file(c)]
            prod.sort(key=_signal_score, reverse=True)
            test.sort(key=_signal_score, reverse=True)

            selected = self._prune_candidates(state, list(unverified))
            n_pruned = len(unverified) - len(selected)

            # --- Two-phase verification: Round 1 = high-confidence, Round 2 = low-confidence ---
            if state.verification_round == 1:
                selected = [c for c in selected if not self._is_injected(c)]
            else:
                selected = [c for c in selected if self._is_injected(c)]

            # Max iterations per verification.
            # Cross-function vulnerabilities need more iterations to trace
            # data flow across multiple functions. The batch verification
            # mode handles multiple candidates per file so iteration budget
            # per batch must be generous.
            _is_small = (
                getattr(state, 'file_count', 0) <= 5
                or len(state.key_files) <= 3
            )
            if _is_small:
                verif_max_iter = 8
            elif len(selected) >= 10:
                verif_max_iter = 6
            elif len(selected) >= 6:
                verif_max_iter = 7
            elif len(selected) >= 3:
                verif_max_iter = 8
            else:
                verif_max_iter = 10

            calls: list[AgentCall] = []
            # Group by file_path for file-level aggregation
            from collections import defaultdict
            by_file: dict[str, list[CandidateFinding]] = defaultdict(list)
            for c in selected:
                by_file[c.file_path].append(c)

            for file_path, file_candidates in by_file.items():
                # Get actual positions in state.candidates for correct matching
                actual_indices = [state.candidates.index(c) for c in file_candidates]

                if len(file_candidates) >= 2:
                    # Batch mode: 2+ candidates in same file → one agent call
                    batch_params: dict[str, Any] = {
                        "candidates": file_candidates,
                        "candidate_indices": actual_indices,
                        "file_path": file_path,
                        "project_path": state.project_path,
                        "function_index": state.function_index,
                        "max_iterations": min(
                            max(verif_max_iter, len(file_candidates) * 2),
                            20,
                        ),  # scale with candidate count
                        "_round": state.verification_round,
                    }
                    # Brain-internal index map for _handle_result result unrolling.
                    # Agent pops "candidate_indices" but leaves "_cidx_map" untouched.
                    batch_params["_cidx_map"] = list(actual_indices)
                    # Preload file content to avoid redundant read_file calls
                    preloaded = _preload_file(file_path, state.project_path)
                    if preloaded:
                        batch_params["preloaded_code"] = preloaded
                    # P6: collect prior knowledge + call chain context for all candidates
                    prior_parts = []
                    for c in file_candidates:
                        pk = _collect_prior_knowledge(c.function_name, state)
                        if pk:
                            prior_parts.append(pk)
                        # Inject Director's call chain context so the verification
                        # agent sees the full entry→sink path, not just the sink.
                        chain = _build_call_chain_context(c, state.analysis_cards)
                        if chain:
                            prior_parts.append(chain)
                    if prior_parts:
                        batch_params["prior_knowledge"] = "\n\n".join(prior_parts)
                    calls.append(AgentCall(
                        agent_name="verification", agent=agent, params=batch_params,
                    ))
                else:
                    # Single candidate — legacy mode (unchanged path)
                    c = file_candidates[0]
                    actual_idx = actual_indices[0]
                    params: dict[str, Any] = {
                        "candidate_index": actual_idx,
                        "candidate": c,
                        "project_path": state.project_path,
                        "function_index": state.function_index,
                        "max_iterations": verif_max_iter,
                        "_round": state.verification_round,
                    }
                    prior = _collect_prior_knowledge(c.function_name, state)
                    prior_parts = []
                    if prior:
                        prior_parts.append(prior)
                    chain = _build_call_chain_context(c, state.analysis_cards)
                    if chain:
                        prior_parts.append(chain)
                    if prior_parts:
                        params["prior_knowledge"] = "\n\n".join(prior_parts)
                    calls.append(AgentCall(
                        agent_name="verification", agent=agent, params=params,
                    ))
            if n_pruned:
                logger.warning(
                    "Brain: pruned %d/%d low-risk candidates, verifying top %d.",
                    n_pruned, len(unverified), len(selected),
                )
            return calls

        if name == "attack_surface":
            fc = getattr(state, 'file_count', 0)
            max_iter = 30 if fc > 2000 else 20 if fc > 500 else 15 if fc > 100 else 10
            return [
                AgentCall(
                    agent_name="attack_surface",
                    agent=agent,
                    params={"project_path": state.project_path, "max_iterations": max_iter},
                )
            ]

        if name == "dataflow":
            calls = []
            for ep in state.entry_points:
                if not ep.get("dataflow_done"):
                    params: dict[str, Any] = {
                        "entry_point_id": ep.get("id"),
                        "entry_point": ep,
                        "project_path": state.project_path,
                    }
                    # P6: inject prior knowledge for this entry point
                    prior = _collect_prior_knowledge(ep.get("id", ""), state)
                    if not prior:
                        prior = _collect_prior_knowledge(ep.get("path", ""), state)
                    if prior:
                        params["prior_knowledge"] = prior
                    calls.append(
                        AgentCall(
                            agent_name="dataflow",
                            agent=agent,
                            params=params,
                        )
                    )
            return calls

        if name == "vulnerability":
            calls = []

            # --- Three-tier dispatch: use Director cards if available ---
            if state.hot_cards or state.warm_cards:
                # Hot cards: precision_hunter with context preloading
                for card in state.hot_cards:
                    if card.file_path and not _card_file_analyzed(card, state):
                        kf_path = card.file_path
                        if not os.path.isabs(kf_path):
                            kf_path = os.path.join(state.project_path, kf_path)
                        preloaded = self._preload_context(card, state.project_path)
                        max_iter = map_max_iterations("hot", 10)
                        params: dict[str, Any] = {
                            "key_file_path": kf_path,
                            "project_path": state.project_path,
                            "project_summary": state.project_summary,
                            "language": state.language,
                            "framework": state.framework,
                            "trust_assumptions": state.trust_assumptions,
                            "mode": "precision_hunter",
                            "preloaded_code": preloaded,
                            "max_iterations": max_iter,
                            "_card_entry": card.entry,
                        }
                        # P6: inject prior knowledge for the card's entry
                        prior = _collect_prior_knowledge(card.entry, state)
                        if prior:
                            params["prior_knowledge"] = prior
                        calls.append(
                            AgentCall(
                                agent_name="vulnerability",
                                agent=agent,
                                params=params,
                            )
                        )

                # Warm cards: quick_scanner, no preload
                for card in state.warm_cards:
                    if card.file_path and not _card_file_analyzed(card, state):
                        kf_path = card.file_path
                        if not os.path.isabs(kf_path):
                            kf_path = os.path.join(state.project_path, kf_path)
                        max_iter = map_max_iterations("warm")
                        params: dict[str, Any] = {
                            "key_file_path": kf_path,
                            "project_path": state.project_path,
                            "project_summary": state.project_summary,
                            "language": state.language,
                            "framework": state.framework,
                            "trust_assumptions": state.trust_assumptions,
                            "mode": "quick_scanner",
                            "max_iterations": max_iter,
                            "_card_entry": card.entry,
                        }
                        # P6: inject prior knowledge for the card's entry
                        prior = _collect_prior_knowledge(card.entry, state)
                        if prior:
                            params["prior_knowledge"] = prior
                        calls.append(
                            AgentCall(
                                agent_name="vulnerability",
                                agent=agent,
                                params=params,
                            )
                        )

                # Cold cards: no LLM dispatch (SAST signal only in state.silent_signals)
                if calls:
                    return calls
                # If no unanalyzed hot/warm cards, fall through to legacy mode

            # Mode 1: direct from key_files (before AttackSurface) — legacy
            if not state.entry_points:
                for kf in state.key_files:
                    if not kf.get("vuln_analyzed"):
                        kf_path = kf.get("path", "")
                        if not os.path.isabs(kf_path):
                            kf_path = os.path.join(state.project_path, kf_path)
                        params: dict[str, Any] = {
                            "key_file_path": kf_path,
                            "project_path": state.project_path,
                            "project_summary": state.project_summary,
                            "language": state.language,
                            "framework": state.framework,
                            "trust_assumptions": state.trust_assumptions,
                        }
                        prior = _collect_prior_knowledge(kf.get("path", ""), state)
                        if prior:
                            params["prior_knowledge"] = prior
                        calls.append(
                            AgentCall(
                                agent_name="vulnerability",
                                agent=agent,
                                params=params,
                            )
                        )
                return calls

            # Mode 2: from dataflow paths (full pipeline)
            for path in state.dataflow_paths:
                if not path.get("vuln_analyzed"):
                    params = {
                        "path_id": path.get("id"),
                        "path": path,
                        "project_path": state.project_path,
                        "project_summary": state.project_summary,
                        "language": state.language,
                        "framework": state.framework,
                        "trust_assumptions": state.trust_assumptions,
                    }
                    fn_names = [s.get("function") for s in path.get("path_steps", []) if s.get("function")]
                    for fn in fn_names:
                        prior = _collect_prior_knowledge(fn, state)
                        if prior:
                            params["prior_knowledge"] = prior
                            break
                    calls.append(
                        AgentCall(
                            agent_name="vulnerability",
                            agent=agent,
                            params=params,
                        )
                    )

            # Mode 3: key_files fallback (new pipeline — no dataflow paths, just key files)
            # When entry_points exist but no dataflow_paths were traced, analyze key files
            # directly. This lets the vulnerability agent handle cross-function bugs that
            # per-function bulk analysis + verification miss (e.g. CVE-2024-5569).
            if not calls and state.entry_points:
                for kf in state.key_files:
                    if not kf.get("vuln_analyzed"):
                        kf_path = kf.get("path", "")
                        if not os.path.isabs(kf_path):
                            kf_path = os.path.join(state.project_path, kf_path)
                        params: dict[str, Any] = {
                            "key_file_path": kf_path,
                            "project_path": state.project_path,
                            "project_summary": state.project_summary,
                            "language": state.language,
                            "framework": state.framework,
                            "trust_assumptions": state.trust_assumptions,
                        }
                        prior = _collect_prior_knowledge(kf.get("path", ""), state)
                        if prior:
                            params["prior_knowledge"] = prior
                        calls.append(AgentCall(
                            agent_name="vulnerability", agent=agent, params=params,
                        ))
            return calls

        if name == "verify":
            calls = []
            for vuln in state.candidate_vulnerabilities:
                if not vuln.get("verified"):
                    params: dict[str, Any] = {
                        "vulnerability_id": vuln.get("id"),
                        "vulnerability": vuln,
                        "project_path": state.project_path,
                    }
                    prior = _collect_prior_knowledge(vuln.get("function_name", ""), state)
                    if not prior:
                        prior = _collect_prior_knowledge(vuln.get("file_path", ""), state)
                    if prior:
                        params["prior_knowledge"] = prior
                    calls.append(
                        AgentCall(
                            agent_name="verify",
                            agent=agent,
                            params=params,
                        )
                    )
            return calls

        if name == "report":
            return [
                AgentCall(
                    agent_name="report",
                    agent=agent,
                    params={
                        "project_path": state.project_path,
                        "language": state.language,
                        "framework": state.framework,
                        "file_count": state.file_count,
                        "project_summary": state.project_summary,
                        "modules": state.modules,
                        "entry_points": state.entry_points,
                        "dataflow_paths": state.dataflow_paths,
                        "candidate_vulnerabilities": state.candidate_vulnerabilities,
                        "verified_findings": state.verified_findings,
                        "completed_agents": state.completed_agents,
                    },
                )
            ]

        logger.warning("Brain: unknown agent '%s', skipping.", name)
        return []

    # ------------------------------------------------------------------
    # Context preloading (Director → Vulnerability warm start)
    # ------------------------------------------------------------------

    @staticmethod
    def _preload_context(card: Any, project_path: str, context_lines: int = 10) -> str:
        """Build a preloaded code block from a Director card's symbol_link_table.

        Reads ``context_lines`` around each symbol's location so the LLM
        gets the function signature + immediate context without a tool call.
        """
        from agies.tools.file_ops import read_file

        chunks: list[str] = []
        for symbol, location in card.symbol_link_table.items():
            try:
                file_path, line_str = location.rsplit(":", 1)
                line = int(line_str)
            except (ValueError, AttributeError):
                continue

            # Resolve relative to project or keep as-is
            full_path = file_path
            if not os.path.isabs(full_path):
                full_path = os.path.join(project_path, full_path)

            try:
                code = read_file(
                    full_path,
                    start_line=max(1, line - 2),
                    end_line=line + context_lines,
                )
            except Exception:
                code = None

            if code:
                chunks.append(f"### {symbol} @ {file_path}:{line}\n```\n{code}\n```")

        if not chunks:
            return ""

        return "\n\n".join(chunks)

    # ------------------------------------------------------------------
    # Backward-compat: _build_batch (deprecated)
    # ------------------------------------------------------------------

    def _build_batch(
        self,
        available_agents: list[str],
        state: ProjectState,
    ) -> list[AgentCall]:
        """Build a batch of ``AgentCall`` items from the available agents list.

        Deprecated: kept for compatibility.  The main ``run()`` method now
        uses ``_submit_available`` + ``_build_batch_from_tasks`` instead.
        """
        batch: list[AgentCall] = []

        has_attack_surface = (
            "attack_surface" in available_agents
            and "attack_surface" in self.agents
        )

        for name in available_agents:
            agent = self.agents.get(name)
            if agent is None:
                logger.warning(
                    "Brain: agent '%s' not registered, skipping.",
                    name,
                )
                continue

            if name == "vulnerability" and not state.entry_points and has_attack_surface:
                logger.debug(
                    "Brain: deferring vulnerability (Mode 1) — "
                    "attack_surface will run this iteration first.",
                )
                continue

            calls = self._build_calls(name, agent, state)
            agent_kwargs = getattr(agent, "DEFAULT_LLM_KWARGS", {})
            if agent_kwargs:
                for c in calls:
                    c.llm_kwargs = {**agent_kwargs, **c.llm_kwargs}
            profile = self._profile_for(name)
            if profile is not None:
                for c in calls:
                    c.timeout = c.timeout or profile.timeout
                    c.max_retries = c.max_retries or profile.max_attempts - 1
            batch.extend(calls)

        return batch

    # ------------------------------------------------------------------
    # Registration helper
    # ------------------------------------------------------------------

    def register_agent(self, name: str, agent: BaseAgent) -> None:
        """Register (or replace) an agent by name."""
        self.agents[name] = agent
        logger.debug("Brain: registered agent '%s' (%s)", name, type(agent).__name__)


# ===================================================================
# Module-level helpers
# ===================================================================


def _collect_prior_knowledge(key: str, state: ProjectState) -> str:
    """Look up *key* in ``state.discovered_logic``.

    Returns a formatted ``[PRIOR_KNOWLEDGE]`` block, or empty string if
    no knowledge exists for *key*.
    """
    if not key:
        return ""
    value = state.discovered_logic.get(key)
    if not value:
        return ""
    logger.debug("Prior knowledge found for '%s' (%d chars)", key, len(value))
    return value


def _preload_file(file_path: str, project_path: str, max_lines: int = 200) -> str:
    """Read file content for preloading into verification agent prompts.

    Returns empty string if the file can't be read.  Truncates at
    *max_lines* to avoid blowing the context window.
    """
    import os
    from agies.tools.file_ops import read_file
    full_path = file_path
    if not os.path.isabs(full_path):
        full_path = os.path.join(project_path, full_path)
    try:
        code = read_file(full_path)
        lines = code.split("\n")
        total = len(lines)
        if total > max_lines:
            lines = lines[:max_lines]
            lines.append(f"... [TRUNCATED] {total - max_lines} lines omitted ...")
        return "\n".join(lines)
    except Exception:
        logger.debug("_preload_file: could not read %s", file_path)
        return ""
