"""v3 pipeline orchestrator — path discovery → slicing → analysis → verify.

Entry point called from ``agies audit --v3``.

Phases
------
Phase A:  Path discovery — tree-sitter (default) or CodeQL (if available)
Phase B:  Path slicing & ranking (Explore/Exploit)
Phase C:  README understanding
Phase D:  Parallel Intent Agent + Logic Agent
Phase E:  Blackboard aggregation
Phase F:  Verification & report
"""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agies.engine.v3.codeql.models import VulnType, VULN_LABELS, QueryResult, Reachability
from agies.engine.v3.slicer import select_top_k
from agies.engine.v3.slicer.models import SortResult
from agies.engine.v3.aggregator.blackboard import BlackboardAggregator
from agies.engine.v3.aggregator.models import AgentPhaseResult, IntentResult
from agies.engine.v3.aggregator.token_counter import TokenCounter, QuotaExceededException
from agies.engine.v3.agents.intent_agent import IntentAgent, IntentAgentTask
from agies.engine.v3.agents.logic_agent import LogicAgent
from agies.engine.v3.agents.adversary_agent import AdversaryAgent
from agies.engine.v3.agents.poc_agent import PoCAgent
from agies.engine.v3.agents.merge import MergeLayer
from agies.engine.v3.agents.path_code_loader import PathCodeLoader
from agies.engine.v3.agents.evidence_checker import EvidenceChecker
from agies.engine.v3.agents.bridge_verifier import (
    BridgeVerifier, BridgeAnnotation, scan_path_bridge_evidence,
)
from agies.engine.v3.classifier import classify_project

logger = logging.getLogger(__name__)

# Rich display is optional
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False
    Console = None


def run_v3_pipeline(
    target: str,
    model: str = "deepseek-chat",
    verbose: bool = False,
    codeql_bin: str = "",
    db_dir: str = "",
    use_codeql: bool = False,
    max_exploit: int = 30,
    max_explore: int = 15,
    max_intent_workers: int = 5,
    exclude_test: bool = False,
    project_type: str = "auto",
    consensus: bool = False,
) -> None:
    """Run the complete v3 pipeline against *target*.

    Parameters
    ----------
    target : str
        Project directory to analyze.
    model : str
        LLM model name for Phase C + D.
    verbose : bool
        Print detailed progress.
    codeql_bin : str
        Path to CodeQL CLI.
    db_dir : str
        Existing CodeQL database dir.
    use_codeql : bool
        Use CodeQL instead of tree-sitter for path discovery.
    max_exploit : int
        Max exploit-slot paths (default 25).
    max_explore : int
        Max explore-slot paths (default 10).
    max_intent_workers : int
        Parallel Intent Agent workers (default 5).
    exclude_test : bool
        Exclude paths originating in test files (default False — wider net).
    project_type : str
        ``"auto"`` (default) — auto-detect, ``"app"`` — web application,
        ``"lib"`` — library / framework.
    """
    console = Console() if _HAS_RICH else None
    target = os.path.abspath(target)

    if not os.path.isdir(target):
        _print(console, f"Error: target must be a directory: {target}")
        return

    pipeline_start = time.time()

    # Initialize LLM provider (shared across phases)
    llm = _init_llm(model, console)
    if llm is None:
        return

    # ==================================================================
    # Phase A: Path Discovery
    # ==================================================================
    _print_header(console, "Phase A: Path Discovery")

    results: list[QueryResult] = []
    function_index = None
    if use_codeql:
        results = _run_codeql_discovery(console, target, codeql_bin, db_dir, verbose)
    else:
        results, function_index = _run_treesitter_discovery(console, target, verbose)

    if not results:
        _print(console, "  [yellow]No path discovery results.[/yellow]")
        return

    # ==================================================================
    # Phase B: Path Slicing & Ranking
    # ==================================================================
    total_paths = sum(r.total_sinks for r in results)
    _print_header(console, f"Phase B: Slice Sorting ({total_paths} raw paths)")

    if total_paths == 0:
        _print(console, "  [dim]No dangerous sinks found. Nothing to analyze.[/dim]")
        return

    all_paths = [p for r in results for p in r.paths]
    sort_result = select_top_k(
        all_paths,
        max_exploit=max_exploit,
        max_explore=max_explore,
        exclude_test=exclude_test,
    )

    body_only_count = sum(
        1 for p in all_paths
        if getattr(p, "reachability", Reachability.CHAIN) in
        (Reachability.BODY_ONLY, Reachability.EXTERNAL_API)
    )
    if body_only_count:
        _print(console, f"  [dim]Body-detected orphans: {body_only_count} (no call chain)[/dim]")
    _print(console, f"  Exploit: {len(sort_result.exploit)} + Explore: {len(sort_result.explore)}")
    for s in sort_result.explore[:3]:
        reasons = f" ({', '.join(s.anomaly_reasons)})" if s.anomaly_reasons else ""
        reach_tag = f" [{s.reachability.value}]" if s.reachability != Reachability.CHAIN else ""
        _print(console, f"    [dim]Explore: {s.id} {s.sink} score={s.score:.2f}{reach_tag}{reasons}[/dim]")

    # Free Phase A memory — thousands of CodeQlPath/PathNode objects and
    # function bodies are no longer needed once slicing is complete.
    # Keeping them through the LLM-heavy Phase D can cause OOM.
    # NOTE: SourceFunction is @dataclass(frozen=True), so fn.body = ""
    # raises FrozenInstanceError.  Use slim() which rebuilds the funcs
    # list with body="" and clears source file texts (frees ~60-80%).
    results.clear()
    all_paths.clear()
    if function_index is not None:
        function_index.slim()

    # ==================================================================
    # Project Type Detection
    # ==================================================================
    if project_type == "auto":
        project_type = classify_project(target)
    _print(console, f"  [cyan]Project type: {project_type}[/cyan]")

    # ==================================================================
    # Phase C: README Understanding (app mode only)
    # ==================================================================
    _print_header(console, "Phase C: README Understanding")

    if project_type == "app":
        readme_text = _try_read_readme(target)
        if readme_text:
            _print(console, f"  README: {len(readme_text)} chars")
            with _status(console, "LLM: summarizing README..."):
                readme_summary = _summarize_readme(llm, readme_text)
        else:
            _print(console, "  [dim]No README found.[/dim]")
            readme_summary = ""

        if readme_summary:
            _print(console, f"  Summary: {readme_summary[:120]}...")
        else:
            _print(console, "  [dim](skipped)[/dim]")
    else:
        readme_summary = ""
        _print(console, "  [dim](skipped — library mode)[/dim]")

    # ==================================================================
    # Phase D: Dual Pipeline
    # ==================================================================
    blackboard = BlackboardAggregator()

    # Initialize token budget counter — defaults to 1M tokens, use
    # AGIES_TOKEN_BUDGET env var to override.  0 = unlimited.
    token_budget = int(os.environ.get("AGIES_TOKEN_BUDGET", "1000000"))
    _init_token_counter(budget=token_budget)
    if token_budget > 0:
        _print(
            console,
            f"  [dim]Token budget: {token_budget:,} tokens[/dim]",
        )

    try:
        if project_type == "app":
            _print_header(console, f"Phase D: Intent+Logic Agents ({len(sort_result.all_slices)} slices)")
            phase_results = _run_phase_d(
                sort_result=sort_result,
                llm=llm,
                blackboard=blackboard,
                readme_summary=readme_summary,
                max_workers=max_intent_workers,
                console=console,
                target=target,
                function_index=function_index,
                consensus=consensus,
            )
        else:
            _print_header(console, f"Phase D: Library Analysis ({len(sort_result.all_slices)} slices)")
            phase_results = _run_phase_d_lib(
                sort_result=sort_result,
                llm=llm,
                blackboard=blackboard,
                console=console,
                function_index=function_index,
                target=target,
                consensus=consensus,
            )
    except QuotaExceededException as qe:
        _print(console, f"  [red]Token budget exceeded ({qe.total_used:,}/{qe.budget:,}) — stopping.[/red]")
        phase_results = []

    # ==================================================================
    # Phase E: Blackboard summary
    # ==================================================================
    _print_header(console, "Phase E: Results")

    high_conf = [r for r in phase_results if r.confidence >= 7]
    medium_conf = [r for r in phase_results if 4 <= r.confidence < 7]

    _print(console, f"  {blackboard.summary()}")

    if high_conf:
        _print(console, f"  [red]High confidence ({len(high_conf)}):[/red]")
        for r in high_conf:
            for c in r.contradictions[:2]:
                _print(console, f"    {r.path_id}: {c.get('func', '?')} — {c.get('contradiction_type', '?')}")
                _print(console, f"      [dim]{c.get('bypass_poc', '')}[/dim]")
    elif medium_conf:
        _print(console, f"  [yellow]Interesting ({len(medium_conf)}):[/yellow]")
        for r in medium_conf[:5]:
            _print(console, f"    {r.path_id}: path {r.vuln_type} score={r.score:.2f}")
    else:
        _print(console, "  [dim]No contradictions found.[/dim]")

    # ==================================================================
    # Summary
    # ==================================================================
    elapsed = time.time() - pipeline_start
    _print_header(console, "Pipeline Complete")

    _print(console, f"  Target: {target}")
    _print(console, f"  Model: {model}")
    _print(console, f"  Duration: {elapsed:.1f}s")
    _print(console, f"  Paths discovered: {total_paths}")
    _print(console, f"  Slices analyzed: {len(sort_result.all_slices)}")
    _print(console, f"  Findings: {len(high_conf)} high, {len(medium_conf)} interesting")
    if _TOKEN_COUNTER and _TOKEN_COUNTER.total_tokens > 0:
        _print(console, f"  Tokens: {_TOKEN_COUNTER.total_tokens:,} total "
               f"({_TOKEN_COUNTER.prompt_tokens:,} prompt + "
               f"{_TOKEN_COUNTER.completion_tokens:,} completion)")

    if high_conf:
        _print(console, "")
        _print(console, "  [bold]Recommended verification targets:[/bold]")
        for r in high_conf[:5]:
            _print(console, f"    {r.vuln_type.upper()} {r.path_id}: {r.analysis[:100]}")


# ======================================================================
# Phase A implementations
# ======================================================================


def _run_treesitter_discovery(
    console: Any, target: str, verbose: bool,
) -> tuple[list[QueryResult], Any]:
    from agies.engine.v3.pathfinder import TreeSitterPathFinder
    _print(console, "  [cyan]Backend: tree-sitter[/cyan]")

    finder = TreeSitterPathFinder(target)
    with _status(console, "Building function index..."):
        finder.build_index()

    _print(console, f"  Functions: {len(finder.index.funcs) if finder.index else 0}")

    with _status(console, "Discovering sink paths..."):
        results = finder.run_all()

    for r in results:
        if r.total_sinks > 0:
            _print(console, f"    {r.label}: {r.total_sinks} sink(s)")

    return results, finder.index


def _run_codeql_discovery(
    console: Any, target: str, codeql_bin: str, db_dir: str, verbose: bool,
) -> list[QueryResult]:
    from agies.engine.v3.codeql.query import CodeQLQueryRunner
    _print(console, "  [cyan]Backend: CodeQL[/cyan]")

    if not codeql_bin:
        codeql_bin = CodeQLQueryRunner._find_codeql()
    if not codeql_bin:
        _print(console, "  [yellow]CodeQL not found, falling back to tree-sitter.[/yellow]")
        results, _ = _run_treesitter_discovery(console, target, verbose)
        return results

    runner = CodeQLQueryRunner(
        project_path=target,
        codeql_bin=codeql_bin,
        query_dir=os.path.join(os.path.dirname(__file__), "codeql", "queries"),
        db_dir=db_dir or "",
    )
    with _status(console, "CodeQL: database create + queries..."):
        try:
            results = runner.run_all()
        except Exception as exc:
            _print(console, f"  [red]CodeQL error: {exc}[/red]")
            _print(console, "  [yellow]Falling back to tree-sitter.[/yellow]")
            results, _ = _run_treesitter_discovery(console, target, verbose)
            return results

    _print(console, runner.summary_text(results))
    return results


# ======================================================================
# Phase D: Intent Agent + Logic Agent (real LLM)
# ======================================================================


def _build_call_context(sink_name: str, sink_file: str, function_index) -> str:
    """Build caller/callee context from FunctionIndex for verification.

    Works with tree-sitter and CodeQL backed indexes — both populate
    the same ``FunctionIndex.call_graph`` structure.
    """
    if function_index is None:
        return ""
    lines: list[str] = []

    callers = function_index.find_callers(sink_name)
    if callers:
        lines.append("Callers (functions that call this sink):")
        for fn in callers[:10]:
            lines.append(f"  {fn.fullname} ({fn.file_path}:{fn.line_start})")

    callees = function_index.find_callees(sink_name)
    if callees:
        lines.append("Callees (functions called by this sink):")
        for fn in callees[:10]:
            lines.append(f"  {fn.fullname} ({fn.file_path}:{fn.line_start})")

    if not lines:
        return ""

    return "\nCall Graph Context\n----\n" + "\n".join(lines) + "\n\n"


def _run_phase_d(
    sort_result: SortResult,
    llm: Any,
    blackboard: BlackboardAggregator,
    readme_summary: str,
    max_workers: int,
    console: Any,
    target: str,
    function_index=None,
    consensus: bool = False,
) -> list[AgentPhaseResult]:
    """Run Phase D with real LLM calls and verification routing.

    When ``slice_.nodes`` is empty (tree-sitter paths without explicit node
    lists), creates a fallback pseudo-node from the sink metadata.
    Routes 4-6 confidence findings to verification with call graph context
    for potential upgrade.
    """
    project_path = os.path.abspath(target) if target else ""
    loader = PathCodeLoader(project_path=project_path, blackboard=blackboard)
    intent_agent = IntentAgent()
    logic_agent = LogicAgent()
    merge_layer = MergeLayer()
    all_results: list[AgentPhaseResult] = []

    for i, slice_ in enumerate(sort_result.all_slices):
        _print(console, f"  [{i+1}/{len(sort_result.all_slices)}] {slice_.id} ({slice_.sink})")

        # Build nodes: use real path nodes if available, otherwise create
        # a pseudo-node from the sink metadata so Intent Agent has code.
        nodes: list[dict[str, Any]] = [{
            "function_name": slice_.sink,
            "file_path": slice_.sink_file.split(":")[0],
            "line_number": int(slice_.sink_file.split(":")[1]) if ":" in slice_.sink_file else 0,
        }]
        if slice_.nodes:
            nodes = slice_.nodes

        # Prepare tasks via PathCodeLoader (checks blackboard cache)
        load_result = loader.prepare(slice_.id, nodes, readme_summary=readme_summary)

        if not load_result.tasks and not load_result.cached:
            _print(console, f"    [dim]No functions to analyze.[/dim]")
            all_results.append(AgentPhaseResult(
                path_id=slice_.id, vuln_type=slice_.vuln_type.value,
                score=slice_.score, is_vulnerable=False,
            ))
            continue

        # Execute Intent Agent tasks (sequentially for deterministic order)
        all_intent_results: list[IntentResult] = list(load_result.cached)
        for task in load_result.tasks:
            prompt = intent_agent.prepare_prompt(task)
            llm_response = _call_llm(llm, prompt, console)
            if llm_response:
                results = intent_agent.run(task, llm_response=llm_response)
                all_intent_results.extend(results)
                loader.register_intent_results(results)
            else:
                _print(console, f"    [red]LLM call failed for batch {task.batch_id}[/red]")

        # Merge into pseudocode chain (with pass_through for dangerous functions)
        intent_chain = merge_layer.merge(all_intent_results)

        if not intent_chain.strip():
            _print(console, f"    [dim]Empty intent chain, skipping Logic Agent.[/dim]")
            all_results.append(AgentPhaseResult(
                path_id=slice_.id, vuln_type=slice_.vuln_type.value,
                score=slice_.score, is_vulnerable=False,
            ))
            continue

        # Build raw source block (includes companion methods + aliases for context)
        code_block = _build_code_block(
            nodes, source_controllability_proof=slice_.source_controllability_proof,
            reachability=slice_.reachability,
        )

        # ── Blackboard cross-path knowledge ──
        # Collect prior knowledge for every function in this path's call chain.
        # Earlier paths may have discovered contradictions or data-flow patterns
        # that involve the same functions — inject that as supplementary evidence.
        current_funcs = {
            node.get("function_name", "")
            for node in nodes
            if node.get("function_name")
        }
        blackboard_knowledge = blackboard.get_all_prior_knowledge(list(current_funcs))

        logic_prompt = logic_agent.prepare_prompt(
            path_id=slice_.id,
            intent_chain=intent_chain,
            vuln_type=slice_.vuln_type.value,
            readme_summary=readme_summary,
            code_block=code_block,
            project_type="app",
            blackboard_knowledge=blackboard_knowledge,
        )
        logic_response = _call_llm(llm, logic_prompt, console)
        if not logic_response:
            _print(console, f"    [red]Logic Agent LLM call failed[/red]")
            all_results.append(AgentPhaseResult(
                path_id=slice_.id, vuln_type=slice_.vuln_type.value,
                score=slice_.score, is_vulnerable=False,
            ))
            continue

        result = logic_agent.run(
            path_id=slice_.id,
            score=slice_.score,
            vuln_type=slice_.vuln_type.value,
            intent_chain=intent_chain,
            llm_response=logic_response,
        )
        all_results.append(result)
        blackboard.record_phase_result(result)
        _print_phase_d_result(console, result)

        # ── Record per-function knowledge back to Blackboard ──
        # When a Logic Agent discovers contradictions or high-confidence
        # findings, those are potentially useful for OTHER paths that also
        # touch the same functions (cross-path knowledge).
        if result.contradictions or result.confidence >= 7:
            for node in nodes:
                fn_name = node.get("function_name", "")
                if fn_name:
                    blackboard.record_knowledge(
                        fn_name,
                        f"[{result.vuln_type}] "
                        f"{result.analysis[:200] if result.analysis else '(no analysis)'}",
                        source_path_id=slice_.id,
                    )
            for c in result.contradictions[:3]:
                func_name = c.get("func", "")
                if func_name:
                    blackboard.record_knowledge(
                        func_name,
                        f"contradiction ({c.get('contradiction_type', '?')}): "
                        f"{c.get('actual', '')[:150]}",
                        source_path_id=slice_.id,
                    )

        # ── Inject structured Intent evidence into code_block ──
        # The Adversary and PoC Agent need per-function evidence: what each
        # function does, what input it receives, what it outputs, and what
        # suspicious observations the Intent Agent flagged.  This structured
        # data has been available in all_intent_results since line ~440 but
        # was never threaded through to downstream agents — they only got
        # Logic Agent's free-text `analysis`.
        intent_evidence = _build_intent_evidence(all_intent_results)
        code_block = code_block + "\n\n" + intent_evidence

        # Conditional consensus voting (grey zone, 4-7)
        if consensus:
            result = _run_consensus_vote(llm, logic_agent, result, logic_prompt, console)
            if result is not all_results[-1]:
                all_results[-1] = result
                _print_phase_d_result(console, result)

        # Adversary Agent: try to rebut before PoC generation
        if result.is_vulnerable or result.confidence >= 7:
            adversary = AdversaryAgent()
            contradiction_desc = (
                result.contradictions[0].get("contradiction_type", "")
                + ": "
                + result.contradictions[0].get("actual", "")
                if result.contradictions else ""
            )
            with _status(console, f"  Adversary: {slice_.id}..."):
                adv_result = adversary.run(
                    vuln_type=slice_.vuln_type.value,
                    analysis=result.analysis,
                    contradiction=contradiction_desc,
                    code_block=code_block,
                    llm_call=lambda p: _call_llm(llm, p, console),
                )

            if adv_result["rebutted"]:
                # BODY_ONLY/EXTERNAL_API override: deterministic evidence exists
                # in function body despite no project-internal call chain.
                if slice_.reachability in (Reachability.BODY_ONLY, Reachability.EXTERNAL_API):
                    _print(console, f"    [yellow]⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)[/yellow]")
                    _run_poc = True
                else:
                    _print(console, f"    [red]✗ rebutted[/red]")
                    _safe_r = adv_result['rebuttal'].replace('[', r'\[')
                    _print(console, f"      reason: {_safe_r}")
                    result = AgentPhaseResult(
                        path_id=result.path_id, vuln_type=result.vuln_type,
                        score=result.score, contradictions=result.contradictions,
                        confidence=min(result.confidence, adv_result["confidence_downgrade"]),
                        analysis=result.analysis
                        + f"\n[Adversary rebutted: {adv_result['rebuttal']}]",
                        is_vulnerable=False,
                        rebutted=True,
                        rebuttal=adv_result["rebuttal"],
                    )
                    all_results[-1] = result
                    _run_poc = False
            else:
                _print(console, f"    [green]✓ not rebutted[/green]")
                _safe_w = adv_result.get('weakness', '').replace('[', r'\[')
                _print(console, f"      weak point: {_safe_w}")
                _run_poc = True

            if _run_poc:
                # PoC Agent: write exploit script
                with _status(console, f"  PoC Agent: {slice_.id}..."):
                    poc = PoCAgent(
                        output_dir=os.path.join(os.getcwd(), "pocs"),
                        target=target,
                    )
                    poc_path = poc.run(
                        path_id=slice_.id,
                        vuln_type=result.actual_vuln_type or slice_.vuln_type.value,
                        analysis=result.analysis,
                        contradiction=contradiction_desc,
                        code_block=code_block,
                        weakness=adv_result.get("weakness", ""),
                        sink_name=slice_.sink,
                        # PoC prompts output Python code in fenced blocks, not JSON
                        llm_call=lambda p: _call_llm(llm, p, console, force_json=False),
                    )
                if poc_path:
                    _print(console, f"    [green]📄 PoC: {poc_path}[/green]")
                    result = AgentPhaseResult(
                        path_id=result.path_id, vuln_type=result.vuln_type,
                        score=result.score, contradictions=result.contradictions,
                        confidence=result.confidence,
                        analysis=result.analysis,
                        is_vulnerable=result.is_vulnerable,
                        poc_path=poc_path,
                    )
                    all_results[-1] = result

        # Evidence Checker: always run code-level pattern matching
        checker = EvidenceChecker(
            llm_call_fn=lambda p: _call_llm(llm, p, console),
            blackboard=blackboard,
        )
        with _status(console, f"  Evidence: {slice_.id}..."):
            evidence = checker.run(result, code_block, slice_.nodes)

        if evidence.evidence_found:
            _print(console, f"    [green]✓ evidence found ({len(evidence.matches)} match(es))[/green]")
            if evidence.poc:
                _print(console, f"      PoC: {evidence.poc[:150]}...")
            # Boost confidence from code-level evidence
            result = AgentPhaseResult(
                path_id=result.path_id,
                vuln_type=result.vuln_type,
                score=result.score,
                contradictions=result.contradictions,
                confidence=max(result.confidence, 5),
                analysis=evidence.analysis or result.analysis,
                is_vulnerable=True,
            )
            all_results[-1] = result

            # Verification (only for evidence-confirmed findings)
            sink_name = slice_.sink
            sink_file = slice_.sink_file.split(":")[0]
            call_context = _build_call_context(sink_name, sink_file, function_index)
            with _status(console, f"  Verifying {slice_.id}..."):
                verify_prompt = logic_agent.create_verify_prompt(
                    result, code_block=code_block, call_context=call_context,
                )
                verify_response = _call_llm(llm, verify_prompt, console)

            if verify_response:
                verified = logic_agent.verify(
                    result, code_block=code_block, llm_response=verify_response,
                )
                all_results[-1] = verified
                if result.confidence >= 7:
                    if not verified.is_vulnerable:
                        _print(console, f"    [yellow]↓ verification downgraded (7→{verified.confidence})[/yellow]")
                else:
                    if verified.is_vulnerable or verified.confidence >= 7:
                        _print(console, f"    [green]↑ verification upgraded (→{verified.confidence})[/green]")
                    else:
                        _print(console, f"    [dim]verification: {verified.confidence}/10 — keeping as interesting[/dim]")
        elif evidence.matches:
            _print(console, f"    [yellow]? pattern match, LLM skeptical ({len(evidence.matches)} match(es))[/yellow]")
            # Deterministic evidence: pattern matched regardless of LLM opinion
            pattern_summary = "; ".join(
                f"{m.function_name or '?'}:{m.line_content[:60]}"
                for m in evidence.matches[:5]
            )
            deterministic_analysis = (
                f"Code-level pattern evidence ({len(evidence.matches)} matches): "
                f"{pattern_summary}"
            )
            result = AgentPhaseResult(
                path_id=result.path_id,
                vuln_type=result.vuln_type,
                score=result.score,
                contradictions=result.contradictions or [{
                    "evidence_checker": "Code-level pattern matched (deterministic)",
                    "matches": f"{len(evidence.matches)} pattern(s)",
                    "patterns": pattern_summary,
                }],
                confidence=max(result.confidence, 7),
                analysis=deterministic_analysis,
                is_vulnerable=True,
            )
            all_results[-1] = result

    return all_results


def _run_phase_d_lib(
    sort_result: SortResult,
    llm: Any,
    blackboard: BlackboardAggregator,
    console: Any,
    function_index=None,
    target: str = "",
    consensus: bool = False,
) -> list[AgentPhaseResult]:
    """Library-mode Phase D — parallel Intent+Logic pipeline.

    Libraries rarely have intentional vulnerabilities, but may have
    composition vulnerabilities (path-builder + consumer) or misuse-prone
    APIs.
    """
    project_path = os.path.abspath(target) if target else ""
    loader = PathCodeLoader(project_path=project_path, blackboard=blackboard)
    intent_agent = IntentAgent()
    logic_agent = LogicAgent()
    merge_layer = MergeLayer()

    _print_lock = threading.Lock()

    def _safe_print(msg: str) -> None:
        with _print_lock:
            if console:
                console.print(msg)
            else:
                print(msg)

    total = len(sort_result.all_slices)

    def _process_one(slice_: PathSlice, idx: int) -> AgentPhaseResult | None:
        """Process one slice -- returns result or None (skipped)."""
        _safe_print(f"  [{idx+1}/{total}] {slice_.id} ({slice_.sink})")

        nodes: list[dict[str, Any]] = [{
            "function_name": slice_.sink,
            "file_path": slice_.sink_file.split(":")[0],
            "line_number": int(slice_.sink_file.split(":")[1]) if ":" in slice_.sink_file else 0,
        }]
        if slice_.nodes:
            nodes = slice_.nodes

        load_result = loader.prepare(slice_.id, nodes, readme_summary="")
        if not load_result.tasks and not load_result.cached:
            _safe_print(f"    [dim]No functions to analyze.[/dim]")
            return None

        all_intent_results: list[IntentResult] = list(load_result.cached)
        for task in load_result.tasks:
            prompt = intent_agent.prepare_prompt(task)
            llm_response = _call_llm(llm, prompt, console)
            if llm_response:
                results = intent_agent.run(task, llm_response=llm_response)
                all_intent_results.extend(results)
                loader.register_intent_results(results)

        intent_chain = merge_layer.merge(all_intent_results)
        if not intent_chain.strip():
            _safe_print(f"    [dim]Empty intent chain, skipping Logic Agent.[/dim]")
            return None

        code_block = _build_code_block(
            nodes, source_controllability_proof=slice_.source_controllability_proof,
            reachability=slice_.reachability,
        )
        code_block = _wrap_lib_sandbox(
            code_block, source_name=slice_.source, sink_name=slice_.sink,
        )

        # ── Blackboard cross-path knowledge ──
        current_funcs = {
            node.get("function_name", "")
            for node in nodes
            if node.get("function_name")
        }
        blackboard_knowledge = blackboard.get_all_prior_knowledge(list(current_funcs))

        logic_prompt = logic_agent.prepare_prompt(
            path_id=slice_.id,
            intent_chain=intent_chain,
            vuln_type=slice_.vuln_type.value,
            readme_summary="",
            code_block=code_block,
            project_type="lib",
            blackboard_knowledge=blackboard_knowledge,
        )
        logic_response = _call_llm(llm, logic_prompt, console)
        if not logic_response:
            _safe_print(f"    [red]Logic Agent LLM call failed[/red]")
            return None

        result = logic_agent.run(
            path_id=slice_.id,
            score=slice_.score,
            vuln_type=slice_.vuln_type.value,
            intent_chain=intent_chain,
            llm_response=logic_response,
        )
        blackboard.record_phase_result(result)
        _print_phase_d_result(console, result)

        # ── Record per-function knowledge back to Blackboard ──
        if result.contradictions or result.confidence >= 7:
            for node in nodes:
                fn_name = node.get("function_name", "")
                if fn_name:
                    blackboard.record_knowledge(
                        fn_name,
                        f"[{result.vuln_type}] "
                        f"{result.analysis[:200] if result.analysis else '(no analysis)'}",
                        source_path_id=slice_.id,
                    )
            for c in result.contradictions[:3]:
                func_name = c.get("func", "")
                if func_name:
                    blackboard.record_knowledge(
                        func_name,
                        f"contradiction ({c.get('contradiction_type', '?')}): "
                        f"{c.get('actual', '')[:150]}",
                        source_path_id=slice_.id,
                    )

        if consensus:
            with _print_lock:
                c_result = _run_consensus_vote(llm, logic_agent, result, logic_prompt, console)
            if c_result is not result:
                result = c_result
                _print_phase_d_result(console, result)

        bridge_result = _run_lib_bridge_verifier(llm, result, nodes, code_block, console)
        if bridge_result:
            result = bridge_result

        if result.is_vulnerable or result.confidence >= 7:
            adversary = AdversaryAgent()
            contradiction_desc = (
                result.contradictions[0].get("contradiction_type", "")
                + ": " + result.contradictions[0].get("actual", "")
                if result.contradictions else ""
            )
            _safe_print(f"    Adversary: {slice_.id}...")
            adv_result = adversary.run(
                vuln_type=slice_.vuln_type.value,
                analysis=result.analysis,
                contradiction=contradiction_desc,
                code_block=code_block,
                llm_call=lambda p: _call_llm(llm, p, console),
            )

            _run_poc = False
            if adv_result["rebutted"]:
                if slice_.reachability in (Reachability.BODY_ONLY, Reachability.EXTERNAL_API):
                    _safe_print(f"    [yellow]⚠ BODY_ONLY -- rebuttal overridden (body evidence, no call chain)[/yellow]")
                    _run_poc = True
                else:
                    _safe_print(f"    [red]x rebutted[/red]")
                    _safe_r = adv_result['rebuttal'].replace('[', r'\[')
                    _safe_print(f"      reason: {_safe_r}")
                    result = AgentPhaseResult(
                        path_id=result.path_id, vuln_type=result.vuln_type,
                        score=result.score, contradictions=result.contradictions,
                        confidence=min(result.confidence, adv_result["confidence_downgrade"]),
                        analysis=result.analysis + f"\n[Adversary rebutted: {adv_result['rebuttal']}]",
                        is_vulnerable=False,
                        rebutted=True,
                        rebuttal=adv_result["rebuttal"],
                    )
                    _run_poc = False
            else:
                _safe_print(f"    [green]not rebutted[/green]")
                _safe_w = adv_result.get('weakness', '').replace('[', r'\[')
                _safe_print(f"      weak point: {_safe_w}")
                _run_poc = True

            if _run_poc:
                _safe_print(f"    PoC Agent: {slice_.id}...")
                poc = PoCAgent(
                    output_dir=os.path.join(os.getcwd(), "pocs"),
                    target=target,
                )
                poc_path = poc.run(
                    path_id=slice_.id,
                    vuln_type=result.actual_vuln_type or slice_.vuln_type.value,
                    analysis=result.analysis,
                    contradiction=contradiction_desc,
                    code_block=code_block,
                    weakness=adv_result.get("weakness", ""),
                    sink_name=slice_.sink,
                    llm_call=lambda p: _call_llm(llm, p, console, force_json=False),
                )
                if poc_path:
                    _safe_print(f"    [green]PoC: {poc_path}[/green]")
                    result = AgentPhaseResult(
                        path_id=result.path_id, vuln_type=result.vuln_type,
                        score=result.score, contradictions=result.contradictions,
                        confidence=result.confidence,
                        analysis=result.analysis,
                        is_vulnerable=result.is_vulnerable,
                        poc_path=poc_path,
                    )

        checker = EvidenceChecker(
            llm_call_fn=lambda p: _call_llm(llm, p, console),
            blackboard=blackboard,
        )
        _safe_print(f"    Evidence: {slice_.id}...")
        evidence = checker.run(result, code_block, nodes)

        if evidence.evidence_found:
            _safe_print(f"    [green]evidence found ({len(evidence.matches)} match(es))[/green]")
            if evidence.poc:
                _safe_print(f"      PoC: {evidence.poc[:150]}...")
            result = AgentPhaseResult(
                path_id=result.path_id, vuln_type=result.vuln_type,
                score=result.score, contradictions=result.contradictions,
                confidence=max(result.confidence, 5),
                analysis=evidence.analysis or result.analysis,
                is_vulnerable=True,
            )
        elif evidence.matches:
            _safe_print(f"    [cyan]? pattern matched ({len(evidence.matches)} match(es))[/cyan]")
            pattern_summary = "; ".join(
                f"{m.function_name or '?'}:{m.line_content[:60]}"
                for m in evidence.matches[:5]
            )
            deterministic_analysis = (
                f"Code-level pattern evidence ({len(evidence.matches)} matches): "
                f"{pattern_summary}"
            )
            result = AgentPhaseResult(
                path_id=result.path_id, vuln_type=result.vuln_type,
                score=result.score, contradictions=result.contradictions or [{
                    "evidence_checker": "Code-level pattern matched (deterministic)",
                    "matches": f"{len(evidence.matches)} pattern(s)",
                    "patterns": pattern_summary,
                }],
                confidence=max(result.confidence, 7),
                analysis=deterministic_analysis,
                is_vulnerable=True,
            )
        else:
            _safe_print(f"    [dim]No code-level evidence patterns.[/dim]")

        return result

    # Parallel execution
    all_results: list[AgentPhaseResult] = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        fut_map = {
            executor.submit(_process_one, slice_, i): (i, slice_)
            for i, slice_ in enumerate(sort_result.all_slices)
        }
        for future in as_completed(fut_map):
            i, slice_ = fut_map[future]
            try:
                r = future.result()
                if r is not None:
                    all_results.append(r)
            except Exception as e:
                logger.error("Slice %s failed: %s", slice_.id, e)
                _safe_print(f"    [red]Error: {slice_.id}: {e}[/red]")

    all_results.sort(key=lambda r: int(r.path_id.rsplit("-", 1)[-1]))
    return all_results


def _run_lib_bridge_verifier(
    llm: Any,
    result: AgentPhaseResult,
    nodes: list[dict[str, Any]],
    code_block: str,
    console: Any,
) -> AgentPhaseResult | None:
    """Run bridge verification on a library slice.

    Handles two bridge patterns:

    **Attr-bridge** (``[attr bridge: self.X stored by Y → read by Z]``):
    Parsed from path node annotations.  Calls the full
    :class:`BridgeVerifier` pipeline when found.

    **Path-bridge**: scans ``code_block`` for path-builder patterns
    (``PurePosixPath``, ``posixpath.join``, etc.) AND consumer patterns
    (``open``, ``read_text``, ``extract``, regex ops) appearing together
    in the same sink function.  When both sets of patterns match,
    creates a ``BridgeAnnotation`` and runs through ``BridgeVerifier``.

    Returns ``None`` when no bridge pattern detected; otherwise returns
    the (possibly updated) ``AgentPhaseResult``.
    """
    # ── Phase 1: check for [attr bridge: ...] annotations ──
    bridge = None
    for node in nodes:
        annotations = node.get("annotations", []) or []
        for ann_text in annotations:
            parsed = BridgeAnnotation.parse(ann_text)
            if parsed:
                bridge = parsed
                break
        if bridge:
            break

    if bridge:
        _print(console, f"    [cyan]attr bridge: self.{bridge.attr} ({bridge.storer}→{bridge.reader})[/cyan]")

        storer_code = _load_function_source(
            nodes[0].get("file_path", ""), bridge.storer,
        )
        reader_code = _load_function_source(
            nodes[-1].get("file_path", ""), bridge.reader,
        )

        verifier = BridgeVerifier(llm_call_fn=lambda p: _call_llm(llm, p, console))
        return verifier.verify(
            logic_result=result,
            path_nodes=nodes,
            storer_code=storer_code,
            reader_code=reader_code,
            bridge=bridge,
            backtrack_chain=_build_backtrack_text(nodes),
        )

    # ── Phase 2: check for path-bridge composition patterns ──
    path_evidence = scan_path_bridge_evidence(code_block)

    if not path_evidence["path_bridge_found"]:
        return None

    _print(console, f"    [cyan]path bridge: {len(path_evidence['builder_patterns'])} builder + {len(path_evidence['consumer_patterns'])} consumer[/cyan]")

    verifier = BridgeVerifier()  # pattern-only, no LLM

    bridge = BridgeAnnotation(
        attr="(path)",
        storer=", ".join(d for d, _ in path_evidence["builder_patterns"]),
        reader=", ".join(d for _, _, d in path_evidence["consumer_patterns"]),
        raw_text=str(path_evidence),
    )

    return verifier.verify(
        logic_result=result,
        path_nodes=nodes,
        storer_code=code_block,
        reader_code=code_block,
        bridge=bridge,
    )


_TOKEN_COUNTER: TokenCounter | None = None
"""Global token counter shared across the v3 pipeline."""


def _init_token_counter(budget: int = 0) -> TokenCounter:
    global _TOKEN_COUNTER
    _TOKEN_COUNTER = TokenCounter(budget=budget)
    return _TOKEN_COUNTER


def _call_llm(
    llm: Any, prompt: str, console: Any,
    token_counter: TokenCounter | None = None,
    force_json: bool = True,
) -> str | None:
    """Call the LLM with a prompt and return the response text.

    Optionally records token usage in ``token_counter`` (falls back to
    the global ``_TOKEN_COUNTER`` when not provided).

    Parameters
    ----------
    force_json : bool
        When True (default), injects ``[SYSTEM_NOTICE: RESPOND IN JSON FORMAT]``
        and sets ``response_format={"type": "json_object"}`` for DeepSeek
        stability.  Set to False for prompts that need raw output (e.g. PoC
        scripts, code fences).
    """
    try:
        kwargs = {}
        if force_json:
            # DeepSeek JSON mode: prompt MUST contain "json" word or API rejects
            if "json" in prompt.lower():
                kwargs["response_format"] = {"type": "json_object"}
            else:
                # Force JSON mode by injecting system notice
                prompt = f"[SYSTEM_NOTICE: RESPOND IN JSON FORMAT]\n\n{prompt}"
                kwargs["response_format"] = {"type": "json_object"}
        response = llm.chat_completion(
            [{"role": "user", "content": prompt}], **kwargs,
        )
        if response and response.content:
            # Record token usage
            counter = token_counter or _TOKEN_COUNTER
            if counter and response.usage:
                counter.add(
                    prompt_tokens=response.usage.get("prompt_tokens", 0),
                    completion_tokens=response.usage.get("completion_tokens", 0),
                    total_tokens=response.usage.get("total_tokens", 0),
                )
            return response.content
        return None
    except Exception as exc:
        # Re-raise QuotaExceededException — don't swallow budget enforcement
        if isinstance(exc, QuotaExceededException):
            raise
        _print(console, f"    [red]LLM error: {exc}[/red]")
        return None


def _print_phase_d_result(console: Any, result: AgentPhaseResult) -> None:
    if result.is_vulnerable:
        _print(console, f"    [red]⚠ {result.confidence}/10 — {len(result.contradictions)} contradiction(s)[/red]")
    elif result.confidence >= 4:
        _print(console, f"    [yellow]? {result.confidence}/10 — interesting[/yellow]")
    else:
        _print(console, f"    [dim]✓ {result.confidence}/10 — safe[/dim]")


# ======================================================================
# Consensus voting — grey zone majority vote
# ======================================================================


def _run_consensus_vote(
    llm: Any,
    logic_agent: LogicAgent,
    result: AgentPhaseResult,
    logic_prompt: str,
    console: Any,
) -> AgentPhaseResult:
    """Conditional majority voting for grey-zone findings (confidence 4-7).

    Runs 2 additional LLM calls (3 total), then takes majority vote
    on ``is_vulnerable``.  Non-grey-zone results pass through unchanged.
    """
    if not (4 <= result.confidence <= 7):
        return result

    votes_is_vuln: list[bool] = [result.is_vulnerable]
    votes_conf: list[int] = [result.confidence]

    for i in range(2):
        r = _call_llm(llm, logic_prompt, console)
        if not r:
            continue
        r2 = logic_agent.run(
            path_id=result.path_id,
            score=result.score,
            vuln_type=result.vuln_type,
            intent_chain="",
            llm_response=r,
        )
        votes_is_vuln.append(r2.is_vulnerable)
        votes_conf.append(r2.confidence)

    majority_vuln = sum(votes_is_vuln) >= 2  # 2/3 or 3/3
    if majority_vuln and not result.is_vulnerable:
        # Grey zone promoted
        avg_conf = sum(votes_conf) // len(votes_conf)
        return AgentPhaseResult(
            path_id=result.path_id,
            vuln_type=result.vuln_type,
            score=result.score,
            contradictions=result.contradictions,
            confidence=max(avg_conf, 7),
            analysis=result.analysis,
            is_vulnerable=True,
        )
    elif not majority_vuln and result.is_vulnerable:
        # Grey zone demoted
        avg_conf = sum(votes_conf) // len(votes_conf)
        return AgentPhaseResult(
            path_id=result.path_id,
            vuln_type=result.vuln_type,
            score=result.score,
            contradictions=result.contradictions,
            confidence=min(avg_conf, 3),
            analysis=result.analysis,
            is_vulnerable=False,
        )

    return result


# ======================================================================
# Phase C: README summarizer
# ======================================================================


def _summarize_readme(llm: Any, readme_text: str) -> str:
    """Summarize README using LLM (optional, 1 call)."""
    from agies.engine.v3.prompts.readme_summary import build_readme_prompt
    prompt = build_readme_prompt(readme_text[:2000])
    try:
        response = llm.chat_completion(
            [{"role": "user", "content": prompt}],
            temperature=0,
        )
        if response and response.content:
            return response.content.strip()
    except Exception:
        pass
    return ""


# ======================================================================
# LLM init
# ======================================================================


def _init_llm(model: str, console: Any) -> Any | None:
    """Initialize the LLM provider. Returns None on failure."""
    from agies.llm import get_model
    try:
        llm = get_model(model)
        if not llm.api_key:
            _print(console, f"[red]Error: {llm.env_key_name} not set[/red]")
            return None
        return llm
    except Exception as exc:
        _print(console, f"[red]Failed to initialize LLM: {exc}[/red]")
        return None


# ======================================================================
# Helpers
# ======================================================================


def _wrap_lib_sandbox(code_block: str, source_name: str, sink_name: str) -> str:
    """Prepend a synthetic web app controller for library-mode analysis.

    LLMs exhibit strong "library bias" — they refuse to flag library code
    as vulnerable because "it's not an app."  Wrapping the code block with
    a simulated application endpoint forces the LLM into web-audit mode,
    making it evaluate the code path as if it were part of a real application.
    """
    return (
        "# [SYSTEM WRAPPER: SIMULATED APP CONTROLLER FOR SECURITY ANALYSIS]\n"
        "# To evaluate the potential exploitability of this library, \n"
        "# it is wrapped within a simulated production-grade web endpoint:\n"
        "#\n"
        f"# @app.post(\"/api/v1/trigger\")\n"
        f"# def handle_request(untrusted_user_input: str):\n"
        f"#     # The library's entry point is invoked with attacker-controlled input:\n"
        f"#     result = {source_name}(untrusted_user_input)\n"
        f"#     # This leads to the sink function: {sink_name}\n"
        "#\n"
        "# The code below shows the actual library implementation.\n"
        "# [END SYSTEM WRAPPER]\n"
        "# ── Library source code below ──\n\n"
        f"{code_block}"
    )


def _build_code_block(
    nodes: list[dict[str, Any]],
    source_controllability_proof: str = "",
    reachability: Reachability = Reachability.CHAIN,
) -> str:
    """Build a raw source code block from PathNode snippets.

    Shows the call chain direction from source (entry) → sink.
    Includes class-level aliases and companion consumer methods.
    When ``source_controllability_proof`` is provided, prepends it as a
    system notice so downstream LLM agents receive irrefutable evidence
    of external input controllability.
    When ``reachability`` is BODY_ONLY or EXTERNAL_API, prepends a notice
    explaining the missing call chain so agents can adjust their analysis.
    """
    parts: list[str] = []

    # Reachability notice for body-detected orphans
    if reachability == Reachability.BODY_ONLY:
        parts.append(
            "# ── [REACHABILITY: BODY_ONLY] ──\n"
            "# This function was flagged because its body contains dangerous\n"
            "# API calls (e.g. pickle.load, eval, open). No caller chain was\n"
            "# found inside this project — the function may be a library public\n"
            "# API called from external code.\n"
            "# Assess whether the dangerous operation in the body is reachable\n"
            "# with attacker-controlled input.\n"
            "# ── ── ── ── ── ── ── ── ── ── ──"
        )
    elif reachability == Reachability.EXTERNAL_API:
        parts.append(
            "# ── [REACHABILITY: EXTERNAL_API] ──\n"
            "# This function is a library public API (detected via __all__ or\n"
            "# module-level definition). It calls dangerous operations in its\n"
            "# body. The function is exposed to external callers who control\n"
            "# its parameters — treat all parameters as attacker-controllable.\n"
            "# ── ── ── ── ── ── ── ── ── ── ──"
        )

    if source_controllability_proof:
        parts.append(
            "# ── [SOURCE CONTROLLABILITY EVIDENCE] ──\n"
            f"# {source_controllability_proof}\n"
            "# This is a static-analysis signal: the entry function is a "
            "verified HTTP controller.\n"
            "# The untrusted input reaches the sink through the call chain "
            "below.\n"
            "# ── ── ── ── ── ── ── ── ── ── ──"
        )

    # ── Taint flow annotation ──
    taint_annotation = _annotate_taint_flow(nodes)
    if taint_annotation:
        parts.append(taint_annotation)

    companion_shown = False
    for i, node in enumerate(nodes):
        fn_name = node.get("function_name", f"func_{i}")
        fp = node.get("file_path", "?")
        ln = node.get("line_number", "?")
        snippet = node.get("snippet", "") or node.get("code", "")
        direction = "entry" if i == 0 else "middle" if i < len(nodes) - 1 else "sink"

        header = f"# ── Call Chain [{i}] [{direction}] → {fn_name} ({fp}:{ln}) ──"

        # Scan for class-level aliases (e.g. __truediv__ = joinpath)
        aliases = ""
        if direction == "sink" and fp and os.path.isfile(fp):
            aliases = _find_function_aliases(fp, fn_name)
        if aliases:
            aliases = f"\n#    Note: also aliased as `{aliases}`"

        parts.append(f"{header}\n{snippet}{aliases}")

        # For sink, append companion consumer methods in same class
        if direction == "sink" and fp and os.path.isfile(fp) and not companion_shown:
            companions = _find_companion_methods(fp, fn_name, ln)
            if companions:
                parts.append(
                    "# ── Related: companion methods in same class (consumers of this path) ──\n"
                    + companions
                )
                companion_shown = True

    return "\n\n".join(parts)


_AST_CACHE: dict[str, Any] = {}
"""Cache for ``ast.parse()`` results keyed by absolute file path.

Without this cache, each ``PathSlice`` that passes through ``_build_code_block``
re-reads and re-parses the same source file.  With 5 concurrent Phase D workers
and many slices referencing the same large file, this creates significant
memory pressure from redundant AST trees.

Cleared implicitly when ``_free_phase_a_memory()`` is called or on module exit.
The cache is bounded by the number of unique files referenced by all slices,
typically << the total file count in the project.
"""


# ═══════════════════════════════════════════════════════════════════════════
# Taint flow annotation — marks entry params as UNTRUSTED and traces
# propagation through the call chain so that downstream agents (Adversary,
# PoC) know exactly which arguments at the sink carry attacker-controlled
# values rather than having to infer data flow from bare source snippets.
# ═══════════════════════════════════════════════════════════════════════════

import re as _re

_PARAM_RE = _re.compile(r"def\s+\w+\s*\(([^)]*)\)")
_CALL_RE = _re.compile(r"\b(\w+)\s*\(")
_ARG_SPLIT_RE = _re.compile(r",\s*(?![^()]*\))")

# Names that are never attacker-controlled (builtins / self / cls / constants)
_SAFE_PARAM_NAMES = frozenset({
    "self", "cls", "args", "kwargs", "request", "response",
    "app", "config", "settings", "db", "session",
})


def _extract_params(snippet: str) -> list[str]:
    """Extract parameter names from a ``def func(...)`` signature snippet."""
    m = _PARAM_RE.search(snippet)
    if not m:
        return []
    raw = m.group(1)
    params = []
    for part in raw.split(","):
        p = part.strip().split(":")[0].split("=")[0].strip()
        if p and p not in _SAFE_PARAM_NAMES and not p.startswith("*"):
            params.append(p)
    return params


def _extract_call_args(snippet: str, callee: str) -> list[str]:
    """Extract positional argument names from the first call to *callee* in *snippet*.

    Returns e.g. ``["files_list", "self.temp_dir"]`` for a call like
    ``some_func(files_list, self.temp_dir)``.  Only handles direct variable/
    attribute references — complex expressions are returned as-is.
    """
    # Find the first call to callee: callee(...)
    pattern = _re.compile(r"\b" + _re.escape(callee) + r"\s*\(([^)]*)\)")
    m = pattern.search(snippet)
    if not m:
        return []
    raw_args = m.group(1)
    # Split on commas that are not inside nested parentheses
    args = []
    depth = 0
    current = ""
    for ch in raw_args:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        args.append(current.strip())
    return args


def _extract_init_self_attrs(file_path: str, entry_lineno: int) -> list[str]:
    """Extract potential untrusted member variables from the entry function's class.

    Scans the enclosing class for ``self.xxx =`` assignments (in any method)
    and class-level annotated attributes.  These are potential untrusted sources
    in library mode where the entry function is a class method with ``self``.

    Used by ``_annotate_taint_flow`` to hint the LLM when static taint
    tracking can't trace attribute → local variable propagation.
    """
    try:
        with open(file_path) as f:
            source = f.read()
    except OSError:
        return []
    lines = source.splitlines()

    # Scan backwards from entry function to find the enclosing class
    class_line = None
    for i in range(entry_lineno - 1, -1, -1):
        if _re.match(r"^\s*class\s+\w+", lines[i]):
            class_line = i
            break
    if class_line is None:
        return []

    class_indent = len(lines[class_line]) - len(lines[class_line].lstrip())
    body_indent = class_indent + 4
    attrs: set[str] = set()

    for i in range(class_line + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.strip().startswith("#"):
            continue

        cur_indent = len(line) - len(line.lstrip())

        # Left the class
        if cur_indent <= class_indent:
            break

        # Class-level attribute: xxx or xxx: Type or xxx = value or xxx: Type = value
        # Lines at exactly body_indent that aren't def/@/decorator
        stripped = line.strip()
        if cur_indent == body_indent:
            if stripped.startswith("def ") or stripped.startswith("@") or stripped.startswith("class "):
                continue
            # Class-level: xxx: Type or xxx = value or xxx: Type = value
            m = _re.match(r"\s*(\w+)\s*:", line)
            if m:
                attrs.add(m.group(1))
            else:
                m = _re.match(r"\s*(\w+)\s*=", line)
                if m:
                    attrs.add(m.group(1))
            continue

        # Inside a method body: only collect from __init__
        if cur_indent > body_indent:
            # Find which method we're in by checking if we passed def __init__
            # Simple approach: scan backwards from this line for the nearest def
            for j in range(i, class_line - 1, -1):
                prev_stripped = lines[j].strip()
                if prev_stripped.startswith("def __init__(") or prev_stripped.startswith("def __init__ ("):
                    # We're inside __init__ — collect self.xxx =
                    for m in _re.finditer(r"self\.(\w+)\s*=", line):
                        attrs.add(m.group(1))
                    break
                elif prev_stripped.startswith("def ") or prev_stripped.startswith("class "):
                    # Some other method — don't collect
                    break

    return sorted(attrs)


def _annotate_taint_flow(nodes: list[dict[str, Any]]) -> str:
    """Build a data flow annotation block for the call chain.

    Traces which entry function parameters (untrusted) propagate through
    intermediate calls to the sink.  Returns a comment block suitable for
    prepending to ``_build_code_block`` output.
    """
    if not nodes:
        return ""

    lines: list[str] = [
        "# ── [DATA FLOW] ──",
    ]

    # -- Determine entry parameters (always attacker-controllable) --
    entry_func_name = nodes[0].get("function_name", "")
    entry_snippet = nodes[0].get("snippet", "")
    entry_params = _extract_params(entry_snippet)
    # If this is a library or body-only entry, params that aren't obviously
    # safe are considered untrusted
    if not entry_params:
        entry_params = _extract_params(entry_snippet)

    if entry_params:
        lines.append(f"# ENTRY '{entry_func_name}' — UNTRUSTED params: {', '.join(entry_params)}")
        lines.append("#   (all entry parameters are treated as attacker-controlled)")
    else:
        has_self = bool(_re.search(r"\bdef\s+\w+\s*\(\s*self\b", entry_snippet))
        if has_self:
            entry_lineno = nodes[0].get("line_number", 0) or 0
            fp = nodes[0].get("file_path", "")
            attrs = _extract_init_self_attrs(fp, entry_lineno) if fp else []
            if attrs:
                lines.append(f"# ENTRY '{entry_func_name}' — Class method (self)")
                lines.append(f"#   Potential untrusted class attributes: {', '.join(attrs)}")
            else:
                lines.append(f"# ENTRY '{entry_func_name}' — Class method (self)")
                lines.append("#   (no explicit class attributes detected)")
        else:
            lines.append(f"# ENTRY '{entry_func_name}' — no identifiable parameters")
        lines.append("# ⚠ Static engine could not trace variable propagation (e.g. self.properties).")
        lines.append("# ⚠ Semantically analyze the source code to determine if class attributes or")
        lines.append("#   parameters can be controlled by an untrusted user.")

    # -- Trace tainted symbols through the chain --
    tainted_symbols = set(entry_params)
    # Also track common return-value patterns like ``result = fn(...)``
    RETURN_VAR_RE = _re.compile(r"(\w+)\s*=\s*\w+\(")

    for i in range(1, len(nodes)):
        prev_snippet = nodes[i - 1].get("snippet", "")
        prev_fn = nodes[i - 1].get("function_name", "")
        curr_fn = nodes[i].get("function_name", "")
        curr_snippet = nodes[i].get("snippet", "")
        curr_params = _extract_params(curr_snippet)
        is_sink = (i == len(nodes) - 1)
        tag = "SINK" if is_sink else f"CALL {i}"

        # Find how the previous function calls the current one
        call_args = _extract_call_args(prev_snippet, curr_fn.split(".")[-1])

        # Map call arguments to this function's parameter names
        tainted_params = []
        for arg_val, param_name in zip(call_args, curr_params):
            # Check if the argument value contains any tainted symbol
            for tainted in tainted_symbols:
                if tainted in arg_val:
                    tainted_params.append(f"{param_name}={arg_val}")
                    tainted_symbols.add(param_name)
                    break

        if tainted_params:
            lines.append(f"# {tag} '{curr_fn}' — tainted: {', '.join(tainted_params)}")
        elif curr_params:
            # Even without explicit match, mark params as potentially tainted
            # if the function receives any argument at all (conservative)
            lines.append(f"# {tag} '{curr_fn}' — {len(curr_params)} param(s), taint could not be statically resolved")
            lines.append("# ⚠ Semantically analyze the source code above to determine if these params carry untrusted data.")

        # Collect return variable names that could carry taint forward
        for rm in RETURN_VAR_RE.finditer(prev_snippet):
            # If the RHS call references tainted args, the LHS is tainted
            rhs_start = rm.end()
            call_text = prev_snippet[rm.start():rm.end() + 80]
            if any(t in call_text for t in tainted_symbols):
                tainted_symbols.add(rm.group(1))

    lines.append("# ── ── ── ── ──")
    return "\n".join(lines)


def _build_intent_evidence(all_intent_results: list[IntentResult]) -> str:
    """Build a structured evidence section from Intent Agent results.

    Renders each function's intent, inputs, outputs, key_logic, and
    suspicious observations as compact annotations.  This is appended to
    the ``code_block`` before it reaches the Adversary and PoC Agent,
    giving them high-density evidence that the Logic Agent's free-text
    ``analysis`` field alone does not provide.
    """
    lines: list[str] = [
        "# ── [INTENT EVIDENCE] ──",
    ]
    for r in all_intent_results:
        parts = [f"# {r.func_name} ({r.file_path}):"]
        if r.intent:
            parts.append(f"#   intent: {r.intent[:120]}")
        if r.inputs:
            parts.append(f"#   inputs: {r.inputs[:120]}")
        if r.outputs:
            parts.append(f"#   outputs: {r.outputs[:120]}")
        if r.key_logic:
            parts.append(f"#   key_logic: {r.key_logic[:120]}")
        if r.suspicious:
            items = "; ".join(s[:80] for s in r.suspicious[:3])
            parts.append(f"#   suspicious: {items}")
        lines.extend(parts)
    lines.append("# ── ── ── ── ──")
    return "\n".join(lines)


def _find_companion_methods(file_path: str, func_name: str, line_number: int) -> str:
    """Find companion consumer methods in the same class as a path-builder.

    For a path-builder sink (joinpath, _base), returns consumer methods
    (read_text, read_bytes, open) that could use the constructed path.
    """
    import ast
    try:
        cached = _AST_CACHE.get(file_path)
        if cached is not None:
            tree = cached
        else:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source)
            _AST_CACHE[file_path] = tree

        # Always load source text — needed by ast.get_source_segment even when
        # the AST is retrieved from cache (source is not stored in _AST_CACHE).
        if cached is not None:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()

        # Find class containing func_name
        target_class = None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if item.name == func_name:
                            target_class = node
                            break
                if target_class:
                    break

        if target_class is None:
            return ""

        # Look for consumer methods in the same class
        consumers = {"read_text", "read_bytes", "read", "open",
                     "write_text", "write_bytes", "extractall", "extract"}
        consumer_lines: list[str] = []
        for item in target_class.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name in consumers and item.name != func_name:
                    fn_source = ast.get_source_segment(source, item)
                    if fn_source:
                        lines = fn_source.split("\n")
                        consumer_lines.append(
                            f"  # Consumer: {item.name} (line {item.lineno})\n"
                            + "\n".join("  " + l for l in lines)
                        )

        if consumer_lines:
            return "\n\n".join(consumer_lines)

        # Fallback: show class docstring
        doc = ast.get_docstring(target_class)
        if doc:
            return f"  # Class: {target_class.name} — {doc[:200]}"
        return f"  # Class: {target_class.name}"

    except (SyntaxError, OSError):
        return ""


def _load_function_source(file_path: str, func_name: str) -> str:
    """Extract full source code of a function by name from a Python file.

    Uses AST to find the function definition and extract its source text.
    Returns empty string on failure.
    """
    import ast
    try:
        cached = _AST_CACHE.get(file_path)
        if cached is not None:
            tree = cached
        else:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source)
            _AST_CACHE[file_path] = tree
        # Load source for ast.get_source_segment (not cached)
        if cached is not None:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == func_name:
                    return ast.get_source_segment(source, node) or ""
        # Fallback: try class methods
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if item.name == func_name:
                            return ast.get_source_segment(source, item) or ""
    except (SyntaxError, OSError):
        pass
    return ""


def _build_backtrack_text(nodes: list[dict[str, Any]]) -> str:
    """Build human-readable call chain text from path nodes."""
    parts = []
    for i, n in enumerate(nodes):
        fn = n.get("function_name", "?")
        fp = n.get("file_path", "?")
        ln = n.get("line_number", "?")
        parts.append(f"  [{i}] {fn} ({fp}:{ln})")
    return "\n".join(parts)


def _find_function_aliases(file_path: str, func_name: str) -> str:
    """Scan a source file for class-level ``alias = func_name`` assignments."""
    aliases: list[str] = []
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                stripped = line.strip()
                # Match patterns like: __truediv__ = joinpath
                if "=" in stripped and not stripped.startswith("#"):
                    parts = stripped.split("=", 1)
                    lhs = parts[0].strip()
                    rhs = parts[1].strip().rstrip(",")
                    if rhs == func_name and lhs.isidentifier():
                        aliases.append(lhs)
    except OSError:
        pass
    return ", ".join(aliases)


# ======================================================================
# Display helpers
# ======================================================================


def _print_header(console: Any, title: str) -> None:
    if console:
        console.print()
        console.print(f"[bold]{title}[/bold]")
    else:
        print(f"\n{title}")


def _print(console: Any, msg: str) -> None:
    if console:
        console.print(msg)
    else:
        print(msg)


def _status(console: Any, msg: str) -> Any:
    if console:
        return console.status(f"[bold]{msg}[/bold]")

    class _Noop:
        def __enter__(self) -> None: ...
        def __exit__(self, *args: Any) -> None: ...
    return _Noop()


def _try_read_readme(target: str) -> str:
    for name in ("README.md", "README", "readme.md", "README.rst", "readme.rst"):
        path = os.path.join(target, name)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()[:2000]
            except OSError:
                pass
    return ""


# ======================================================================
# CLI entry (for standalone testing)
# ======================================================================


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="agies v3 pipeline")
    parser.add_argument("target", help="Project directory")
    parser.add_argument("--model", default="deepseek-chat", help="LLM model")
    parser.add_argument("--codeql", action="store_true", help="Use CodeQL")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--type", default="auto", choices=["auto", "app", "lib"],
                        help="Project type (auto-detect, app, or lib)")

    args = parser.parse_args()
    run_v3_pipeline(
        target=args.target,
        model=args.model,
        verbose=args.verbose,
        use_codeql=args.codeql,
        project_type=args.type,
    )


if __name__ == "__main__":
    main()
