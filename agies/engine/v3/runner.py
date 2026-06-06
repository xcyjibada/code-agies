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
import time
from typing import Any

from agies.engine.v3.codeql.models import VulnType, VULN_LABELS, QueryResult
from agies.engine.v3.slicer import select_top_k
from agies.engine.v3.slicer.models import SortResult
from agies.engine.v3.aggregator.blackboard import BlackboardAggregator
from agies.engine.v3.aggregator.models import AgentPhaseResult, IntentResult
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
    max_exploit: int = 25,
    max_explore: int = 10,
    max_intent_workers: int = 5,
    exclude_test: bool = False,
    project_type: str = "auto",
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

    _print(console, f"  Exploit: {len(sort_result.exploit)} + Explore: {len(sort_result.explore)}")
    for s in sort_result.explore[:3]:
        reasons = f" ({', '.join(s.anomaly_reasons)})" if s.anomaly_reasons else ""
        _print(console, f"    [dim]Explore: {s.id} {s.sink} score={s.score:.2f}{reasons}[/dim]")

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
        )

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
        code_block = _build_code_block(nodes)
        logic_prompt = logic_agent.prepare_prompt(
            path_id=slice_.id,
            intent_chain=intent_chain,
            vuln_type=slice_.vuln_type.value,
            readme_summary=readme_summary,
            code_block=code_block,
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
                _print(console, f"    [red]✗ rebutted: {adv_result['rebuttal'][:120]}[/red]")
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
            else:
                _print(console, f"    [green]✓ not rebutted (weakness: {adv_result.get('weakness', '')[:80]})[/green]")
                # PoC Agent: write exploit script for un-rebutted findings
                with _status(console, f"  PoC Agent: {slice_.id}..."):
                    poc = PoCAgent(output_dir=os.path.join(os.getcwd(), "pocs"))
                    poc_path = poc.run(
                        path_id=slice_.id,
                        vuln_type=slice_.vuln_type.value,
                        analysis=result.analysis,
                        contradiction=contradiction_desc,
                        code_block=code_block,
                        weakness=adv_result.get("weakness", ""),
                        llm_call=lambda p: _call_llm(llm, p, console),
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
) -> list[AgentPhaseResult]:
    """Library-mode Phase D — lightweight Intent+Logic pipeline.

    Libraries rarely have intentional vulnerabilities, but may have
    composition vulnerabilities (path-builder + consumer) or misuse-prone
    APIs. Uses the same Intent Agent → Merge → Logic Agent flow as app
    mode, but without README context.
    """
    project_path = os.path.abspath(target) if target else ""
    loader = PathCodeLoader(project_path=project_path, blackboard=blackboard)
    intent_agent = IntentAgent()
    logic_agent = LogicAgent()
    merge_layer = MergeLayer()
    all_results: list[AgentPhaseResult] = []

    for i, slice_ in enumerate(sort_result.all_slices):
        _print(console, f"  [{i+1}/{len(sort_result.all_slices)}] {slice_.id} ({slice_.sink})")

        # Build nodes from sink metadata + real path nodes
        nodes: list[dict[str, Any]] = [{
            "function_name": slice_.sink,
            "file_path": slice_.sink_file.split(":")[0],
            "line_number": int(slice_.sink_file.split(":")[1]) if ":" in slice_.sink_file else 0,
        }]
        if slice_.nodes:
            nodes = slice_.nodes

        # Prepare tasks via PathCodeLoader (checks blackboard cache)
        load_result = loader.prepare(slice_.id, nodes, readme_summary="")

        if not load_result.tasks and not load_result.cached:
            _print(console, f"    [dim]No functions to analyze.[/dim]")
            all_results.append(AgentPhaseResult(
                path_id=slice_.id, vuln_type=slice_.vuln_type.value,
                score=slice_.score, is_vulnerable=False,
            ))
            continue

        # Intent Agent: extract developer intent from each function
        all_intent_results: list[IntentResult] = list(load_result.cached)
        for task in load_result.tasks:
            prompt = intent_agent.prepare_prompt(task)
            llm_response = _call_llm(llm, prompt, console)
            if llm_response:
                results = intent_agent.run(task, llm_response=llm_response)
                all_intent_results.extend(results)
                loader.register_intent_results(results)

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
        code_block = _build_code_block(nodes)
        logic_prompt = logic_agent.prepare_prompt(
            path_id=slice_.id,
            intent_chain=intent_chain,
            vuln_type=slice_.vuln_type.value,
            readme_summary="",
            code_block=code_block,
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

        # Bridge Verifier: handle both attr-bridge and path-bridge patterns
        bridge_result = _run_lib_bridge_verifier(
            llm, result, nodes, code_block, console,
        )
        if bridge_result:
            result = bridge_result
            all_results[-1] = result
            if result.confidence >= 4 or result.is_vulnerable:
                _print_phase_d_result(console, result)

        # Adversary Agent: try to rebut before PoC generation (lib mode)
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
                _print(console, f"    [red]✗ rebutted: {adv_result['rebuttal'][:120]}[/red]")
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
            else:
                _print(console, f"    [green]✓ not rebutted (weakness: {adv_result.get('weakness', '')[:80]})[/green]")
                with _status(console, f"  PoC Agent: {slice_.id}..."):
                    poc = PoCAgent(output_dir=os.path.join(os.getcwd(), "pocs"))
                    poc_path = poc.run(
                        path_id=slice_.id,
                        vuln_type=slice_.vuln_type.value,
                        analysis=result.analysis,
                        contradiction=contradiction_desc,
                        code_block=code_block,
                        weakness=adv_result.get("weakness", ""),
                        llm_call=lambda p: _call_llm(llm, p, console),
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
            evidence = checker.run(result, code_block, nodes)

        if evidence.evidence_found:
            _print(console, f"    [green]✓ evidence found ({len(evidence.matches)} match(es))[/green]")
            if evidence.poc:
                _print(console, f"      PoC: {evidence.poc[:150]}...")
            result = AgentPhaseResult(
                path_id=result.path_id, vuln_type=result.vuln_type,
                score=result.score, contradictions=result.contradictions,
                confidence=max(result.confidence, 5),
                analysis=evidence.analysis or result.analysis,
                is_vulnerable=True,
            )
            all_results[-1] = result
        elif evidence.matches:
            _print(console, f"    [cyan]? pattern matched (deterministic) ({len(evidence.matches)} match(es))[/cyan]")
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
            all_results[-1] = result
        else:
            _print(console, f"    [dim]No code-level evidence patterns.[/dim]")

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


def _call_llm(llm: Any, prompt: str, console: Any) -> str | None:
    """Call the LLM with a prompt and return the response text."""
    try:
        response = llm.chat_completion([{"role": "user", "content": prompt}])
        if response and response.content:
            return response.content
        return None
    except Exception as exc:
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


def _build_code_block(nodes: list[dict[str, Any]]) -> str:
    """Build a raw source code block from PathNode snippets.

    Shows the call chain direction from source (entry) → sink.
    Includes class-level aliases and companion consumer methods.
    """
    parts: list[str] = []
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


def _find_companion_methods(file_path: str, func_name: str, line_number: int) -> str:
    """Find companion consumer methods in the same class as a path-builder.

    For a path-builder sink (joinpath, _base), returns consumer methods
    (read_text, read_bytes, open) that could use the constructed path.
    """
    import ast
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            source = f.read()
        tree = ast.parse(source)

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
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            source = f.read()
        tree = ast.parse(source)
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
