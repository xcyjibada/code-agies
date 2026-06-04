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
from agies.engine.v3.agents.merge import MergeLayer
from agies.engine.v3.agents.path_code_loader import PathCodeLoader

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
    if use_codeql:
        results = _run_codeql_discovery(console, target, codeql_bin, db_dir, verbose)
    else:
        results = _run_treesitter_discovery(console, target, verbose)

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
    # Phase C: README Understanding
    # ==================================================================
    _print_header(console, "Phase C: README Understanding")

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

    # ==================================================================
    # Phase D: Intent Agent + Logic Agent
    # ==================================================================
    _print_header(console, f"Phase D: Intent+Logic Agents ({len(sort_result.all_slices)} slices)")

    blackboard = BlackboardAggregator()
    phase_results = _run_phase_d(
        sort_result=sort_result,
        llm=llm,
        blackboard=blackboard,
        readme_summary=readme_summary,
        max_workers=max_intent_workers,
        console=console,
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
) -> list[QueryResult]:
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

    return results


def _run_codeql_discovery(
    console: Any, target: str, codeql_bin: str, db_dir: str, verbose: bool,
) -> list[QueryResult]:
    from agies.engine.v3.codeql.query import CodeQLQueryRunner
    _print(console, "  [cyan]Backend: CodeQL[/cyan]")

    if not codeql_bin:
        codeql_bin = CodeQLQueryRunner._find_codeql()
    if not codeql_bin:
        _print(console, "  [yellow]CodeQL not found, falling back to tree-sitter.[/yellow]")
        return _run_treesitter_discovery(console, target, verbose)

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
            return _run_treesitter_discovery(console, target, verbose)

    _print(console, runner.summary_text(results))
    return results


# ======================================================================
# Phase D: Intent Agent + Logic Agent (real LLM)
# ======================================================================


def _run_phase_d(
    sort_result: SortResult,
    llm: Any,
    blackboard: BlackboardAggregator,
    readme_summary: str,
    max_workers: int,
    console: Any,
    target: str = "",
) -> list[AgentPhaseResult]:
    """Run Phase D with real LLM calls.

    1. PathCodeLoader prepares Intent tasks (checks blackboard cache)
    2. Intent Agent pool runs in parallel (one per function group)
    3. Merge layer assembles pseudocode chain
    4. Logic Agent runs per path (finds contradictions)
    """
    project_path = os.path.abspath(target) if target else os.path.abspath(
        getattr(sort_result, '_project_path', '')
    )

    from agies.engine.v3.pathfinder import TreeSitterPathFinder
    finder = TreeSitterPathFinder(project_path) if project_path else None
    loader = PathCodeLoader(project_path=project_path, blackboard=blackboard)

    intent_agent = IntentAgent()
    logic_agent = LogicAgent()
    merge_layer = MergeLayer()
    all_results: list[AgentPhaseResult] = []

    for i, slice_ in enumerate(sort_result.all_slices):
        _print(console, f"  [{i+1}/{len(sort_result.all_slices)}] {slice_.id} ({slice_.sink})")

        # Build Pseudo-nodes from slice metadata
        nodes: list[dict[str, Any]] = [{
            "function_name": slice_.sink,
            "file_path": slice_.sink_file.split(":")[0],
            "line_number": int(slice_.sink_file.split(":")[1]) if ":" in slice_.sink_file else 0,
        }]
        if slice_.nodes:
            nodes = slice_.nodes

        # Prepare tasks via PathCodeLoader
        load_result = loader.prepare(slice_.id, nodes, readme_summary=readme_summary)

        if not load_result.tasks and not load_result.cached:
            _print(console, f"    [dim]No functions to analyze.[/dim]")
            all_results.append(AgentPhaseResult(
                path_id=slice_.id, vuln_type=slice_.vuln_type.value,
                score=slice_.score, is_vulnerable=False,
            ))
            continue

        # Execute Intent Agent tasks (sequentially for now)
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

        # Merge into pseudocode chain (with pass_through raw source for dangerous functions)
        intent_chain = merge_layer.merge(all_intent_results)

        if not intent_chain.strip():
            _print(console, f"    [dim]Empty intent chain, skipping Logic Agent.[/dim]")
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
        if logic_response:
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

            # Lightweight verification for high-confidence findings
            if result.is_vulnerable and result.confidence >= 7:
                with _status(console, f"Verifying {slice_.id}..."):
                    verify_prompt = logic_agent.create_verify_prompt(
                        result, code_block=code_block,
                    )
                    verify_response = _call_llm(llm, verify_prompt, console)
                if verify_response:
                    verified = logic_agent.verify(
                        result, code_block=code_block, llm_response=verify_response,
                    )
                    all_results[-1] = verified
                    if not verified.is_vulnerable:
                        _print(console, f"    [dim]Verification rejected — downgraded to interesting ({verified.confidence}/10)[/dim]")
                    else:
                        _print(console, f"    [dim]Verification confirmed — {verified.confidence}/10[/dim]")

    return all_results


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

    args = parser.parse_args()
    run_v3_pipeline(
        target=args.target,
        model=args.model,
        verbose=args.verbose,
        use_codeql=args.codeql,
    )


if __name__ == "__main__":
    main()
