"""Quick scan — static analysis without LLM.

Provides fast, actionable output for CI or quick checks:
1. Language detection + file counting
2. Heuristic file prioritization (no LLM)
3. Static analysis (Python taint tracking)
4. Concise report with priority targets
"""

import os
from datetime import datetime

from agies.core import collect_context, collect_files
from agies.strategy import StrategyEngine
from agies.analyzer import Analyzer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def run_scan(target: str, output: str | None = None) -> dict:
    """Run a quick scan — static analysis only, no LLM."""
    target = os.path.abspath(target)

    if not os.path.exists(target):
        console.print(f"[red]Error: target does not exist: {target}[/red]")
        return {"error": "target not found"}

    # Step 1: Collect context
    context = collect_context(target)
    if "error" in context:
        console.print(f"[red]{context['error']}[/red]")
        return context

    console.print(f"[bold]agies scan[/bold] — [cyan]{target}[/cyan]")
    console.print(f"  Languages: {', '.join(context.get('languages', ['none detected']))}")
    console.print(f"  Files: {context['file_count']}")
    console.print()

    # Step 2: File prioritization
    all_files = collect_files(target)
    engine = StrategyEngine(target)
    strategy_result = engine.analyze_project(all_files)
    priority_summary = strategy_result["priority_summary"]

    # Display top priority files
    table = Table(title="Top Priority Files (heuristic)")
    table.add_column("Score", style="cyan", justify="right")
    table.add_column("File", style="white")
    table.add_column("Reason", style="dim")

    for sf in engine.priority_files[:10]:
        rel = os.path.relpath(sf.path, target)
        table.add_row(str(sf.score), rel, sf.reason[:50])

    console.print(table)
    console.print()

    # Step 3: Static analysis (Python only)
    findings = []
    if "Python" in context.get("languages", []):
        with console.status("[bold]Running static analysis...[/bold]"):
            analyzer = Analyzer()
            result = analyzer.run(target)
            findings = result.findings

        if findings:
            console.print(f"  [yellow]Static analysis: {len(findings)} finding(s)[/yellow]")
            for f in findings:
                console.print(f"  [{f.severity.upper()}] {f.title}")
                console.print(f"         {f.file_path}:{f.line_number}")
                console.print()
        else:
            console.print("  [dim]Static analysis: no findings[/dim]")
    else:
        console.print("  [dim]Static analysis: Python only, skipping[/dim]")

    # Step 4: Generate report
    scan_result = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "context": {
            "languages": context.get("languages", []),
            "file_count": context["file_count"],
        },
        "static_findings": [
            {
                "severity": f.severity,
                "title": f.title,
                "file": f.file_path,
                "line": f.line_number,
                "description": f.description,
            }
            for f in findings
        ],
        "priority_files": [
            {"path": sf.path, "score": sf.score, "reason": sf.reason}
            for sf in engine.priority_files[:20]
        ],
        "suggested_llm_targets": strategy_result["high_value_files"],
        "scan_summary": priority_summary,
    }

    # Output
    if output:
        import json
        with open(output, "w") as f:
            json.dump(scan_result, f, indent=2, ensure_ascii=False)
        console.print(f"Scan report written to [cyan]{output}[/cyan]")
    else:
        _print_summary(scan_result)

    return scan_result


def _print_summary(result: dict):
    """Print a human-readable summary."""
    total = result["context"]["file_count"]
    findings = result["static_findings"]
    targets = result.get("suggested_llm_targets", [])

    lines = [f"\n[bold]Scan Summary[/bold]"]
    lines.append(f"  Target: {result['target']}")
    lines.append(f"  Files: {total}")
    lines.append(f"  Languages: {', '.join(result['context']['languages'])}")
    lines.append(f"  Static findings: {len(findings)}")

    if findings:
        lines.append(f"\n  [yellow]Findings by severity:[/yellow]")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sum(1 for f in findings if f.get("severity") == sev)
            if count:
                lines.append(f"    {sev.capitalize()}: {count}")

    if targets:
        lines.append(f"\n  [cyan]Suggested for full LLM audit: {len(targets)} files[/cyan]")
        for t in targets[:5]:
            rel = os.path.relpath(t, result["target"])
            lines.append(f"    - {rel}")

    console.print(Panel("\n".join(lines), title="Results"))
