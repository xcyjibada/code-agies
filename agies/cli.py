import typer
from rich.console import Console
from typing import Optional

from agies.core.auditor import run_audit

app = typer.Typer(help="agies — AI-native code audit CLI")
console = Console()


@app.command()
def audit(
    target: str = typer.Argument(..., help="Target file or directory to audit"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model (e.g. deepseek-chat, gpt-4o, claude-sonnet-4-6)"),
    strong_model: Optional[str] = typer.Option(None, "--strong-model", help="Stronger model for cross-model verification (e.g. claude-opus-4-7)"),
    sandbox: bool = typer.Option(False, "--sandbox", help="Run commands in Docker sandbox"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output report path"),
    output_format: Optional[str] = typer.Option(None, "--output-format", "-f", help="Output format: markdown or json"),
    static_analysis: bool = typer.Option(True, "--static/--no-static", help="Enable/disable static analysis"),
    static_only: bool = typer.Option(False, "--static-only", help="Run static analysis only (skip LLM)"),
    verify: Optional[bool] = typer.Option(None, "--verify/--no-verify", help="Enable/disable verification pipeline"),
    new_pipeline: bool = typer.Option(False, "--new-pipeline", help="Use new Xint-inspired pipeline (sourcer → bulk → verification)"),
    v3: bool = typer.Option(False, "--v3", help="Use v3 CodeQL pipeline (source→sink path queries)"),
    project_type: Optional[str] = typer.Option(None, "--project-type", help="Override project type: app or lib (v3 only)"),
    consensus: bool = typer.Option(False, "--consensus", help="Enable conditional majority voting for grey-zone findings (confidence 4-7)"),
    all_paths: bool = typer.Option(False, "--all-paths", help="Skip path filtering, send ALL discovered paths to analysis (v3 only, high-value targets)"),
):
    """Run an AI-powered code audit on the target.

    Configuration is loaded from .agies/config.yml if present.
    CLI flags override config file values.
    """
    import logging

    if verbose:
        logging.basicConfig(
            level=logging.INFO,
            format="%(levelname)s %(name)s: %(message)s",
            force=True,
        )

    from agies.core.config import load_config

    cfg = load_config(target)

    # Merge: CLI arg → config file → hardcoded default
    final_model = model or cfg.llm.model or "deepseek-chat"
    final_strong = strong_model or cfg.llm.strong_model
    final_output = output or cfg.report.output or None
    final_output_format = output_format or cfg.report.format or "markdown"
    final_verify = verify if verify is not None else cfg.verification.enabled

    run_audit(target, model=final_model, strong_model=final_strong, sandbox=sandbox,
              verbose=verbose, output=final_output, output_format=final_output_format,
              static_analysis=static_analysis, static_only=static_only,
              verify=final_verify, new_pipeline=new_pipeline, v3=v3,
              project_type=project_type, consensus=consensus, all_paths=all_paths)


@app.command()
def init(
    target: str = typer.Argument(".", help="Project root directory"),
    ci: bool = typer.Option(False, "--ci", help="Also generate CI/CD workflow templates"),
):
    """Initialize agies configuration in the project.

    Auto-detects project languages and creates .agies/config.yml
    with sensible defaults.
    """
    from agies.core.config import init_config
    config_path = init_config(target, ci=ci)
    console.print(f"[green]Config created:[/green] {config_path}")
    console.print()
    console.print("  Next steps:")
    console.print("  1. Review [cyan].agies/config.yml[/cyan] and adjust settings")
    console.print(f'  2. Run [bold]agies scan .[/bold] for a quick static analysis')
    console.print(f'  3. Run [bold]agies audit .[/bold] for a full LLM-powered audit')
    if ci:
        console.print(f'     CI/CD workflows generated in [cyan].agies/[/cyan]')
    console.print("[bold]Done.[/bold]")


@app.command()
def scan(
    target: str = typer.Argument(".", help="Directory to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON report path"),
):
    """Quick scan for common issues without full AI analysis.

    Runs static analysis + heuristic file prioritization.
    No LLM API key required.
    """
    from agies.core.scanner import run_scan
    run_scan(target, output=output)
