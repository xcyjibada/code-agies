#!/usr/bin/env python3
"""Real-world test: Vulnerability Agent against vulpy (deliberately vulnerable Flask app).

Runs the full pipeline via Brain → Runner(parallel) → State(with dedup).

Usage:
    python tests/test_vuln_real.py [--model claude-sonnet-4-6] [--project /path/to/vulpy]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

VULPY_REPO = "https://github.com/fportantier/vulpy.git"


def clone_vulpy(target_dir: str) -> str:
    """Clone vulpy repository and return path to the 'bad' version."""
    print(f"[*] Cloning vulpy to {target_dir}...", flush=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", VULPY_REPO, target_dir],
        capture_output=True, check=True,
    )
    bad_path = os.path.join(target_dir, "bad")
    if not os.path.exists(bad_path):
        print("[!] 'bad' directory not found, using repo root.")
        bad_path = target_dir
    return bad_path


def count_python_lines(project_path: str) -> int:
    """Count lines of Python code in a project."""
    result = subprocess.run(
        ["find", project_path, "-name", "*.py", "-exec", "cat", "{}", "+"],
        capture_output=True, text=True,
    )
    return len(result.stdout.splitlines())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test Vulnerability Agent against vulpy"
    )
    parser.add_argument(
        "--model", default="claude-sonnet-4-20250514",
        help="LLM model name (default: claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--project",
        help="Path to existing vulpy clone (will clone if not provided)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output report path (default: vuln_real_test_report.md)",
    )
    parser.add_argument(
        "--workers", type=int, default=5,
        help="Max parallel workers (default: 5)",
    )
    args = parser.parse_args()

    model_name = args.model
    max_workers = args.workers
    temp_dir = None
    needs_cleanup = False

    if args.project:
        project_path = os.path.abspath(args.project)
        if not os.path.exists(project_path):
            print(f"Error: {project_path} does not exist")
            sys.exit(1)
        print(f"[*] Using existing project: {project_path}")
    else:
        temp_dir = tempfile.mkdtemp(prefix="agies_vuln_test_")
        needs_cleanup = True
        try:
            project_path = clone_vulpy(temp_dir)
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to clone vulpy: {e}")
            shutil.rmtree(temp_dir)
            sys.exit(1)

    project_path = os.path.abspath(project_path)
    output_path = args.output or os.path.join(
        os.path.dirname(__file__), "vuln_real_test_report.md"
    )

    loc = count_python_lines(project_path)
    print(f"[*] Project: {project_path} ({loc} Python LOC)", flush=True)
    print(f"[*] Model:   {model_name}", flush=True)
    print(f"[*] Workers: {max_workers}", flush=True)
    print(f"[*] Output:  {output_path}", flush=True)
    print()

    report_sections: list[str] = []
    errors: list[str] = []

    report_sections.append(f"""# Vulnerability Agent Real-World Test Report

**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}
**Model:** {model_name}
**Project:** {os.path.basename(project_path)} ({loc} Python LOC)
**Mode:** Brain → Runner(parallel) → State(dedup)

---

""")

    # --- Step 1: Create LLM ---
    print("=" * 60, flush=True)
    print("STEP 1: Creating LLM", flush=True)
    print("=" * 60, flush=True)

    try:
        from agies.llm import get_model
        llm = get_model(model_name)
    except Exception as e:
        print(f"[!] Error creating LLM: {e}", flush=True)
        errors.append(f"LLM creation failed: {e}")
        if needs_cleanup and temp_dir:
            shutil.rmtree(temp_dir)
        sys.exit(1)

    if not getattr(llm, "api_key", None):
        key_name = getattr(llm, "env_key_name", "API_KEY")
        print(f"[!] Warning: {key_name} is not set. May fail.", flush=True)

    # --- Step 2: Run Brain (Mapping → Vulnerability) ---
    print()
    print("=" * 60, flush=True)
    print("STEP 2: Running Brain → Mapping → Vulnerability pipeline", flush=True)
    print("=" * 60, flush=True)

    from agies.engine.v2.runner import Runner
    from agies.engine.v2.brain import Brain
    from agies.engine.v2.agents.mapping import MappingAgent, MappingOutput
    from agies.engine.v2.agents.vulnerability import (
        VulnerabilityAgent, VulnerabilityOutput,
    )

    runner = Runner(llm=llm, max_workers=max_workers)
    brain = Brain(runner=runner)
    brain.register_agent("mapping", MappingAgent())
    brain.register_agent("vulnerability", VulnerabilityAgent())

    start = time.time()
    try:
        state = brain.run(project_path)
        total_time = time.time() - start
        print(f"[✓] Brain pipeline complete ({total_time:.1f}s)", flush=True)
        print(f"    Completed agents: {state.completed_agents}", flush=True)
        print(f"    Key files: {len(state.key_files)}", flush=True)
        print(f"    Raw vulns received: {state.dedup_stats.get('total_raw', 'N/A')}", flush=True)
        print(f"    Unique vulns after dedup: {len(state.candidate_vulnerabilities)}", flush=True)
        for agent, tokens in state.agent_tokens.items():
            print(f"    {agent} tokens: {tokens}", flush=True)

    except Exception as e:
        print(f"[!] Brain pipeline failed: {e}", flush=True)
        errors.append(f"Brain pipeline failed: {e}")
        state = None

    # --- Build report ---
    if state is None:
        report_sections.append("Pipeline failed — no results.")
        print("[!] Pipeline failed, writing minimal report.", flush=True)
    else:
        # Mapping details
        report_sections.append(f"""## Phase 1: Project Mapping

**Time:** included in pipeline ({total_time:.1f}s total)
**Tokens (mapping):** {state.agent_tokens.get('mapping', 'N/A')}

### Summary
{state.project_summary or 'N/A'}

### Key Files ({len(state.key_files)})
""")

        for kf in state.key_files:
            analyzed = "✅" if kf.get("vuln_analyzed") else "❌"
            report_sections.append(f"""| `{kf.get('path')}` | {kf.get('role', '?')} | {analyzed} |""")

        report_sections.append(f"""
### Trust Assumptions ({len(state.trust_assumptions)})
""")

        for ta in state.trust_assumptions:
            report_sections.append(f"""- **{ta.get('assumption', '?')}** (risk: `{ta.get('risk_category', '?')}`)""")

        report_sections.append("\n---\n")

        # Vulnerability details
        all_vulns = state.candidate_vulnerabilities
        raw_count = state.dedup_stats.get("total_raw", len(all_vulns))
        dedup_count = len(all_vulns)
        compression = (
            (1 - dedup_count / raw_count) * 100 if raw_count > 0 else 0
        )

        report_sections.append(f"""## Phase 2: Vulnerability Analysis

### Summary

| Metric | Value |
|--------|-------|
| Pipeline total time | {total_time:.1f}s |
| Max parallel workers | {max_workers} |
| Key files analyzed | {sum(1 for kf in state.key_files if kf.get('vuln_analyzed'))}/{len(state.key_files)} |
| Raw findings (before dedup) | {raw_count} |
| Unique findings (after dedup) | {dedup_count} |
| Compression | {compression:.0f}% |
| Files with findings | {len(set(v.get('file_path', '') for v in all_vulns))} |
""")

        # Severity breakdown
        sev_map: dict[str, int] = {}
        type_map: dict[str, int] = {}
        conf_map: dict[str, int] = {}
        for v in all_vulns:
            sev = v.get("severity", "unknown")
            sev_map[sev] = sev_map.get(sev, 0) + 1
            vtype = v.get("type", "unknown")
            type_map[vtype] = type_map.get(vtype, 0) + 1
            conf = v.get("confidence", "unknown")
            conf_map[conf] = conf_map.get(conf, 0) + 1

        report_sections.append("\n### By Severity\n")
        for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
            if sev in sev_map:
                report_sections.append(f"- **{sev.capitalize()}**: {sev_map[sev]}\n")

        report_sections.append("\n### By Vulnerability Type\n")
        for vtype in sorted(type_map.keys()):
            report_sections.append(f"- **{vtype}**: {type_map[vtype]}\n")

        report_sections.append("\n### By Confidence\n")
        for conf in ["high", "medium", "low"]:
            if conf in conf_map:
                report_sections.append(f"- **{conf}**: {conf_map[conf]}\n")

        report_sections.append("\n### All Findings (deduplicated)\n")
        for i, v in enumerate(all_vulns, 1):
            report_sections.append(f"""#### {i}. {v.get('title', 'Untitled')}

| Field | Value |
|-------|-------|
| **Type** | `{v.get('type', '?')}` |
| **Severity** | **{v.get('severity', '?').upper()}** |
| **File** | `{v.get('file_path', '?')}` |
| **Line** | {v.get('line_number', '?')} |
| **Confidence** | {v.get('confidence', '?')} |

**Description:** {v.get('description', 'N/A')}

**Reasoning:** {v.get('reasoning', 'N/A')}

**Attack Path:** {v.get('attack_path', 'N/A')}

**Suggestion:** {v.get('suggestion', 'N/A')}

""")

        # Token usage
        report_sections.append(f"""
### Token Usage

| Agent | Tokens |
|-------|--------|
| Mapping | {state.agent_tokens.get('mapping', 0)} |
| Vulnerability | {state.agent_tokens.get('vulnerability', 0)} |
| **Grand Total** | {sum(state.agent_tokens.values())} |
""")

    # Errors
    if errors:
        report_sections.append("""
### Errors
""")
        for e in errors:
            report_sections.append(f"- ❌ {e}\n")

    report_sections.append("""
---

*Report generated by `tests/test_vuln_real.py` (Brain pipeline)*
""")

    # --- Write report ---
    report_text = "".join(report_sections)
    with open(output_path, "w") as f:
        f.write(report_text)

    print()
    print("=" * 60, flush=True)
    print("RESULTS", flush=True)
    print("=" * 60, flush=True)
    if state:
        print(f"  Total unique vulnerabilities found: {len(state.candidate_vulnerabilities)}", flush=True)
        print(f"  Dedup stats: {state.dedup_stats}", flush=True)
        print(f"  Token usage: {state.agent_tokens}", flush=True)
    print(f"  Report written to: {output_path}", flush=True)
    print()

    # --- Cleanup ---
    if needs_cleanup and temp_dir:
        print(f"[*] Cleaning up temp directory: {temp_dir}", flush=True)
        shutil.rmtree(temp_dir, ignore_errors=True)

    print("[✓] Done.", flush=True)


if __name__ == "__main__":
    main()
