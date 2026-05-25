"""Report generation with confidence levels."""

from datetime import datetime
from typing import Optional

from agies.tools.report import get_findings


def generate_markdown(target: str, context: dict,
                       analyzer_result: Optional["AnalysisResult"] = None,
                       route_section: str = "") -> str:
    """Generate a Markdown audit report from findings."""
    from agies.analyzer.models import AnalysisResult

    findings = get_findings()
    lines = []
    lines.append("# AI Code Audit Report")
    lines.append(f"**Target:** `{target}`")
    lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Files scanned:** {context.get('file_count', 'N/A')}")
    lines.append(f"**Languages detected:** {', '.join(context.get('languages', []))}")
    lines.append("")

    # ── Route Analysis Section ──────────────────────────────
    if route_section:
        lines.append(route_section)
        lines.append("")

    # ── Static Analysis Results ─────────────────────────────
    if analyzer_result and analyzer_result.findings:
        lines.append("## Static Analysis Findings")
        lines.append("")
        lines.append(f"**Total: {len(analyzer_result.findings)}**")
        lines.append("")
        for f in analyzer_result.findings:
            lines.append(f"### [{f.severity.upper()}] {f.title}")
            lines.append(f"**Location:** `{f.file_path}` line {f.line_number}")
            lines.append("")
            lines.append(f.description)
            lines.append("")
            if f.taint_path and f.taint_path.propagation_steps:
                lines.append("**Taint Flow:**")
                lines.append(f"- Source: `{f.taint_path.source.file_path}:{f.taint_path.source.line}`")
                for step in f.taint_path.propagation_steps[:5]:
                    lines.append(f"- → `{step.file_path}:{step.line}` ({step.variable_or_expr})")
                lines.append(f"- Sink: `{f.taint_path.sink.file_path}:{f.taint_path.sink.line}`")
            if f.call_chain:
                lines.append(f"**Call Chain:** {len(f.call_chain)} hop(s)")
            if f.suggestion:
                lines.append("")
                lines.append(f"> **Fix:** {f.suggestion}")
            lines.append("")
            lines.append("---")
            lines.append("")

    if not findings:
        lines.append("## LLM Agent Findings")
        lines.append("No issues were detected by the AI agent.")
        lines.append("")
        return "\n".join(lines)

    # Summary counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    confidence_counts = {"L1": 0, "L2": 0, "L3": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        conf = f.get("confidence", "L2")
        if conf in confidence_counts:
            confidence_counts[conf] += 1

    lines.append("## Summary")
    total = len(findings)
    lines.append(f"**Total findings: {total}**")
    for sev in ["critical", "high", "medium", "low", "info"]:
        c = severity_counts.get(sev, 0)
        if c:
            lines.append(f"- **{sev.capitalize()}**: {c}")

    lines.append("")
    lines.append("**Confidence Distribution:**")
    lines.append(f"- **L1 (Pattern Match)**: {confidence_counts.get('L1', 0)} -- grep/pattern match, may be false positive")
    lines.append(f"- **L2 (Data Flow)**: {confidence_counts.get('L2', 0)} -- source to sink confirmed")
    lines.append(f"- **L3 (Full Chain)**: {confidence_counts.get('L3', 0)} -- HTTP entry to vulnerability confirmed")
    lines.append("")

    # Verification summary
    ver_statuses = {"verified": 0, "uncertain": 0, "contradicted": 0, "unverified": 0}
    for f in findings:
        vs = f.get("verification", {}).get("verification_status", "unverified")
        ver_statuses[vs] = ver_statuses.get(vs, 0) + 1
    has_verification = any(f.get("verification") for f in findings)
    if has_verification:
        lines.append("**Verification Status:**")
        if ver_statuses.get("verified"):
            lines.append(f"- **Verified**: {ver_statuses['verified']}")
        if ver_statuses.get("uncertain"):
            lines.append(f"- **Uncertain**: {ver_statuses['uncertain']}")
        if ver_statuses.get("contradicted"):
            lines.append(f"- **Contradicted**: {ver_statuses['contradicted']}")
        if ver_statuses.get("unverified"):
            lines.append(f"- **Unverified**: {ver_statuses['unverified']}")
        lines.append("")

    # Findings detail
    lines.append("## Findings")
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        conf = f.get("confidence", "L2")
        sev_badge = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH",
                      "medium": "🟡 MEDIUM", "low": "🔵 LOW",
                      "info": "⚪ INFO"}.get(sev, "INFO")
        conf_badge = {"L1": "🔍 L1(Pattern)", "L2": "📊 L2(DataFlow)",
                      "L3": "✅ L3(FullChain)"}.get(conf, "🔍 L1")

        lines.append(f"### {i}. [{sev_badge}][{conf_badge}] {f['title']}")
        if f.get("file_path"):
            loc = f["file_path"]
            if f.get("line_number"):
                loc += f"#{f['line_number']}"
            lines.append(f"**Location:** `{loc}`")

        # Verification status
        ver = f.get("verification", {})
        if ver:
            vs = ver.get("verification_status", "")
            if vs == "verified":
                lines.append("**Verification:** Verified")
            elif vs == "contradicted":
                lines.append("**Verification:** Contradicted")
                for c in ver.get("contradictions", []):
                    lines.append(f"- Contradiction: {c}")
            elif vs == "uncertain":
                lines.append("**Verification:** Uncertain")
                for e in ver.get("evidence_chain", [])[-2:]:
                    lines.append(f"- {e.get('status', '')}: {e.get('detail', '')[:100]}")
            elif vs == "unverified":
                lines.append("**Verification:** Unverified")

        lines.append("")
        lines.append(f["detail"])
        lines.append("")
        if f.get("suggestion"):
            lines.append("**Suggestion:**")
            lines.append(f"> {f['suggestion']}")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def generate_json() -> list[dict]:
    """Return findings as a list of dicts suitable for JSON output."""
    return get_findings()
