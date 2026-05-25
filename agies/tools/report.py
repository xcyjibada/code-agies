"""Report writing tool — accumulates findings in a shared list with confidence levels."""

from typing import Optional

# Shared state for accumulating findings during an audit session
_findings: list[dict] = []
_analyzer_result: Optional["AnalysisResult"] = None  # Set by auditor


def reset_findings():
    _findings.clear()


def get_findings() -> list[dict]:
    return list(_findings)


def set_analyzer_result(result) -> None:
    """Store the static analysis result for the get_taint_flows tool."""
    global _analyzer_result
    _analyzer_result = result


def get_analyzer_result():
    """Retrieve the stored analyzer result."""
    return _analyzer_result


def write_report(
    title: str,
    detail: str,
    severity: str = "info",
    file_path: str | None = None,
    line_number: int | None = None,
    suggestion: str | None = None,
    confidence: str = "medium",
) -> str:
    """Record a finding to the audit report.

    Args:
        title: Finding title
        detail: Detailed description of the finding
        severity: critical/high/medium/low/info
        file_path: Related file path
        line_number: Related line number
        suggestion: Fix suggestion
        confidence: L1(pattern match) / L2(data flow) / L3(full chain)

    Returns:
        Formatted finding string.
    """
    # Normalize confidence
    confidence = confidence.lower()
    if confidence in ("l1", "l1"):
        confidence = "L1"
    elif confidence in ("l2", "l2"):
        confidence = "L2"
    elif confidence in ("l3", "l3"):
        confidence = "L3"
    elif confidence not in ("L1", "L2", "L3"):
        confidence = "L2"  # default

    finding = {
        "title": title,
        "detail": detail,
        "severity": severity,
        "file_path": file_path,
        "line_number": line_number,
        "suggestion": suggestion,
        "confidence": confidence,
    }
    _findings.append(finding)

    sev_tag = {
        "critical": "🔥",
        "high": "⚠️",
        "medium": "📌",
        "low": "📝",
        "info": "ℹ️",
    }.get(severity, "ℹ️")

    conf_tag = {"L1": "🔍", "L2": "📊", "L3": "✅"}.get(confidence, "🔍")

    return f"{sev_tag}{conf_tag} [{severity.upper()}][{confidence}] {title}"


def get_taint_flows(
    severity: Optional[str] = None,
    file_glob: Optional[str] = None,
    sink_name: Optional[str] = None,
    limit: int = 20,
) -> str:
    """Query structured taint flow data from static analysis.

    Args:
        severity: Filter by severity (critical/high/medium/low/info)
        file_glob: Filter by file path substring
        sink_name: Filter by sink function name
        limit: Maximum results to return

    Returns:
        Formatted string with taint flow details.
    """
    result = _analyzer_result
    if result is None:
        return "No static analysis results available."

    findings = result.findings
    if severity:
        findings = [f for f in findings if f.severity == severity]
    if file_glob:
        findings = [f for f in findings if file_glob in f.file_path]
    if sink_name:
        findings = [f for f in findings
                    if sink_name in f.title
                    or (f.taint_path and sink_name in f.taint_path.sink.variable_or_expr)]

    if not findings:
        return "No matching findings found."

    lines = [f"Found {len(findings)} matching taint flow(s):", ""]
    for i, f in enumerate(findings[:limit], 1):
        lines.append(f"{i}. [{f.severity.upper()}] {f.title}")
        lines.append(f"   Location: {f.file_path}:{f.line_number}")
        if f.taint_path:
            tp = f.taint_path
            lines.append(f"   Source: {tp.source.file_path}:{tp.source.line} ({tp.source.detail})")
            for step in tp.propagation_steps[:3]:
                lines.append(f"   → {step.file_path}:{step.line} ({step.detail})")
            lines.append(f"   Sink:  {tp.sink.file_path}:{tp.sink.line} ({tp.sink.detail})")
        if f.suggestion:
            lines.append(f"   Fix: {f.suggestion[:100]}")
        lines.append("")

    if len(findings) > limit:
        lines.append(f"... and {len(findings) - limit} more. Refine your filter.")

    return "\n".join(lines)
