"""Convert taint paths and analysis results into structured findings."""

from __future__ import annotations

from agies.analyzer.config import AnalysisConfig, LanguageAnalysisConfig
from agies.analyzer.models import AnalyzerFinding, AnalysisResult, TaintPath


def _sink_to_rule_id(sink_name: str) -> str:
    """Derive a rule ID from a sink function name."""
    mapping = {
        # Python
        "eval": "python-code-injection",
        "exec": "code-injection",
        "compile": "python-code-injection",
        "__import__": "python-code-injection",
        "os.system": "os-command-injection",
        "os.popen": "os-command-injection",
        "subprocess.Popen": "os-command-injection",
        "subprocess.run": "os-command-injection",
        "subprocess.call": "os-command-injection",
        "subprocess.check_output": "os-command-injection",
        "subprocess.check_call": "os-command-injection",
        "sqlite3.execute": "sql-injection",
        "sqlite3.executemany": "sql-injection",
        "sqlite3.executescript": "sql-injection",
        "pickle.loads": "unsafe-deserialization",
        "pickle.load": "unsafe-deserialization",
        "yaml.load": "unsafe-deserialization",
        "open": "path-traversal",
        # JavaScript
        "innerHTML": "xss",
        "outerHTML": "xss",
        "insertAdjacentHTML": "xss",
        "document.write": "xss",
        "Function": "code-injection",
        # Java
        "Runtime.exec": "os-command-injection",
        "ProcessBuilder": "os-command-injection",
        "ProcessBuilder.start": "os-command-injection",
        "Statement.executeQuery": "sql-injection",
        "Statement.executeUpdate": "sql-injection",
        "Statement.execute": "sql-injection",
        "PreparedStatement.executeQuery": "sql-injection",
        "PreparedStatement.executeUpdate": "sql-injection",
        "PreparedStatement.execute": "sql-injection",
        "InitialContext.lookup": "jndi-injection",
        "Context.lookup": "jndi-injection",
        "Method.invoke": "reflective-injection",
        "ObjectInputStream.readObject": "unsafe-deserialization",
        "HttpURLConnection.connect": "ssrf",
        "URL.openConnection": "ssrf",
        "URL.openStream": "ssrf",
        "HttpClient.send": "ssrf",
        "RestTemplate.exchange": "ssrf",
        "DocumentBuilder.parse": "xxe",
        "SAXParser.parse": "xxe",
    }
    return mapping.get(sink_name, f"taint-to-{sink_name.replace('.', '-')}")


def _build_suggestion(severity: str, sink_name: str, source_name: str) -> str:
    """Build a human-readable fix suggestion."""
    if "eval" in sink_name or "exec" in sink_name:
        return (
            f"Avoid using {sink_name} with user-controlled input. "
            "Consider using safer alternatives like `ast.literal_eval()` for data evaluation, "
            "or validate/sanitize the input with a strict allowlist."
        )
    if "os.system" in sink_name or "subprocess" in sink_name:
        return (
            f"Avoid passing user input to {sink_name}. "
            "Use `subprocess.run()` with `shell=False` and pass arguments as a list. "
            "Validate and sanitize the input with a strict allowlist."
        )
    if "sqlite3" in sink_name:
        return (
            f"Use parameterized queries instead of string formatting in {sink_name}. "
            "Pass query parameters as a tuple/second argument to `execute()`."
        )
    if "pickle" in sink_name:
        return (
            f"Never unpickle untrusted data. Use a safer serialization format like JSON "
            f"or validate the input before deserialization."
        )
    if sink_name == "open":
        return (
            f"Restrict file paths from user input using `os.path.abspath()` and "
            f"verify they stay within an allowed base directory."
        )
    return (
        f"Validate and sanitize user-controlled input before passing it to {sink_name}. "
        "Consider using input validation, allowlists, or proper escaping."
    )


def generate_findings(
    taint_paths: list[TaintPath],
    lang_config: LanguageAnalysisConfig,
) -> list[AnalyzerFinding]:
    """Convert taint paths into structured AnalyzerFinding objects."""
    findings: list[AnalyzerFinding] = []

    for path in taint_paths:
        severity = lang_config.sinks.get(path.sink_rule_name, "medium")
        rule_id = _sink_to_rule_id(path.sink_rule_name)

        # Build description with taint flow
        source_detail = path.source.detail or f"source at {path.source.file_path}:{path.source.line}"
        sink_detail = f"call to {path.sink.variable_or_expr} at {path.sink.file_path}:{path.sink.line}"

        steps_desc = ""
        if path.propagation_steps:
            step_desc_list = [f"  → {s.variable_or_expr}" for s in path.propagation_steps[:5]]
            steps_desc = "\n" + "\n".join(step_desc_list)

        description = (
            f"Tainted data from {source_detail} flows into "
            f"{sink_detail}.{steps_desc}\n\n"
            f"Confidence: {path.confidence}"
        )

        suggestion = _build_suggestion(severity, path.sink_rule_name, path.source_rule_name)

        finding = AnalyzerFinding(
            rule_id=rule_id,
            severity=severity,
            title=f"Tainted data reaches {path.sink_rule_name}",
            description=description,
            file_path=path.sink.file_path,
            line_number=path.sink.line,
            taint_path=path,
            call_chain=[(path.source.file_path, path.source.line)],
            suggestion=suggestion,
        )
        findings.append(finding)

    # Sort by severity (critical first, then high, medium, low, info)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    # Deduplicate by (file, line, rule_id)
    seen: set[tuple[str, int, str]] = set()
    deduped: list[AnalyzerFinding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.rule_id)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped


def augment_result(result: AnalysisResult, config: AnalysisConfig) -> None:
    """Add findings to an AnalysisResult from its taint_paths.

    Uses AnalysisConfig to look up per-language sink severity mappings.
    """
    all_findings: list[AnalyzerFinding] = []
    for path in result.taint_paths:
        # Determine which language config to use from the sink file's parsed language
        # Fallback: try each lang_config that contains this sink_rule_name
        lang_config = None
        for lc in config.languages.values():
            if path.sink_rule_name in lc.sinks:
                lang_config = lc
                break
        if lang_config is None and config.languages:
            lang_config = next(iter(config.languages.values()))

        if lang_config:
            all_findings.extend(generate_findings([path], lang_config))
        else:
            all_findings.extend(generate_findings([path], LanguageAnalysisConfig(language="unknown")))

    result.findings = all_findings
