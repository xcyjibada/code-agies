"""EvidenceChecker — code-level evidence verification for Logic Agent findings.

Phase 1:  Pattern-based scan (no LLM) — keyword match on source code.
Phase 1b: AST-based sink argument analysis — classify the dangerous argument
          as HARDCODED / HTTP_INPUT / CONFIG_DRIVEN / FUNCTION_PARAM / UNTRACEABLE.
Phase 1c: Guard detection — input validation / sanitization before sink call.
Phase 2:  LLM deep analysis (only if Phase 1+1b+1c produce ambiguous results).
Phase 3:  Record to blackboard.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from agies.engine.v3.aggregator.blackboard import BlackboardAggregator
from agies.engine.v3.aggregator.models import AgentPhaseResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Evidence patterns: per-vuln-type, checked against raw source code.
# The checker must find at least one match for the finding to be credible.
# ---------------------------------------------------------------------------

EVIDENCE_PATTERNS: dict[str, list[re.Pattern]] = {
    "lfi": [
        re.compile(r"\bopen\s*\(", re.IGNORECASE),
        re.compile(r"\.read\s*\(", re.IGNORECASE),
        re.compile(r"pathlib\.Path"),
        re.compile(r"PurePosixPath|PureWindowsPath"),
        re.compile(r"os\.path\.join|posixpath\.join|ntpath\.join"),
        re.compile(r"read_text|read_bytes"),
    ],
    "rce": [
        re.compile(r"\bexec\b", re.IGNORECASE),
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"subprocess\.", re.IGNORECASE),
        re.compile(r"os\.system|os\.popen", re.IGNORECASE),
        re.compile(r"pickle\.loads|pickle\.load|cloudpickle", re.IGNORECASE),
        re.compile(r"yaml\.load(?!s)", re.IGNORECASE),
        re.compile(r"__import__"),
        re.compile(r"\bcompile\s*\(", re.IGNORECASE),
    ],
    "redos": [
        re.compile(r"re\.(match|search|sub|compile|findall|fullmatch|split)", re.IGNORECASE),
        re.compile(r"fnmatch\.(translate|filter)", re.IGNORECASE),
        re.compile(r"\bglob\b", re.IGNORECASE),
    ],
    "afo": [
        re.compile(r"\.write\s*\(", re.IGNORECASE),
        re.compile(r"shutil\.\w+", re.IGNORECASE),
        re.compile(r"os\.remove|os\.unlink|os\.rmdir", re.IGNORECASE),
        re.compile(r"extractall|extract\s*\(", re.IGNORECASE),
    ],
    "ssrf": [
        re.compile(r"urlopen|urlretrieve", re.IGNORECASE),
        re.compile(r"httpx\.", re.IGNORECASE),
        re.compile(r"aiohttp\.", re.IGNORECASE),
        re.compile(r"requests\.", re.IGNORECASE),
    ],
    "sqli": [
        re.compile(r"\bexecute\b", re.IGNORECASE),
        re.compile(r"executemany|executescript", re.IGNORECASE),
    ],
    "idor": [
        re.compile(r"\.get\s*\(", re.IGNORECASE),
        re.compile(r"\.filter\s*\(", re.IGNORECASE),
        re.compile(r"objects\.|queryset", re.IGNORECASE),
        re.compile(r"get_object_or_404", re.IGNORECASE),
    ],
    # -- Java evidence patterns --
    "java_rce": [
        re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(", re.IGNORECASE),
        re.compile(r"new\s+ProcessBuilder\s*\(", re.IGNORECASE),
        re.compile(r"ScriptEngine(Manager)?\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"SpelExpressionParser\.parseExpression", re.IGNORECASE),
        re.compile(r"Ognl\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"MVEL\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"Jexl(Engine|Expression)", re.IGNORECASE),
        re.compile(r"ELProcessor\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"GroovyShell\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"InitialContext\.lookup\s*\(", re.IGNORECASE),
        re.compile(r"ObjectInputStream\.readObject", re.IGNORECASE),
        re.compile(r"Yaml\.load\s*\(", re.IGNORECASE),
        re.compile(r"XStream\.fromXML\s*\(", re.IGNORECASE),
        re.compile(r"ObjectMapper\.enableDefaultTyping", re.IGNORECASE),
    ],
    "java_lfi": [
        re.compile(r"new\s+File(Input|Reader)\s*\(", re.IGNORECASE),
        re.compile(r"Files\.read(AllBytes|AllLines|String)\s*\(", re.IGNORECASE),
        re.compile(r"FileUtils\.read(FileToString|Lines)\s*\(", re.IGNORECASE),
        re.compile(r"ResourceLoader\.getResource\s*\(", re.IGNORECASE),
        re.compile(r"Paths\.get\s*\(", re.IGNORECASE),
    ],
    "java_ssrf": [
        re.compile(r"URL\.open(Connection|Stream)\s*\(", re.IGNORECASE),
        re.compile(r"CloseableHttpClient\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"OkHttpClient\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"RestTemplate\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"WebClient\.create\s*\(", re.IGNORECASE),
        re.compile(r"new\s+URL\s*\(", re.IGNORECASE),
        re.compile(r"new\s+Socket\s*\(", re.IGNORECASE),
    ],
    "java_sqli": [
        re.compile(r"Statement\.execute(Query|Update)?\s*\(", re.IGNORECASE),
        re.compile(r"JdbcTemplate\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"Session\.create(Query|SQLQuery)\s*\(", re.IGNORECASE),
        re.compile(r"EntityManager\.createNativeQuery\s*\(", re.IGNORECASE),
    ],
    "java_xxe": [
        re.compile(r"DocumentBuilder\.parse\s*\(", re.IGNORECASE),
        re.compile(r"SAX(Parser|Reader)\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"SAXBuilder\.build\s*\(", re.IGNORECASE),
        re.compile(r"XMLInputFactory\.create\w+Reader\s*\(", re.IGNORECASE),
        re.compile(r"XmlMapper\s*\(", re.IGNORECASE),
    ],
    "java_afo": [
        re.compile(r"new\s+File(Output|Writer)\s*\(", re.IGNORECASE),
        re.compile(r"Files\.(write|copy|move|delete)\s*\(", re.IGNORECASE),
        re.compile(r"FileUtils\.(write|copy|delete|move)", re.IGNORECASE),
    ],
    "java_ssti": [
        re.compile(r"freemarker.*Template\.process", re.IGNORECASE),
        re.compile(r"Velocity(Engine)?\.evaluate\s*\(", re.IGNORECASE),
        re.compile(r"TemplateEngine\.process\s*\(", re.IGNORECASE),
        re.compile(r"PebbleEngine\.getTemplate\s*\(", re.IGNORECASE),
    ],
}

# ---------------------------------------------------------------------------
# Sink argument specification: for each vuln type, which sink functions and
# which argument position to check.
# ---------------------------------------------------------------------------

SINK_ARG_SPEC: dict[str, list[tuple[re.Pattern, int, str]]] = {
    "lfi": [
        (re.compile(r"^open$"), 0, "file path"),
        (re.compile(r"^Path\.read_text$"), 0, "file path"),
        (re.compile(r"^Path\.read_bytes$"), 0, "file path"),
    ],
    "rce": [
        (re.compile(r"^exec$"), 0, "code"),
        (re.compile(r"^eval$"), 0, "expression"),
        (re.compile(r"^subprocess\.(call|run|Popen|check_output|check_call)$"), 0, "command"),
        (re.compile(r"^os\.system$"), 0, "command"),
        (re.compile(r"^os\.popen$"), 0, "command"),
        (re.compile(r"^pickle\.loads$"), 0, "pickle data"),
        (re.compile(r"^pickle\.load$"), 0, "pickle file"),
        (re.compile(r"^yaml\.load$"), 0, "yaml data"),
    ],
    "ssrf": [
        (re.compile(r"^requests\.(get|post|put|delete|patch|head|options|request)$"), 0, "URL"),
        (re.compile(r"^urlopen$"), 0, "URL"),
        (re.compile(r"^urlretrieve$"), 0, "URL"),
        (re.compile(r"^httpx\.(get|post|put|delete|patch|head|options|request|Client)$"), 0, "URL"),
        (re.compile(r"^aiohttp\.(get|post|put|delete|patch|head|options|request)$"), 0, "URL"),
    ],
    "sqli": [
        (re.compile(r"execute$"), 0, "SQL query"),
        (re.compile(r"executemany$"), 0, "SQL query"),
        (re.compile(r"executescript$"), 0, "SQL query"),
    ],
    "afo": [
        (re.compile(r"^open$"), 0, "file path (write mode)"),
        (re.compile(r"^shutil\.(copy|copy2|move|chown)$"), 0, "file path"),
        (re.compile(r"^os\.remove$"), 0, "file path"),
        (re.compile(r"^os\.unlink$"), 0, "file path"),
        (re.compile(r"^os\.rmdir$"), 0, "directory path"),
        (re.compile(r"^tarfile\.extractall$"), 0, "destination path"),
        (re.compile(r"^zipfile\.extractall$"), 0, "destination path"),
    ],
    "redos": [
        (re.compile(r"^re\.match$"), 0, "regex pattern"),
        (re.compile(r"^re\.search$"), 0, "regex pattern"),
        (re.compile(r"^re\.sub$"), 0, "regex pattern"),
        (re.compile(r"^re\.compile$"), 0, "regex pattern"),
        (re.compile(r"^re\.findall$"), 0, "regex pattern"),
        (re.compile(r"^re\.fullmatch$"), 0, "regex pattern"),
        (re.compile(r"^re\.split$"), 0, "regex pattern"),
    ],
    "idor": [
        (re.compile(r"^\.get$"), 0, "lookup key"),
        (re.compile(r"^\.filter$"), 0, "filter argument"),
        (re.compile(r"get_object_or_404$"), 0, "lookup parameter"),
    ],
    # -- Java sink arg specs --
    "java_rce": [
        (re.compile(r"Runtime\.exec$"), 0, "command string"),
        (re.compile(r"Runtime\.getRuntime\.exec$"), 0, "command string"),
        (re.compile(r"ProcessBuilder$"), 0, "command list"),
        (re.compile(r"ScriptEngine\.eval$"), 0, "script code"),
        (re.compile(r"SpelExpressionParser\.parseExpression$"), 0, "expression"),
        (re.compile(r"Ognl\.getValue$"), 0, "expression"),
        (re.compile(r"MVEL\.eval$"), 0, "expression"),
        (re.compile(r"ELProcessor\.eval$"), 0, "expression"),
        (re.compile(r"InitialContext\.lookup$"), 0, "JNDI name"),
        (re.compile(r"Yaml\.load$"), 0, "YAML data"),
        (re.compile(r"XStream\.fromXML$"), 0, "XML data"),
    ],
    "java_lfi": [
        (re.compile(r"^FileInputStream$"), 0, "file path"),
        (re.compile(r"^FileReader$"), 0, "file path"),
        (re.compile(r"Files\.readAllBytes$"), 0, "file path"),
        (re.compile(r"Files\.readString$"), 0, "file path"),
        (re.compile(r"FileUtils\.readFileToString$"), 0, "file path"),
    ],
    "java_ssrf": [
        (re.compile(r"URL\.openConnection$"), 0, "URL"),
        (re.compile(r"URL\.openStream$"), 0, "URL"),
        (re.compile(r"RestTemplate\.(get|post|exchange)ForObject$"), 0, "URL"),
        (re.compile(r"OkHttpClient\.newCall$"), 0, "request"),
    ],
    "java_sqli": [
        (re.compile(r"Statement\.executeQuery$"), 0, "SQL query"),
        (re.compile(r"Statement\.execute$"), 0, "SQL query"),
        (re.compile(r"JdbcTemplate\.query$"), 0, "SQL query"),
        (re.compile(r"Session\.createSQLQuery$"), 0, "SQL query"),
    ],
    "java_xxe": [
        (re.compile(r"DocumentBuilder\.parse$"), 0, "XML document"),
        (re.compile(r"SAXParser\.parse$"), 0, "XML document"),
        (re.compile(r"SAXReader\.read$"), 0, "XML document"),
        (re.compile(r"SAXBuilder\.build$"), 0, "XML document"),
    ],
    "java_afo": [
        (re.compile(r"^FileOutputStream$"), 0, "file path"),
        (re.compile(r"^FileWriter$"), 0, "file path"),
        (re.compile(r"Files\.write$"), 0, "file path"),
        (re.compile(r"Files\.copy$"), 0, "source/target paths"),
    ],
    "java_ssti": [
        (re.compile(r"Template\.process$"), 0, "template data"),
        (re.compile(r"Velocity\.evaluate$"), 0, "template"),
        (re.compile(r"VelocityEngine\.evaluate$"), 0, "template"),
    ],
}
_HTTP_INPUT_PATTERNS = re.compile(
    r"\b(request|flask\.request|self\.request|ctx\.request)\."
    r"(args|form|data|json|headers|cookies|params|query_params|"
    r"body|stream|files|values|get_json|query_string)"
)
_CONFIG_PATTERNS = re.compile(
    r"\b(os\.environ|os\.getenv|env|settings|config|app\.config|"
    r"django\.conf|from_conf|__config__)"
)
_SANITIZE_PATTERNS = [
    (re.compile(r"re\.(match|search|fullmatch)\s*\("), "regex validation"),
    (re.compile(r"\.startswith\s*\("), "prefix check"),
    (re.compile(r"\.endswith\s*\("), "suffix check"),
    (re.compile(r"len\s*\("), "length check"),
    (re.compile(r"\.replace\s*\("), "character filtering"),
    (re.compile(r"\.strip\s*\("), "strip"),
    (re.compile(r"sanitize|sanitise|validate|cleanse|purify"), "named sanitizer"),
    (re.compile(r"os\.path\.realpath|os\.path\.abspath"), "path normalization"),
    (re.compile(r"escape\("), "escaping"),
]


@dataclass
class EvidenceMatch:
    """A single piece of code-level evidence."""
    pattern: str
    line_number: int | None
    line_content: str
    function_name: str | None = None


@dataclass
class SinkCallAnalysis:
    """AST-level analysis of a single sink call site."""
    sink_function: str          # e.g. "open", "requests.get"
    call_line: int
    call_source: str
    dangerous_arg: str          # the expression passed as the dangerous arg
    arg_classification: str     # HARDCODED | HTTP_INPUT | CONFIG_DRIVEN | FUNCTION_PARAM | UNTRACEABLE
    arg_evidence: str           # why classified that way
    param_role: str             # e.g. "file path", "SQL query"
    guards: list[str] = field(default_factory=list)
    confidence_delta: int = 0   # net adjustment from this analysis


@dataclass
class EvidenceResult:
    """Result of evidence checking + analysis."""
    evidence_found: bool = False
    matches: list[EvidenceMatch] = field(default_factory=list)
    sink_analyses: list[SinkCallAnalysis] = field(default_factory=list)
    poc: str = ""
    analysis: str = ""
    confidence_delta: int = 0
    """Net confidence adjustment from static analysis. Applied by caller."""


# ---------------------------------------------------------------------------
# Sink argument analysis (Phase 1b)
# ---------------------------------------------------------------------------


def _extract_functions(code_block: str) -> list[tuple[str, str]]:
    """Split code_block by ``# ── Call Chain ──`` markers.

    Returns list of ``(header_label, function_body)`` tuples.
    The last entry is typically the sink function.
    """
    sections = re.split(
        r"# ── Call Chain \[(\d+)\] \[(\w+)\] → (.+?) \(.*?\) ──",
        code_block,
    )
    # The re.split with groups produces interleaved results:
    # [0] = text before first match
    # [1] = group 1 (index), [2] = group 2 (direction), [3] = group 3 (name)
    # [4] = text after first match, ...
    # We want (name, text_after)
    if len(sections) < 4:
        # No call chain markers — treat whole block as one function
        return [("(unknown)", code_block.strip())]

    functions: list[tuple[str, str]] = []
    for i in range(1, len(sections) - 1, 4):
        if i + 3 >= len(sections):
            break
        name = sections[i + 2].strip()
        body = sections[i + 3].strip()
        functions.append((name, body))
    return functions


def _classify_arg_ast(node: ast.AST, func_body: str) -> tuple[str, str]:
    """Classify an argument AST node into a source category.

    Returns ``(classification, evidence)``.
    """
    # ── String literal / constant → HARDCODED ──
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        val = node.value
        if len(val) > 50:
            val = val[:50] + "..."
        return ("HARDCODED", f"string literal: {val!r}")

    if isinstance(node, ast.Constant) and node.value is None:
        return ("HARDCODED", "None constant")

    # ── f-string → can contain interpolated values; treat as UNTRACEABLE ──
    if isinstance(node, ast.JoinedStr):
        return ("UNTRACEABLE", "f-string (may contain interpolated values)")

    # ── Config patterns in expression ──
    expr_str = ast.unparse(node) if hasattr(ast, "unparse") else ""
    if not expr_str:
        return ("UNTRACEABLE", "cannot unparse AST node")

    if _CONFIG_PATTERNS.search(expr_str):
        return ("CONFIG_DRIVEN", f"config/env expression: {expr_str[:80]}")

    if _HTTP_INPUT_PATTERNS.search(expr_str):
        return ("HTTP_INPUT", f"HTTP request attribute: {expr_str[:80]}")

    # ── Simple variable name → trace backwards in function body ──
    if isinstance(node, ast.Name):
        return _trace_variable(node.id, func_body)

    # ── Attribute access (e.g. obj.attr) → trace if config-like ──
    if isinstance(node, ast.Attribute):
        attr_str = ast.unparse(node)
        if "config" in attr_str.lower() or "setting" in attr_str.lower() or "env" in attr_str.lower():
            return ("CONFIG_DRIVEN", f"config-like attribute: {attr_str[:80]}")
        if "request" in attr_str.lower():
            return ("HTTP_INPUT", f"request attribute chain: {attr_str[:80]}")
        return ("UNTRACEABLE", f"attribute access: {attr_str[:60]}")

    # ── Function call result ──
    if isinstance(node, ast.Call):
        func_str = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
        # If calling request.get_json() or similar HTTP input methods
        if "request" in func_str.lower() or "get_json" in func_str.lower():
            return ("HTTP_INPUT", f"HTTP input method: {func_str[:60]}")
        if "getenv" in func_str or "environ" in func_str:
            return ("CONFIG_DRIVEN", f"env method: {func_str[:60]}")
        if "config" in func_str.lower() or "settings" in func_str.lower():
            return ("CONFIG_DRIVEN", f"config method: {func_str[:60]}")
        return ("UNTRACEABLE", f"function call result: {func_str[:60]}")

    # ── Binary op (e.g. string concatenation) ──
    if isinstance(node, ast.BinOp):
        # Try tracing both sides; if either side is a variable trace it
        for side in (node.left, node.right):
            if isinstance(side, ast.Name):
                cls, ev = _trace_variable(side.id, func_body)
                if cls != "UNTRACEABLE":
                    return (cls, f"binop left/right: {ev}")
            elif isinstance(side, ast.Constant) and isinstance(side.value, str):
                pass  # constant side is fine
            else:
                # Try unparsing the side for config/HTTP patterns
                side_str = ast.unparse(side) if hasattr(ast, "unparse") else ""
                if _CONFIG_PATTERNS.search(side_str):
                    return ("CONFIG_DRIVEN", f"binop side from config: {side_str[:60]}")
                if _HTTP_INPUT_PATTERNS.search(side_str):
                    return ("HTTP_INPUT", f"binop side from request: {side_str[:60]}")
        # All sides are constant or untraceable
        return ("UNTRACEABLE", "binary operation")

    # ── List/Tuple literal (e.g. ['ls', '-la']) ──
    if isinstance(node, (ast.List, ast.Tuple)):
        all_const = all(isinstance(elt, ast.Constant) for elt in node.elts)
        if all_const:
            return ("HARDCODED", f"{'list' if isinstance(node, ast.List) else 'tuple'} literal with {len(node.elts)} constant(s)")
        return ("UNTRACEABLE", f"{'list' if isinstance(node, ast.List) else 'tuple'} with non-constant elements")

    # ── Compare (e.g. x == "value") — used as argument? rare ──
    if isinstance(node, ast.Compare):
        return ("UNTRACEABLE", "comparison expression")

    # ── IfExp (ternary) ──
    if isinstance(node, ast.IfExp):
        return ("UNTRACEABLE", "ternary expression")

    return ("UNTRACEABLE", f"unsupported AST node: {type(node).__name__}")


def _trace_variable(var_name: str, func_body: str) -> tuple[str, str]:
    """Trace a variable name backwards in function body to find origin.

    Simple approach: search for assignment statements in the function body
    that assign to *var_name*.
    """
    try:
        tree = ast.parse(func_body)
    except SyntaxError:
        return ("UNTRACEABLE", f"cannot parse function body to trace {var_name}")

    for node in ast.walk(tree):
        # Direct assignment: x = <value>
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    return _classify_arg_ast(node.value, func_body)

        # Annotated assignment: x: Type = <value>
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == var_name and node.value:
                return _classify_arg_ast(node.value, func_body)

        # Augmented assignment: x += <value>
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == var_name:
                return ("UNTRACEABLE", f"augmented assignment (prior value unknown)")

        # For loop: for x in <iterable>
        if isinstance(node, ast.For):
            if isinstance(node.target, ast.Name) and node.target.id == var_name:
                return ("UNTRACEABLE", f"loop variable from {ast.unparse(node.iter)[:60] if hasattr(ast, 'unparse') else 'iterable'}")

    # Try function parameter — if var_name matches a parameter name,
    # classify as FUNCTION_PARAM
    try:
        tree = ast.parse(func_body)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args:
                    if arg.arg == var_name:
                        return ("FUNCTION_PARAM", f"function parameter: {var_name}")
                # Check *args and **kwargs too
                if node.args.vararg and node.args.vararg.arg == var_name:
                    return ("FUNCTION_PARAM", f"*args parameter")
                if node.args.kwarg and node.args.kwarg.arg == var_name:
                    return ("FUNCTION_PARAM", f"**kwargs parameter")
    except SyntaxError:
        pass

    return ("UNTRACEABLE", f"cannot trace variable: {var_name}")


def _detect_guards(func_lines: list[str], sink_line: int) -> list[str]:
    """Detect guard/validation patterns between function start and sink call.

    Scans lines before the sink line for validation patterns.
    """
    guards: list[str] = []
    for lineno, line in enumerate(func_lines, 1):
        if lineno >= sink_line:
            break
        for pattern, label in _SANITIZE_PATTERNS:
            if pattern.search(line) and label not in guards:
                guards.append(label)
                if len(guards) >= 4:
                    return guards
    return guards


def _find_sink_call_source(func_lines: list[str], call_line: int) -> str:
    """Extract the full source line of a sink call, handling multi-line calls."""
    if call_line <= 0 or call_line > len(func_lines):
        return "(unknown)"
    return func_lines[call_line - 1].strip()


# ---------------------------------------------------------------------------
# Phase 4: Cross-chain guard detection + param propagation
# ---------------------------------------------------------------------------


def detect_chain_guards(
    functions: list[tuple[str, str]],
    sink_index: int = -1,
) -> list[str]:
    """Scan all functions in a call chain for guard/validation patterns.

    For intermediate functions, scans the ENTIRE function body.
    For the sink function, skips body-level guards (already caught by
    ``_detect_guards`` at the per-call-site level).

    Returns unique guard descriptions with ``func_name: label`` prefix.
    """
    guards: list[str] = []
    if sink_index < 0:
        sink_index = len(functions) - 1

    for i, (func_name, func_body) in enumerate(functions):
        if i == sink_index:
            continue  # sink guards already handled per-site
        for line in func_body.split("\n"):
            for pattern, label in _SANITIZE_PATTERNS:
                if pattern.search(line):
                    guard_key = f"{func_name}: {label}"
                    if guard_key not in guards:
                        guards.append(guard_key)
        if len(guards) >= 8:
            break
    return guards


def _find_param_position(func_body: str, param_name: str) -> int | None:
    """Find the positional index of a named parameter in a function."""
    try:
        tree = ast.parse(func_body)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for i, arg in enumerate(node.args.args):
                    if arg.arg == param_name:
                        return i
    except SyntaxError:
        pass
    return None


def propagate_param_classification(
    result: SinkCallAnalysis,
    functions: list[tuple[str, str]],
) -> SinkCallAnalysis:
    """Walk backward through the call chain for FUNCTION_PARAM classification.

    If a sink argument is a function parameter (FUNCTION_PARAM), walk backward
    through each caller to find what expression is actually passed at that
    parameter position.  Resolves param → param chains to a concrete source.

    Returns the (possibly updated) ``SinkCallAnalysis``.
    """
    if result.arg_classification != "FUNCTION_PARAM":
        return result

    if len(functions) < 2:
        return result

    param_name = result.dangerous_arg

    # Walk backward from sink (last) to entry (first)
    for chain_idx in range(len(functions) - 1, 0, -1):
        callee_name, callee_body = functions[chain_idx]
        caller_name, caller_body = functions[chain_idx - 1]

        # Find the parameter position in the callee
        param_idx = _find_param_position(callee_body, param_name)
        if param_idx is None:
            break

        # Parse caller body to find the call to callee
        try:
            caller_tree = ast.parse(caller_body)
        except SyntaxError:
            break

        found_call = False
        for node in ast.walk(caller_tree):
            if not isinstance(node, ast.Call):
                continue
            call_str = _get_call_signature(node)
            if call_str == callee_name:
                args = _get_call_args(node)
                if param_idx < len(args):
                    arg_node = args[param_idx]
                    classification, evidence = _classify_arg_ast(arg_node, caller_body)
                    if classification == "FUNCTION_PARAM" and isinstance(arg_node, ast.Name):
                        param_name = arg_node.id
                        found_call = True
                    else:
                        result.arg_classification = classification
                        result.arg_evidence = f"propagated from {callee_name}: {evidence}"
                        return result
                break  # only first matching call

        if not found_call:
            break

    # Still FUNCTION_PARAM at entry — check for HTTP context
    if functions:
        entry_name, entry_body = functions[0][0], functions[0][1]
        if _HTTP_INPUT_PATTERNS.search(entry_body):
            result.arg_classification = "HTTP_INPUT"
            result.arg_evidence = f"propagated from entry {entry_name} (HTTP context in body)"
        else:
            result.arg_evidence = f"unresolved after walking chain to entry {entry_name}"

    return result


# ---------------------------------------------------------------------------
# Phase 5: Deterministic taint_path verification
# ---------------------------------------------------------------------------


def verify_taint_path_against_evidence(
    logic_analysis: str,
    cross_file_flow: str,
    cpg_data_flow_evidence: str,
) -> tuple[int, str]:
    """Cross-validate Logic Agent analysis against deterministic evidence.

    Checks whether the LLM's claimed taint path matches the statically
    determined data flow annotations.

    Returns (confidence_delta, explanation):
        +1 — strong agreement with both evidence sources
         0 — partial agreement or no evidence to check
        -1 — contradicts one evidence source
        -2 — contradicts both evidence sources
    """
    if not cross_file_flow and not cpg_data_flow_evidence:
        return (0, "no deterministic data flow evidence to verify against")

    if not logic_analysis:
        return (0, "no logic analysis to verify")

    agreement = 0
    reasons: list[str] = []

    # ── Check cross_file_flow ──
    if cross_file_flow:
        flow_funcs = set()
        for f in re.findall(r'(\w+)\s*\(', cross_file_flow):
            if f not in ("param", "L"):  # filter CPG format noise
                flow_funcs.add(f)

        matched = sum(1 for f in flow_funcs if f in logic_analysis)
        if flow_funcs:
            ratio = matched / len(flow_funcs)
            if ratio >= 0.8:
                agreement += 1
                reasons.append("cross_file_flow chain confirmed in analysis")
            elif ratio >= 0.3:
                reasons.append(f"cross_file_flow partially reflected ({matched}/{len(flow_funcs)} funcs)")
            else:
                agreement -= 1
                reasons.append("cross_file_flow chain NOT reflected in analysis")

    # ── Check CPG data flow evidence ──
    if cpg_data_flow_evidence:
        cpg_keywords = re.findall(r'param:(\w+)', cpg_data_flow_evidence)
        if cpg_keywords:
            all_found = all(kw in logic_analysis for kw in cpg_keywords)
            if all_found:
                agreement += 1
                reasons.append("CPG param trace confirmed in analysis")
            else:
                agreement -= 1
                reasons.append("CPG param trace NOT reflected in analysis")

    delta = max(-2, min(1, agreement))
    return (delta, "; ".join(reasons) if reasons else "no relevant evidence")


def analyze_sink_arguments(code_block: str, vuln_type: str) -> list[SinkCallAnalysis]:
    """AST-based analysis of sink call arguments.

    Phase 1b: parses the sink function's body, finds matching sink calls,
    and classifies their dangerous arguments.
    """
    spec = SINK_ARG_SPEC.get(vuln_type.lower())
    if not spec:
        return []

    functions = _extract_functions(code_block)
    # Focus on the sink function (last entry)
    if not functions:
        return []

    results: list[SinkCallAnalysis] = []
    seen_signatures: set[str] = set()

    for func_name, func_body in functions:
        try:
            tree = ast.parse(func_body)
        except SyntaxError:
            continue

        func_lines = func_body.split("\n")

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Build the call signature string
            call_str = _get_call_signature(node)
            if not call_str:
                continue

            # Check against spec patterns
            for sink_pat, arg_idx, param_role in spec:
                if sink_pat.search(call_str):
                    # Deduplicate
                    dedup_key = f"{call_str}:{node.lineno}"
                    if dedup_key in seen_signatures:
                        continue
                    seen_signatures.add(dedup_key)

                    # Extract the dangerous argument
                    args = _get_call_args(node)
                    if arg_idx >= len(args):
                        continue

                    dangerous_arg_node = args[arg_idx]
                    arg_class, arg_evidence = _classify_arg_ast(dangerous_arg_node, func_body)

                    # Guard detection
                    guards = _detect_guards(func_lines, node.lineno)

                    # Calculate confidence delta
                    delta = _calc_confidence_delta(arg_class, len(guards))

                    call_source = _find_sink_call_source(func_lines, node.lineno)

                    results.append(SinkCallAnalysis(
                        sink_function=call_str,
                        call_line=node.lineno,
                        call_source=call_source,
                        dangerous_arg=ast.unparse(dangerous_arg_node) if hasattr(ast, "unparse") else "",
                        arg_classification=arg_class,
                        arg_evidence=arg_evidence,
                        param_role=param_role,
                        guards=guards,
                        confidence_delta=delta,
                    ))
                    break  # one spec match per call

    # Phase 4: Cross-chain guard detection + argument propagation
    if len(functions) > 1:
        chain_guards = detect_chain_guards(functions)
        if chain_guards:
            for analysis in results:
                for g in chain_guards:
                    if g not in analysis.guards:
                        analysis.guards.append(g)

        for i, analysis in enumerate(results):
            results[i] = propagate_param_classification(analysis, functions)

        # Recalculate confidence delta after propagation (classification may
        # have changed from FUNCTION_PARAM to HTTP_INPUT/HARDCODED/etc.)
        for i, analysis in enumerate(results):
            results[i].confidence_delta = _calc_confidence_delta(
                analysis.arg_classification,
                len(analysis.guards),
            )

    return results


def _get_call_signature(node: ast.Call) -> str:
    """Build a call signature string like ``open`` or ``requests.get``."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        # Handle chained attributes like self.request.args.get
        try:
            return ast.unparse(node.func) if hasattr(ast, "unparse") else node.func.attr
        except Exception:
            return node.func.attr
    return ""


def _get_call_args(node: ast.Call) -> list[ast.AST]:
    """Get positional arguments of a call."""
    return list(node.args)


def _calc_confidence_delta(arg_class: str, guard_count: int) -> int:
    """Calculate net confidence adjustment from argument analysis.

    Returns a delta (-2 to +2) added to the finding's confidence.
    """
    delta = 0
    if arg_class == "HARDCODED":
        delta -= 1
    elif arg_class == "CONFIG_DRIVEN":
        delta -= 1
    elif arg_class == "HTTP_INPUT":
        delta += 1
    elif arg_class == "FUNCTION_PARAM":
        delta -= 0  # neutral — need caller context
    # Guards reduce confidence (the sink is protected)
    if guard_count >= 2:
        delta -= 1
    return max(-2, min(2, delta))


# ---------------------------------------------------------------------------
# Pattern scan (Phase 1)
# ---------------------------------------------------------------------------


def scan_evidence(code_block: str, vuln_type: str) -> list[EvidenceMatch]:
    """Phase 1: pattern-based scan of source code.

    Returns all matches — empty list = no evidence.
    """
    patterns = EVIDENCE_PATTERNS.get(vuln_type.lower(), [])
    if not patterns:
        return []

    matches: list[EvidenceMatch] = []
    lines = code_block.split("\n")
    for lineno, line in enumerate(lines, 1):
        for pat in patterns:
            if pat.search(line):
                pat_str = pat.pattern[:60]
                matches.append(EvidenceMatch(
                    pattern=pat_str,
                    line_number=lineno,
                    line_content=line.strip()[:120],
                ))
    return matches


# ---------------------------------------------------------------------------
# Blackboard context builder
# ---------------------------------------------------------------------------


def build_blackboard_context(
    blackboard: BlackboardAggregator,
    nodes: list[dict[str, Any]],
) -> str:
    """Build a context block from blackboard cached intents for these path functions."""
    blocks: list[str] = []
    for node in nodes:
        func_name = node.get("function_name", "")
        file_path = node.get("file_path", "")
        if not func_name:
            continue
        intent = blackboard.get_intent(func_name, file_path)
        if intent and intent.intent:
            blocks.append(
                f"[{func_name}] intent: {intent.intent}\n"
                f"  inputs: {intent.inputs}\n"
                f"  outputs: {intent.outputs}\n"
                f"  key_logic: {intent.key_logic}"
            )
    if not blocks:
        return ""
    return "[Blackboard Intent Context]\n" + "\n\n".join(blocks)


# ---------------------------------------------------------------------------
# LLM deep analysis prompt (Phase 2)
# ---------------------------------------------------------------------------

EVIDENCE_PROMPT = """You are verifying whether a claimed vulnerability has actual code-level evidence.

Logic Agent Claim
----
Vulnerability Type: {vuln_type}
Analysis: {analysis}
Claimed Contradiction: {contradiction_desc}
Suggested PoC: {poc_claim}

Code Context
----
{code_block}

{blackboard_context}

Static Analysis Results (sink argument classification)
----
{sink_analysis_text}

Your job: Trace the actual data flow in the code above and determine if the
claimed vulnerability can actually be exploited. Be skeptical — the Logic Agent
may have hallucinated a code path that doesn't exist.

The static analysis above shows what our AST-level argument classifier found
about the dangerous function call arguments. Use this as a hint, but verify
by reading the actual code.

If the vulnerability IS confirmed:
- Explain step-by-step how data flows from source to sink (cite exact lines)
- Write a working, concrete PoC
- Note any preconditions or limitations

If NOT confirmed:
- Explain exactly why (e.g., "function reads request body not filesystem",
  "regex pattern is linear, no backtracking possible")

Output:
```json
{{
  "confirmed": true/false,
  "confidence": 0-10,
  "evidence_lines": ["web_request.py:655: chunk = await self._payload.readany()", ...],
  "analysis": "Step-by-step data flow analysis...",
  "poc": "If confirmed, the concrete PoC. If not, empty string.",
  "why_rejected": "If not confirmed, explanation."
}}
```
"""


def _format_sink_analyses(analyses: list[SinkCallAnalysis]) -> str:
    """Format sink analyses for prompt injection."""
    if not analyses:
        return "(no static sink analysis available)"
    lines: list[str] = []
    for sa in analyses:
        guard_text = f" | guards: {', '.join(sa.guards)}" if sa.guards else ""
        lines.append(
            f"- {sa.sink_function}:{sa.call_line} → arg={sa.dangerous_arg!r}\n"
            f"  classification: {sa.arg_classification} ({sa.arg_evidence}){guard_text}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Evidence Checker
# ---------------------------------------------------------------------------


class EvidenceChecker:
    """Code-level evidence verification + deep analysis.

    Phases:
      1.  Pattern scan (no LLM)
      1b. AST-based sink argument analysis (no LLM)
      1c. Guard detection (no LLM)
      2.  LLM deep analysis + PoC (only if Phase 1 finds evidence)
      3.  Record to blackboard
    """

    def __init__(
        self,
        llm_call_fn: Callable[[str], str | None] | None = None,
        blackboard: BlackboardAggregator | None = None,
    ) -> None:
        self._llm_call = llm_call_fn
        self._blackboard = blackboard

    def run(
        self,
        logic_result: AgentPhaseResult,
        code_block: str,
        nodes: list[dict[str, Any]],
        cross_file_flow: str = "",
        cpg_data_flow_evidence: str = "",
    ) -> EvidenceResult:
        """Run evidence checking on a Logic Agent finding.

        Phase 1: pattern scan (no LLM cost).
        Phase 1b+1c: AST sink argument analysis + guard detection (no LLM).
        Phase 2: LLM deep analysis + PoC (only if Phase 1 finds evidence).
        Phase 3: record to blackboard.
        Phase 4: cross-chain guard detection + param propagation (injected into
                 ``analyze_sink_arguments``).
        Phase 5: deterministic taint_path verification against
                 ``cross_file_flow`` and ``cpg_data_flow_evidence``.
        """
        # Phase 1: Pattern scan
        matches = scan_evidence(code_block, logic_result.vuln_type)
        if not matches:
            logger.info(
                "EvidenceChecker: no code-level evidence for %s (%s)",
                logic_result.path_id, logic_result.vuln_type,
            )
            return EvidenceResult(evidence_found=False)

        # Phase 1b+1c: AST sink argument analysis + guard detection
        sink_analyses = analyze_sink_arguments(code_block, logic_result.vuln_type)
        total_delta = sum(sa.confidence_delta for sa in sink_analyses)
        total_delta = max(-2, min(2, total_delta))

        # Phase 5: deterministic taint_path verification
        if cross_file_flow or cpg_data_flow_evidence:
            verify_delta, verify_reason = verify_taint_path_against_evidence(
                logic_result.analysis or "",
                cross_file_flow,
                cpg_data_flow_evidence,
            )
            total_delta = max(-2, min(2, total_delta + verify_delta))
            if verify_delta:
                logger.info(
                    "EvidenceChecker: taint_path verify=%d for %s (%s)",
                    verify_delta, logic_result.path_id, verify_reason,
                )

        logger.info(
            "EvidenceChecker: %d evidence matches, %d sink analyses (delta=%d) for %s",
            len(matches), len(sink_analyses), total_delta, logic_result.path_id,
        )

        if not self._llm_call:
            return EvidenceResult(
                evidence_found=True,
                matches=matches,
                sink_analyses=sink_analyses,
                confidence_delta=total_delta,
            )

        # Phase 2: LLM deep analysis with code + blackboard + sink analysis context
        contradiction_desc = ""
        poc_claim = ""
        if logic_result.contradictions:
            c = logic_result.contradictions[0]
            contradiction_desc = c.get("contradiction_type", "") + ": " + c.get("actual", "")
            poc_claim = c.get("bypass_poc", "")

        bb_context = ""
        if self._blackboard and nodes:
            bb_context = build_blackboard_context(self._blackboard, nodes)

        sink_analysis_text = _format_sink_analyses(sink_analyses)

        prompt = EVIDENCE_PROMPT.format(
            vuln_type=logic_result.vuln_type.upper(),
            analysis=logic_result.analysis or "(no analysis)",
            contradiction_desc=contradiction_desc,
            poc_claim=poc_claim,
            code_block=code_block or "(code not loaded)",
            blackboard_context=bb_context or "(no prior context)",
            sink_analysis_text=sink_analysis_text,
        )

        response = self._llm_call(prompt)

        evidence_result = EvidenceResult(
            evidence_found=True,
            matches=matches,
            sink_analyses=sink_analyses,
            confidence_delta=total_delta,
        )

        if response:
            import json
            try:
                data = json.loads(response)
            except json.JSONDecodeError:
                # Try to extract JSON from code fence
                m = re.search(r"```(?:json)?\s*\n(.*?)\n```", response, re.DOTALL)
                if m:
                    try:
                        data = json.loads(m.group(1))
                    except json.JSONDecodeError:
                        data = {"confirmed": False, "analysis": "Failed to parse response"}
                else:
                    data = {"confirmed": True, "analysis": response[:500]}

            if data.get("confirmed", False):
                evidence_result.poc = data.get("poc", "")
                evidence_result.analysis = data.get("analysis", "")
            else:
                evidence_result.evidence_found = False
                evidence_result.analysis = data.get("why_rejected", data.get("analysis", ""))

        # Phase 3: Record to blackboard
        if self._blackboard:
            status = "confirmed" if evidence_result.evidence_found else "rejected"
            delta_note = f" [static_delta={total_delta}]" if total_delta else ""
            self._blackboard.record_knowledge(
                f"evidence:{logic_result.path_id}",
                f"[{status}]{delta_note} {evidence_result.analysis[:200]}"
                + (f"\nPoC: {evidence_result.poc[:300]}" if evidence_result.poc else ""),
                source_path_id=logic_result.path_id,
            )

        return evidence_result
