"""SAST Phase B — Directed Call-Chain Summarizer.

Folds multi-step call chains into a one-page "logic dossier" so the LLM
doesn't have to manually crawl find_callers/find_callees.

Usage::

    from agies.engine.sast.pathfinder import CallChainAnalyzer

    finder = CallChainAnalyzer(index)
    print(finder.analyze("execute_query", entry="handle_login"))
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Noise functions — calls that add no security-relevant logic
# ---------------------------------------------------------------------------

NOISE_FUNCTIONS: frozenset[str] = frozenset({
    # Python / general
    "print", "pprint", "printf", "echo", "write",
    # Logging
    "logging.info", "logging.debug", "logging.warning", "logging.error",
    "logging.critical", "logging.exception", "logging.log",
    "log.info", "log.debug", "log.warning", "log.error", "log.critical",
    "logger.info", "logger.debug", "logger.warning", "logger.error",
    "logger.critical",
    # Java
    "system.out.println", "system.out.print", "system.out.printf",
    "system.err.println", "system.err.print", "system.err.printf",
    # JavaScript / TypeScript
    "console.log", "console.info", "console.debug", "console.warn",
    "console.error", "console.trace", "console.dir",
})

_LOGGER_PREFIXES: frozenset[str] = frozenset({"log", "logger", "logging"})
"""Recognised logger variable names — only these get suffix-based matching."""

_LOG_LEVELS: frozenset[str] = frozenset({
    "info", "debug", "warn", "warning", "error", "critical",
    "exception", "trace", "log",
})


def _is_noise_call(call_name: str) -> bool:
    """Return True if *call_name* is a noise/logging function.

    Matches:
    - Exact names in NOISE_FUNCTIONS (print, console.log, System.out.println, …)
    - ``<log|logger|logging>.<level>()`` patterns, e.g. ``logger.info()``
    """
    name = call_name.strip().lower()
    if name in NOISE_FUNCTIONS:
        return True
    parts = name.rsplit(".", 1)
    if len(parts) == 2 and parts[0] in _LOGGER_PREFIXES:
        if parts[1] in _LOG_LEVELS:
            return True
    return False


# ---------------------------------------------------------------------------
# Sanitizer / Auth-gate patterns (substring matching, lowercased)
# ---------------------------------------------------------------------------

_SANITIZER_TERMS: list[str] = [
    "escape", "sanitize", "sanitise", "encode", "validate",
    "clean", "strip", "purify", "escape_string",
    "html.escape", "htmlentities", "strip_tags",
    "filter_var", "filter_input",
    "quote", "quote_plus", "urlencode",
]

_AUTH_GATE_TERMS: list[str] = [
    "is_admin", "is_authenticated", "is_logged_in",
    "has_role", "has_permission", "has_access",
    "check_auth", "authorize", "login_required",
    "authenticate", "require_auth", "ensure_authenticated",
    "verify_user", "verify_session", "validate_session",
    "check_role", "check_permission",
    "verify_jwt", "verify_token", "validate_token",
    "require_login", "require_admin",
]


def _has_sanitizer(text: str) -> bool:
    t = text.lower()
    for term in _SANITIZER_TERMS:
        if term in t:
            return True
    return False


def _has_auth_gate(text: str) -> bool:
    t = text.lower()
    for term in _AUTH_GATE_TERMS:
        if term in t:
            return True
    return False


# ---------------------------------------------------------------------------
# Tree-sitter logic extraction queries (per language)
# ---------------------------------------------------------------------------

# Python: if, calls (direct + attribute), returns
PY_LOG_QUERY = """
(if_statement condition: (_) @if.cond) @if
(call function: (identifier) @call.name arguments: (_)) @call
(call function: (attribute attribute: (identifier) @call.name) arguments: (_)) @call
(return_statement (_)? @return.value) @return
"""

# Java: if, method calls, returns
JAVA_LOG_QUERY = """
(if_statement condition: (_) @if.cond) @if
(method_invocation name: (identifier) @call.name arguments: (argument_list)) @call
(method_invocation object: (_) name: (identifier) @call.name arguments: (argument_list)) @call
(return_statement (_)? @return.value) @return
"""

# JS/TS: if, call expressions, returns
JS_LOG_QUERY = """
(if_statement condition: (_) @if.cond) @if
(call_expression function: (identifier) @call.name arguments: (arguments)) @call
(call_expression function: (member_expression property: (property_identifier) @call.name) arguments: (arguments)) @call
(return_statement (_)? @return.value) @return
"""

_LOG_QUERIES: dict[str, str] = {
    "python": PY_LOG_QUERY,
    "java": JAVA_LOG_QUERY,
    "javascript": JS_LOG_QUERY,
    "typescript": JS_LOG_QUERY,
}

# Function-finding queries (same as extractor.py)
_PY_FUNC_QUERY = """
(function_definition
  name: (identifier) @func.name
  body: (block) @func.body) @func.def
"""

_JAVA_FUNC_QUERY = """
(method_declaration
  name: (identifier) @func.name
  body: (block)? @func.body) @func.def
(constructor_declaration
  name: (identifier) @func.name
  body: (constructor_body)? @func.body) @func.def
"""

_JS_FUNC_QUERY = """
(function_declaration
  name: (identifier) @func.name
  body: (statement_block) @func.body) @func.def
(method_definition
  name: (property_identifier) @func.name
  body: (statement_block) @func.body) @func.def
"""

_FUNC_QUERIES: dict[str, str] = {
    "python": _PY_FUNC_QUERY,
    "java": _JAVA_FUNC_QUERY,
    "javascript": _JS_FUNC_QUERY,
    "typescript": _JS_FUNC_QUERY,
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PATHS: int = 5
"""Maximum number of distinct call paths to return."""
MAX_DEPTH: int = 12
"""Maximum call-chain depth (cutoff for ``nx.all_simple_paths``)."""


# ===================================================================
# CallChainAnalyzer
# ===================================================================


class CallChainAnalyzer:
    """Directed call-chain summarizer.

    Builds a forward call graph from a ``FunctionIndex``, finds all simple
    paths from *entry* → *sink*, and extracts a compact logic summary for
    each function on the path.
    """

    def __init__(self, index: Any, project_path: str = "") -> None:
        self._index = index
        self._project_path = project_path
        self._graph: Any = None  # nx.DiGraph — set on first use
        self._parsers: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, sink: str, entry: str = "", max_depth: int = 12) -> str:
        """Full pipeline: find paths + extract logic → one-page dossier.

        Parameters
        ----------
        sink:
            The function name at the end of the call chain (the vulnerable sink).
        entry:
            Optional entry-point function name.  If empty, finds all paths
            reaching *sink* from any caller.
        max_depth:
            Maximum call-chain depth.  Default 12.

        Returns
        -------
        str
            Human-readable "logic dossier" that the LLM can reason about.
        """
        import networkx as nx

        self._build_graph()
        paths = self._find_paths(sink, entry, max_depth=max_depth)

        if not paths:
            if entry:
                msg = f"no path found from '{entry}' → '{sink}'"
            else:
                msg = f"no paths found reaching '{sink}'"
            return f"CallChainAnalyzer: {msg}"

        lines: list[str] = []
        ep = f" from '{entry}'" if entry else ""
        lines.append(f"CallChainAnalyzer: {len(paths)} path(s) to '{sink}'{ep}\n")

        for i, path in enumerate(paths, 1):
            lines.append(f"── Path {i}: {' → '.join(path)} ──")
            for func_name in path:
                logic_bits = self._extract_function_logic(func_name)
                if logic_bits:
                    # Tag auth gates / sanitizers
                    tags = []
                    combined = " ".join(logic_bits)
                    if _has_sanitizer(combined):
                        tags.append("[Sanitized]")
                    if _has_auth_gate(combined):
                        tags.append("[Auth_Gate]")

                    summary = "; ".join(logic_bits[:6])  # max 6 items
                    tag_str = " " + " ".join(tags) if tags else ""
                    lines.append(f"  {func_name}: {summary}{tag_str}")
                else:
                    lines.append(f"  {func_name}")
            lines.append("")

        # Quick conclusion
        conclusion = self._conclude(paths)
        lines.append(f"Conclusion: {conclusion}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Graph building
    # ------------------------------------------------------------------

    def _build_graph(self) -> None:
        """Build forward call graph (caller → callee) from FunctionIndex.

        Noise functions are excluded from the graph so paths never
        traverse logging/print functions.
        """
        import networkx as nx

        G: Any = nx.DiGraph()
        if not self._index:
            self._graph = G
            return

        # Recover forward edges from the reverse call_graph
        # index.call_graph = {callee: {caller1, caller2, ...}}
        for callee, callers in getattr(self._index, "call_graph", {}).items():
            if _is_noise_call(callee):
                continue
            G.add_node(callee)
            for caller in callers:
                if _is_noise_call(caller):
                    continue
                G.add_node(caller)
                G.add_edge(caller, callee)

        self._graph = G

    # ------------------------------------------------------------------
    # Path finding
    # ------------------------------------------------------------------

    def _find_paths(
        self,
        sink: str,
        entry: str = "",
        max_paths: int = 5,
        max_depth: int = 12,
    ) -> list[list[str]]:
        """Find up to *max_paths* simple paths from *entry* → *sink*."""
        import networkx as nx

        G = self._graph
        if G is None:
            self._build_graph()
            G = self._graph

        if sink not in G:
            return []

        if entry:
            if entry not in G:
                return []
            try:
                paths = list(
                    nx.all_simple_paths(G, source=entry, target=sink, cutoff=max_depth)
                )
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return []
            return paths[:max_paths]

        # No entry: find shortest paths from any reachable node
        all_paths: list[list[str]] = []
        for node in G.nodes:
            if node == sink:
                continue
            try:
                for p in nx.all_simple_paths(G, source=node, target=sink, cutoff=max_depth):
                    all_paths.append(p)
                    if len(all_paths) >= max_paths * 3:
                        break
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if len(all_paths) >= max_paths * 3:
                break

        return sorted(all_paths, key=len)[:max_paths]

    # ------------------------------------------------------------------
    # Function logic extraction
    # ------------------------------------------------------------------

    def _extract_function_logic(self, func_name: str) -> list[str]:
        """Return a list of compact logic items for *func_name*.

        Tries tree-sitter extraction first, falls back to text-based scan.
        """
        funcs = self._index.lookup(func_name) if hasattr(self._index, "lookup") else []
        if not funcs:
            return []

        fn = funcs[0]
        source_file = self._index.sources.get(fn.file_path)
        if source_file is None:
            return self._extract_with_text(fn.body)

        # Try tree-sitter extraction
        lang_id = _detect_lang(fn.file_path)
        try:
            parts = self._extract_with_treesitter(
                source_file.source, fn.name, lang_id,
            )
            if parts:
                return parts
        except Exception:
            logger.debug("tree-sitter extraction failed for %s, falling back to text", func_name)

        # Fallback
        return self._extract_with_text(fn.body)

    def _extract_with_treesitter(
        self, source: str, func_name: str, lang_id: str,
    ) -> list[str]:
        """Extract logic items using tree-sitter within the function body."""
        from tree_sitter import Query, QueryCursor

        lang, parser = self._get_parser(lang_id)
        source_bytes = source.encode("utf-8")
        tree = parser.parse(source_bytes)

        # Step 1: find function body byte range
        func_query_str = _FUNC_QUERIES.get(lang_id)
        if not func_query_str:
            return []
        func_query = Query(lang, func_query_str)
        body_node = None
        for _, cap in QueryCursor(func_query).matches(tree.root_node):
            name_node = _first_node(cap, "func.name")
            if name_node is None:
                continue
            if name_node.text and name_node.text.decode("utf-8") == func_name:
                body_node = _first_node(cap, "func.body")
                break

        if body_node is None:
            return []

        # Step 2: run logic queries within body range
        logic_query_str = _LOG_QUERIES.get(lang_id)
        if not logic_query_str:
            return []
        logic_query = Query(lang, logic_query_str)
        cursor = QueryCursor(logic_query)
        cursor.set_byte_range(body_node.start_byte, body_node.end_byte)

        parts: list[str] = []
        seen_byte_ranges: set[tuple[int, int]] = set()
        for _, cap in cursor.matches(tree.root_node):
            # --- If condition ---
            cond_node = _first_node(cap, "if.cond")
            if cond_node and (cond_node.start_byte, cond_node.end_byte) not in seen_byte_ranges:
                seen_byte_ranges.add((cond_node.start_byte, cond_node.end_byte))
                cond_text = _node_text(cond_node, source_bytes)
                if cond_text:
                    # Shorten long conditions
                    if len(cond_text) > 80:
                        cond_text = cond_text[:77] + "..."
                    parts.append(f"if {cond_text}")

            # --- Call expression ---
            call_name_node = _first_node(cap, "call.name")
            if call_name_node and (call_name_node.start_byte, call_name_node.end_byte) not in seen_byte_ranges:
                seen_byte_ranges.add((call_name_node.start_byte, call_name_node.end_byte))
                cn = _node_text(call_name_node, source_bytes)
                if cn and not _is_noise_call(cn):
                    parts.append(f"calls {cn}()")

            # --- Return statement ---
            return_val_node = _first_node(cap, "return.value")
            if return_val_node and (return_val_node.start_byte, return_val_node.end_byte) not in seen_byte_ranges:
                seen_byte_ranges.add((return_val_node.start_byte, return_val_node.end_byte))
                rv = _node_text(return_val_node, source_bytes)
                if rv and len(rv) < 80:
                    parts.append(f"return {rv}")

        return parts

    def _extract_with_text(self, body: str) -> list[str]:
        """Fallback: text-based extraction of if/call/return."""
        parts: list[str] = []
        seen: set[str] = set()

        for line in body.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue

            # if / elif / else conditions
            if (stripped.startswith("if ") or stripped.startswith("elif ")) and ":" in stripped:
                cond = stripped.split(":", 1)[0].strip()
                dedup_key = cond
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    parts.append(cond)

            # return statements
            if stripped.startswith("return "):
                val = stripped[len("return "):].rstrip(";").strip()
                if len(val) < 80 and val not in seen:
                    seen.add(val)
                    parts.append(f"return {val}")

            # Call expressions (pattern: name(...)
            call_match = re.search(r'(?:^|[^.])\b([a-zA-Z_][\w.]*)\s*\(', stripped)
            if call_match:
                call_name = call_match.group(1)
                if not _is_noise_call(call_name) and call_name not in seen:
                    seen.add(call_name)
                    parts.append(f"calls {call_name}()")

        return parts

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_parser(self, lang_id: str) -> Any:
        """Get or create (Language, Parser) for *lang_id*.

        Reuses the extractor's parser factory to avoid loading languages twice.
        """
        if lang_id not in self._parsers:
            from agies.engine.sourcer.extractor import _get_parser
            self._parsers[lang_id] = _get_parser(lang_id)
        return self._parsers[lang_id]

    def _conclude(self, paths: list[list[str]]) -> str:
        """Generate a quick conclusion about the paths found."""
        if not paths:
            return "no reachable paths"

        # Check if any path has sanitization
        all_tagged = set()
        for path in paths:
            for func_name in path:
                logic = self._extract_function_logic(func_name)
                combined = " ".join(logic)
                if _has_sanitizer(combined):
                    all_tagged.add("[Sanitized]")
                if _has_auth_gate(combined):
                    all_tagged.add("[Auth_Gate]")

        parts: list[str] = [f"{len(paths)} path(s) found"]
        if "[Sanitized]" in all_tagged:
            parts.append("sanitized path(s) detected")
        if "[Auth_Gate]" in all_tagged:
            parts.append("auth gate(s) present")
        return ", ".join(parts) if parts else "plain path"


# ===================================================================
# Module-level helpers
# ===================================================================


def _detect_lang(file_path: str) -> str:
    """Map file extension to tree-sitter language id."""
    ext = file_path.rsplit(".", 1)[-1].lower()
    return {
        "py": "python",
        "java": "java",
        "js": "javascript",
        "jsx": "javascript",
        "ts": "typescript",
        "tsx": "typescript",
    }.get(ext, "python")


def _first_node(
    cap: dict[str, list[Any]], name: str,
) -> Any:
    """Get first node from a capture group."""
    nodes = cap.get(name)
    return nodes[0] if nodes else None


def _node_text(node: Any, source: bytes) -> str:
    """Decode node text from source bytes."""
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")
