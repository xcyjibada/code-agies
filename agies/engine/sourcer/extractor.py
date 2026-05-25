"""tree-sitter function extraction for multiple languages.

Inspired by Xint's ``c_tree_sitter.py`` and ``java_tree_sitter.py``.
Each language parser is a tree-sitter query + match loop that produces
uniform ``SourceFunction`` objects.
"""

from __future__ import annotations

import re
from typing import Any

from tree_sitter import Parser, Language, Node, Query, QueryCursor

from agies.engine.sourcer.models import SourceFile, SourceFunction

# ---------------------------------------------------------------------------
# Language-specific function definition queries
# ---------------------------------------------------------------------------

PYTHON_QUERY = """
(function_definition
  name: (identifier) @func.name
  parameters: (parameters) @func.args
  body: (block) @func.body
) @func.def
"""

JAVA_QUERY = """
(
  (method_declaration
    type: (_)             @func.return_type
    name: (identifier)     @func.name
    parameters: (formal_parameters) @func.args
    body: (block)?         @func.body
  ) @func.def
)
"""

JAVA_CONSTRUCTOR_QUERY = """
(
  (constructor_declaration
    name: (identifier)      @func.name
    parameters: (formal_parameters) @func.args
    body: (constructor_body)? @func.body
  ) @func.def
)
"""

JS_QUERY = """
; function foo() { ... }
(function_declaration
  name: (identifier) @func.name
  parameters: (formal_parameters) @func.args
  body: (statement_block) @func.body
) @func.def

; const/let foo = function() { ... }
; const/let foo = () => { ... }
; const/let foo = () => expr
(variable_declarator
  name: (identifier) @func.name
  value: [
    (function_expression
      parameters: (formal_parameters) @func.args
      body: (statement_block) @func.body)
    (arrow_function
      parameters: (formal_parameters) @func.args
      body: (_) @func.body)
  ]
) @func.def

; foo = function() { ... } (reassignment)
(assignment_expression
  left: (_) @func.name
  right: [
    (function_expression
      parameters: (formal_parameters) @func.args
      body: (statement_block) @func.body)
    (arrow_function
      parameters: (formal_parameters) @func.args
      body: (_) @func.body)
  ]
) @func.def

; export function foo() { ... }
(export_statement
  (function_declaration
    name: (identifier) @func.name
    parameters: (formal_parameters) @func.args
    body: (statement_block) @func.body)
) @func.def

; method inside class
(method_definition
  name: (property_identifier) @func.name
  parameters: (formal_parameters) @func.args
  body: (statement_block) @func.body
) @func.def
"""


# ---------------------------------------------------------------------------
# Language-specific call expression queries (for call graph)
# ---------------------------------------------------------------------------

PYTHON_CALL_QUERY = """
; Direct calls: foo()
(call
  function: (identifier) @call.name
  arguments: (argument_list)) @call

; Method / attribute calls: obj.foo(), self.foo()
(call
  function: (attribute
    attribute: (identifier) @call.name)
  arguments: (argument_list)) @call
"""

JAVA_CALL_QUERY = """
; Plain calls: foo()
(method_invocation
  name: (identifier) @call.name
  arguments: (argument_list)) @call

; Qualified calls: obj.foo()
(method_invocation
  object: (_)
  name: (identifier) @call.name
  arguments: (argument_list)) @call
"""

JS_CALL_QUERY = """
; foo()
(call_expression
  function: (identifier) @call.name
  arguments: (arguments)) @call

; obj.foo()
(call_expression
  function: (member_expression
    property: (property_identifier) @call.name)
  arguments: (arguments)) @call

; obj.#foo() (private fields)
(call_expression
  function: (member_expression
    property: (private_property_identifier) @call.name)
  arguments: (arguments)) @call
"""


# ---------------------------------------------------------------------------
# Parser factory — lazy init
# ---------------------------------------------------------------------------

_parsers: dict[str, tuple[Language, Parser]] = {}


def _get_parser(lang_id: str) -> tuple[Any, Parser]:
    """Return (Language, Parser) for the given language id."""
    if lang_id not in _parsers:
        if lang_id == "python":
            import tree_sitter_python as tspy

            lang = Language(tspy.language())
        elif lang_id == "java":
            import tree_sitter_java as tsjava

            lang = Language(tsjava.language())
        elif lang_id in ("javascript", "typescript"):
            if lang_id == "typescript":
                import tree_sitter_typescript as tsts

                lang = Language(tsts.language_typescript())
            else:
                import tree_sitter_javascript as tsjs

                lang = Language(tsjs.language())
        else:
            raise ValueError(f"Unsupported language: {lang_id}")
        _parsers[lang_id] = (lang, Parser(lang))
    return _parsers[lang_id]


# ---------------------------------------------------------------------------
# Language dispatcher
# ---------------------------------------------------------------------------


def extract_functions(sf: SourceFile) -> list[SourceFunction]:
    """Extract all functions from *sf* using the appropriate parser."""
    ext = sf.path.rsplit(".", 1)[-1].lower() if "." in sf.path else ""
    source_bytes = sf.source.encode("utf-8")

    if ext == "py":
        return _extract_python(sf, source_bytes)
    elif ext == "java":
        return _extract_java(sf, source_bytes)
    elif ext in ("js", "jsx"):
        return _extract_js(sf, source_bytes, "javascript")
    elif ext in ("ts", "tsx"):
        return _extract_js(sf, source_bytes, "typescript")
    return []


# ---------------------------------------------------------------------------
# Python extraction
# ---------------------------------------------------------------------------


def _extract_python(
    sf: SourceFile, source: bytes
) -> list[SourceFunction]:
    lang, parser = _get_parser("python")
    query = Query(lang, PYTHON_QUERY)
    tree = parser.parse(source)
    results: list[SourceFunction] = []
    cursor = QueryCursor(query)

    for _pattern_idx, cap in cursor.matches(tree.root_node):
        func_def = _first_cap(cap, "func.def")
        func_name = _first_cap(cap, "func.name")
        func_args = _first_cap(cap, "func.args")
        func_body = _first_cap(cap, "func.body")

        if not all([func_def, func_name, func_args, func_body]):
            continue

        name = _node_text(func_name, source)
        sig_text = f"def {name}{_node_text(func_args, source)}"
        body_text = _node_text(func_body, source)
        start_line = func_def.start_point[0] + 1
        end_line = func_body.end_point[0] + 1

        results.append(
            SourceFunction(
                name=name,
                fullname=name,
                file_path=sf.path,
                line_start=start_line,
                line_end=end_line,
                signature=sig_text,
                body=body_text,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Java extraction
# ---------------------------------------------------------------------------


def _extract_java(sf: SourceFile, source: bytes) -> list[SourceFunction]:
    lang, parser = _get_parser("java")
    query = Query(lang, JAVA_QUERY)
    ctor_query = Query(lang, JAVA_CONSTRUCTOR_QUERY)
    tree = parser.parse(source)
    results: list[SourceFunction] = []

    class_scope = _java_class_scope(tree.root_node)

    # Regular methods
    cursor = QueryCursor(query)
    for _pattern_idx, cap in cursor.matches(tree.root_node):
        fn = _make_java_func(sf, source, cap, class_scope)
        if fn:
            results.append(fn)

    # Constructors
    cursor = QueryCursor(ctor_query)
    for _pattern_idx, cap in cursor.matches(tree.root_node):
        fn = _make_java_func(sf, source, cap, class_scope)
        if fn:
            results.append(fn)

    return results


def _java_class_scope(root: Node) -> str:
    """Build the enclosing class prefix for a Java source file."""
    parts: list[str] = []
    _walk_classes(root, parts)
    return "::".join(parts)


def _walk_classes(node: Node, parts: list[str]) -> None:
    for child in node.children:
        if child.type in ("class_declaration", "interface_declaration"):
            for c in child.children:
                if c.type == "identifier":
                    parts.append(_node_text(c, b""))
                    _walk_classes(child, parts)
                    return


def _make_java_func(
    sf: SourceFile,
    source: bytes,
    cap: dict[str, list[Node]],
    class_prefix: str,
) -> SourceFunction | None:
    func_def = _first_cap(cap, "func.def")
    func_name = _first_cap(cap, "func.name")
    func_args = _first_cap(cap, "func.args")
    func_body = _first_cap(cap, "func.body")

    if not all([func_def, func_name, func_args]):
        return None

    name = _node_text(func_name, source)
    prefix = f"{class_prefix}::" if class_prefix else ""
    args_text = _node_text(func_args, source)
    return_type = _node_text(_first_cap(cap, "func.return_type"), source)
    sig_text = f"{return_type} {name}{args_text}" if return_type else f"{name}{args_text}"

    body_text = _node_text(func_body, source) if func_body else ""
    start_line = func_def.start_point[0] + 1
    end_line = (func_body.end_point[0] + 1) if func_body else start_line

    return SourceFunction(
        name=name,
        fullname=f"{prefix}{name}",
        file_path=sf.path,
        line_start=start_line,
        line_end=end_line,
        signature=sig_text.strip(),
        body=body_text,
    )


# ---------------------------------------------------------------------------
# JavaScript / TypeScript extraction
# ---------------------------------------------------------------------------


def _extract_js(
    sf: SourceFile, source: bytes, lang_id: str
) -> list[SourceFunction]:
    lang, parser = _get_parser(lang_id)
    query = Query(lang, JS_QUERY)
    tree = parser.parse(source)
    results: list[SourceFunction] = []
    seen: set[tuple[int, int]] = set()
    cursor = QueryCursor(query)

    for _pattern_idx, cap in cursor.matches(tree.root_node):
        func_def = _first_cap(cap, "func.def")
        func_name = _first_cap(cap, "func.name")
        func_args = _first_cap(cap, "func.args")
        func_body = _first_cap(cap, "func.body")

        if not all([func_def, func_name, func_args, func_body]):
            continue

        name = _node_text(func_name, source)
        args_text = _node_text(func_args, source)
        sig_text = f"function {name}{args_text}"
        body_text = _node_text(func_body, source)
        start_line = func_def.start_point[0] + 1
        end_line = func_body.end_point[0] + 1

        # Deduplicate by byte range
        key = (func_def.start_byte, func_def.end_byte)
        if key in seen:
            continue
        seen.add(key)

        results.append(
            SourceFunction(
                name=name,
                fullname=name,
                file_path=sf.path,
                line_start=start_line,
                line_end=end_line,
                signature=sig_text,
                body=body_text,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Call graph extraction
# ---------------------------------------------------------------------------


def _match_calls_to_functions(
    source: bytes,
    lang: Language,
    func_query: str,
    call_query: str,
) -> dict[str, set[str]]:
    """Parse *source* and return ``{caller_name → {callee_name, ...}}``.

    Two-pass approach:
      1. Extract all function definitions with byte ranges.
      2. Extract all call expressions; assign each to its enclosing function
         by checking byte-range containment.
    """
    parser = Parser(lang)
    tree = parser.parse(source)

    # Pass 1: function definitions → (name, start_byte, end_byte)
    func_defs: list[tuple[str, int, int]] = []
    q_func = Query(lang, func_query)
    for _pattern_idx, cap in QueryCursor(q_func).matches(tree.root_node):
        node = _first_cap(cap, "func.def")
        name_node = _first_cap(cap, "func.name")
        if node and name_node:
            name = _node_text(name_node, source)
            if name:
                func_defs.append((name, node.start_byte, node.end_byte))

    # Pass 2: call expressions → (callee_name, start_byte, end_byte)
    call_matches: list[tuple[str, int, int]] = []
    q_call = Query(lang, call_query)
    for _pattern_idx, cap in QueryCursor(q_call).matches(tree.root_node):
        callee_node = _first_cap(cap, "call.name")
        call_node = _first_cap(cap, "call")
        if callee_node and call_node:
            name = _node_text(callee_node, source)
            if name:
                call_matches.append((name, call_node.start_byte, call_node.end_byte))

    # Spatial containment: assign each call to its enclosing function
    calls: dict[str, set[str]] = {}
    for fn_name, fn_start, fn_end in func_defs:
        callees: set[str] = set()
        for callee_name, call_start, call_end in call_matches:
            if call_start >= fn_start and call_end <= fn_end:
                callees.add(callee_name)
        if callees:
            calls[fn_name] = callees

    return calls


# ---------------------------------------------------------------------------
# Public API: extract_call_graph
# ---------------------------------------------------------------------------


def extract_call_graph(sf: SourceFile) -> dict[str, set[str]]:
    """Build ``{caller_name → {callee_name, ...}}`` for all functions in *sf*.

    Uses tree-sitter to find call expressions and matches them to their
    enclosing function definition by byte-range containment.

    The result is consumed by ``FunctionIndex.build_call_graph_from_calls()``.
    """
    source = sf.source.encode("utf-8")
    ext = sf.path.rsplit(".", 1)[-1].lower() if "." in sf.path else ""

    if ext == "py":
        lang, _ = _get_parser("python")
        return _match_calls_to_functions(
            source, lang, PYTHON_QUERY, PYTHON_CALL_QUERY,
        )
    if ext == "java":
        # Merge method and constructor queries for function-range detection
        java_func_query = f"{JAVA_QUERY}\n\n{JAVA_CONSTRUCTOR_QUERY}"
        lang, _ = _get_parser("java")
        return _match_calls_to_functions(
            source, lang, java_func_query, JAVA_CALL_QUERY,
        )
    if ext in ("js", "jsx"):
        lang_id = "javascript"
    elif ext in ("ts", "tsx"):
        lang_id = "typescript"
    else:
        return {}

    lang, _ = _get_parser(lang_id)
    return _match_calls_to_functions(
        source, lang, JS_QUERY, JS_CALL_QUERY,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _first_cap(cap: dict[str, list[Node]], name: str) -> Node | None:
    """Extract the first (only) node from a capture group list."""
    nodes = cap.get(name)
    return nodes[0] if nodes else None


def _node_text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    # For class_scope walker we pass empty bytes — use the text property
    if source:
        return node.text.decode("utf-8") if node.text else ""
    return node.text.decode("utf-8") if node.text else ""


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

LANGUAGE_PARSERS = {
    ".py": extract_functions,
    ".java": extract_functions,
    ".js": extract_functions,
    ".jsx": extract_functions,
    ".ts": extract_functions,
    ".tsx": extract_functions,
}


def extract_file(path: str) -> list[SourceFunction]:
    """Convenience: read a file path and extract functions."""
    ext = "." + path.rsplit(".", 1)[-1].lower()
    if ext not in LANGUAGE_PARSERS:
        return []
    with open(path, "rb") as f:
        raw = f.read()
    try:
        source_text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []
    sf = SourceFile(path=path, source=source_text)
    return extract_functions(sf)
