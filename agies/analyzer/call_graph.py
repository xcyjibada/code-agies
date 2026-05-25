"""Call graph builder: traverses AST calls and resolves targets via symbol table."""

from __future__ import annotations

import ast
import os

from tree_sitter import Node as TSNode

from agies.analyzer.models import (
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    FunctionIR,
    SourceFileIR,
    SymbolTable,
)


def _node_text(node: TSNode) -> str:
    return node.text.decode("utf-8") if node.text else ""


def _collect_calls_from_body(body: list[ast.stmt]) -> list[ast.Call]:
    """Collect all Call nodes from a list of AST statements."""
    calls: list[ast.Call] = []

    def _walk(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    calls.append(node)

    _walk(body)
    return calls


def _call_name(node: ast.Call) -> str | None:
    """Extract the name of the function being called as a dotted string.

    Examples:
        eval(x) -> "eval"
        os.system(x) -> "os.system"
        obj.method(x) -> "obj.method"
    """
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    elif isinstance(func, ast.Attribute):
        parts: list[str] = []
        curr = func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        else:
            return None
        return ".".join(reversed(parts))
    return None


class CallGraphBuilder:
    """Build a call graph from parsed source files and a symbol table."""

    def __init__(self, source_files: list[SourceFileIR], symbol_table: SymbolTable) -> None:
        self.source_files = source_files
        self.symbol_table = symbol_table
        self._file_map = {sf.file_path: sf for sf in source_files if not sf.parse_error}
        self.call_graph = CallGraph()

    def build(self) -> CallGraph:
        """Build the call graph and return it."""
        # Register all functions as nodes
        for sf in self.source_files:
            if sf.parse_error:
                continue
            for fn in sf.functions:
                self._ensure_node(fn.qualified_name, fn.file_path, fn.line)

        # Process each function body for calls
        for sf in self.source_files:
            if sf.parse_error:
                continue
            for fn in sf.functions:
                self._process_function_calls(fn)

        return self.call_graph

    def _ensure_node(self, qname: str, file_path: str, line: int) -> None:
        """Ensure a CallGraphNode exists for the given function."""
        if qname not in self.call_graph.nodes:
            self.call_graph.nodes[qname] = CallGraphNode(
                qualified_name=qname,
                file_path=file_path,
                line=line,
            )

    def _process_function_calls(self, fn: FunctionIR) -> None:
        """Walk a function's AST body and resolve each call."""
        # Get the source file to detect language
        caller_sf = self._file_map.get(fn.file_path)
        lang = caller_sf.language if caller_sf else "python"

        if lang != "python":
            # Use tree-sitter based call collection for Java, JS, TS, etc.
            self._process_ts_calls(fn, caller_sf)
            return

        # Python: use existing AST-based collection
        all_calls = _collect_calls_from_body(fn.ast_body)

        for call_node in all_calls:
            call_name_str = _call_name(call_node)
            if call_name_str is None:
                continue

            resolved = self._resolve_call_target(call_name_str, fn, caller_sf)
            callee_qname = resolved if resolved else call_name_str

            if callee_qname not in self.call_graph.nodes:
                self.call_graph.nodes[callee_qname] = CallGraphNode(
                    qualified_name=callee_qname,
                    file_path=fn.file_path,
                    line=call_node.lineno,
                )

            edge = CallGraphEdge(
                caller_qname=fn.qualified_name,
                callee_qname=callee_qname,
                call_line=call_node.lineno,
                resolved=resolved is not None,
            )
            self.call_graph.edges.append(edge)

            if not resolved:
                self.call_graph.unresolved_calls.append(
                    (fn.file_path, call_name_str, call_node.lineno)
                )

    def _collect_ts_calls_from_body(self, body: list) -> list[tuple[str, int]]:
        """Collect method_invocation names from tree-sitter CST body.

        Returns list of (call_name, line_number).
        """
        calls: list[tuple[str, int]] = []

        def walk(node) -> None:
            if isinstance(node, TSNode):
                if node.type == "method_invocation":
                    name = self._ts_call_name(node)
                    if name:
                        calls.append((name, node.start_point[0] + 1))
                for child in node.children:
                    walk(child)

        for stmt in body:
            walk(stmt)

        return calls

    def _ts_call_name(self, node: TSNode) -> str | None:
        """Extract dotted call name from a Java method_invocation node.

        Runtime.getRuntime().exec(query) -> 'exec'
        System.out.println(x) -> 'System.out.println'
        """
        parts: list[str] = []

        # Walk right-to-left through dots and identifiers
        def extract(n: TSNode) -> None:
            for child in reversed(n.children):
                if child.type == "identifier":
                    parts.insert(0, _node_text(child))
                elif child.type == "method_invocation":
                    extract(child)
                elif child.type == "field_access":
                    extract(child)

        extract(node)
        return ".".join(parts) if parts else None

    def _process_ts_calls(self, fn: FunctionIR, caller_sf: SourceFileIR | None) -> None:
        """Process calls in a Java function body using tree-sitter CST."""
        body = fn.ast_body
        if not body:
            return

        ts_calls = self._collect_ts_calls_from_body(body)

        for call_name_str, line in ts_calls:
            resolved = self._resolve_call_target(call_name_str, fn, caller_sf)
            callee_qname = resolved if resolved else call_name_str

            if callee_qname not in self.call_graph.nodes:
                self.call_graph.nodes[callee_qname] = CallGraphNode(
                    qualified_name=callee_qname,
                    file_path=fn.file_path,
                    line=line,
                )

            edge = CallGraphEdge(
                caller_qname=fn.qualified_name,
                callee_qname=callee_qname,
                call_line=line,
                resolved=resolved is not None,
            )
            self.call_graph.edges.append(edge)

            if not resolved:
                self.call_graph.unresolved_calls.append(
                    (fn.file_path, call_name_str, line)
                )

    def _resolve_call_target(
        self, name: str, caller_fn: FunctionIR, caller_sf: SourceFileIR | None
    ) -> str | None:
        """Resolve a call name to a fully qualified function name.

        Resolution order:
        1. Direct match in symbol table (qualified name)
        2. Local name in same file (function in scope)
        3. Imported name resolution
        4. Builtin check
        """
        sym = self.symbol_table

        # 1. Direct qualified name
        if name in sym.functions:
            return name

        # 2. If the name has dots, try as a fully qualified path
        if "." in name:
            if name in sym.functions:
                return name

        # 3. Check if this is a local function in the caller's file
        for scope_name in [caller_fn.qualified_name.rsplit(".", 1)[0] if "." in caller_fn.qualified_name else ""]:
            if scope_name:
                candidate = scope_name + "." + name
                if candidate in sym.functions:
                    return candidate

        # 4. Check if name matches any function's short name
        for qname in sym.functions:
            if qname.endswith("." + name) or qname == name:
                return qname

        # 5. Check imports in the caller's file
        if caller_sf:
            # 5a. Dotted name like "os.system" where "os" is an import
            if "." in name:
                module_part = name.split(".")[0]
                for imp in caller_sf.imports:
                    for imp_name, imp_alias in imp.names:
                        if imp_alias == module_part or imp_name == module_part:
                            return name  # Mark resolved so taint engine can match sinks

            # 5b. Direct name imported via "from X import Y" or "import X"
            for imp in caller_sf.imports:
                if imp.is_from:
                    for imp_name, imp_alias in imp.names:
                        effective = imp_alias or imp_name
                        if effective == name:
                            candidate = imp.module + "." + name
                            if candidate in sym.functions:
                                return candidate
                            # Try all functions in that module
                            for qname in sym.functions:
                                if qname == candidate or qname.endswith("." + effective):
                                    return qname
                            # Mark as resolved for taint analysis
                            return name
                else:
                    for imp_name, imp_alias in imp.names:
                        if imp_alias == name or imp_name == name:
                            if imp_name in sym.functions:
                                return imp_name
                            # Check functions in this module
                            for qname in sym.functions:
                                parts = qname.split(".")
                                if len(parts) >= 2 and parts[0] == imp_name and parts[-1] == (imp_alias or imp_name):
                                    pass  # Not precise enough

        # 6. Check Python builtins
        _builtins = {"abs", "all", "any", "bool", "bytes", "chr", "dict",
                     "dir", "enumerate", "eval", "exec", "float", "format",
                     "frozenset", "getattr", "hasattr", "hash", "hex", "id",
                     "input", "int", "isinstance", "issubclass", "iter",
                     "len", "list", "map", "max", "min", "next", "object",
                     "oct", "open", "ord", "pow", "print", "range", "repr",
                     "reversed", "round", "set", "slice", "sorted", "str",
                     "sum", "super", "tuple", "type", "vars", "zip",
                     "__import__"}
        if name in _builtins:
            return name

        return None


def collect_calls_from_body(body: list[ast.stmt]) -> list[ast.Call]:
    """Public helper to collect all Call nodes from a list of AST statements."""
    return _collect_calls_from_body(body)
