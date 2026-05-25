"""Java-specific taint propagation engine for tree-sitter CST.

Walks tree-sitter CST nodes instead of Python AST nodes.
Produces the same TaintPath objects for the existing findings pipeline.
"""

from __future__ import annotations

from typing import Optional

from tree_sitter import Node

from agies.analyzer.config import LanguageAnalysisConfig
from agies.analyzer.models import (
    CallGraph,
    FunctionIR,
    SymbolTable,
    TaintPath,
    TaintStep,
)


def _node_text(node: Node) -> str:
    return node.text.decode("utf-8") if node.text else ""


def _extract_call_name(node: Node) -> str | None:
    """Extract the function/method name from a method_invocation.

    Examples:
        exec(query) -> 'exec'
        Runtime.exec(query) -> 'Runtime.exec'
        Runtime.getRuntime().exec(query) -> 'Runtime.exec' (we use top-level name)
        obj.foo.bar() -> 'obj.foo.bar'
    """
    if node.type != "method_invocation":
        return None

    # Collect all parts
    parts: list[str] = []
    curr: Node | None = node

    # Walk up the chain to get the full dotted name
    # The outermost method_invocation will have the method name
    # and possibly nested method_invocations as its object
    while curr is not None and curr.type == "method_invocation":
        for i, child in enumerate(curr.named_children):
            if child.type == "identifier":
                # This is the method name
                parts.insert(0, _node_text(child))
            elif child.type == "argument_list":
                # This can be a standalone call - the method name comes from elsewhere
                pass

        # Look for object child in the children (between method_invocation parents)
        found_object = False
        for child in curr.children:
            if child.type == ".":
                found_object = True
                continue
            if found_object and child.type == "identifier":
                pass  # Already handled above
            if found_object and child.type == "method_invocation":
                found_object = False  # Let the loop handle it

        # Move up to parent method_invocation (e.g., Runtime.getRuntime().exec)
        # The parent of exec()'s method_invocation is the expression_statement
        # We need to find if there's a nested method_invocation as the object
        break

    return ".".join(parts) if parts else None


def _extract_call_name_v2(node: Node) -> str | None:
    """Improved version: extract full dotted call name from method_invocation."""
    if node.type != "method_invocation":
        return None

    parts: list[str] = []

    # Look for the object part (could be identifier or nested method_invocation)
    for child in node.children:
        if child.type == "identifier":
            parts.append(_node_text(child))
        elif child.type == "method_invocation":
            # Nested call like Runtime.getRuntime() - extract the chain
            nested_name = _extract_call_name_v2(child)
            if nested_name:
                # Take only the base object from nested call
                base = nested_name.split(".")[0] if "." in nested_name else nested_name
                parts.append(base)
        elif child.type == ".":
            continue
        elif child.type == "argument_list":
            continue

    if not parts:
        return None

    return ".".join(parts)


def _extract_call_name_v3(node: Node) -> str:
    """Extract the method name from a method_invocation, handling chained calls.

    For 'Runtime.getRuntime().exec(query)':
      The top-level method_invocation has children:
        method_invocation (for getRuntime()), '.', identifier('exec'), argument_list

    Returns the leaf method name (e.g., 'exec') for sink matching,
    and stores the full chain separately.
    """
    if node.type != "method_invocation":
        return ""

    # The last identifier or field_access child before argument_list is the method name
    last_name = ""
    for child in node.children:
        if child.type == "identifier":
            last_name = _node_text(child)
    return last_name


def _get_call_object_name(node: Node) -> str:
    """Get the base object name from a method_invocation, if any.

    For 'Runtime.getRuntime().exec(query)', returns 'Runtime'.
    For 'exec(query)', returns ''.
    """
    if node.type != "method_invocation":
        return ""

    for child in node.children:
        if child.type == "identifier":
            # First identifier is the object (before any dot)
            return _node_text(child)
        if child.type == "method_invocation":
            # Nested call - get the base of it
            return _get_call_object_name(child)
    return ""


def _get_invocation_args(node: Node) -> list[Node]:
    """Get argument nodes from a method_invocation."""
    for child in node.named_children:
        if child.type == "argument_list":
            return list(child.named_children)
    return []


def _get_arg_texts(node: Node) -> list[str]:
    """Get argument texts from a method_invocation."""
    return [_node_text(arg) for arg in _get_invocation_args(node)]


def _get_identifiers_in_node(node: Node) -> list[str]:
    """Collect all identifier names referenced in a subtree."""
    names: list[str] = []
    _collect_idents(node, names)
    return names


def _collect_idents(node: Node, names: list[str]) -> None:
    if node.type == "identifier":
        names.append(_node_text(node))
    for child in node.named_children:
        _collect_idents(child, names)


class TaintEngineJava:
    """Forward taint propagation engine for Java (tree-sitter CST)."""

    def __init__(
        self,
        lang_config: LanguageAnalysisConfig,
        symbol_table: SymbolTable,
        call_graph: CallGraph,
        max_depth: int = 3,
        max_paths: int = 100,
    ) -> None:
        self.lang_config = lang_config
        self.symbol_table = symbol_table
        self.call_graph = call_graph
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.taint_paths: list[TaintPath] = []

        self._sources = lang_config.sources
        self._sinks = lang_config.sinks
        self._sanitizers = lang_config.sanitizers

        # Map function qname -> FunctionIR
        self._fn_map: dict[str, FunctionIR] = {}
        for fn_list in symbol_table.functions.values():
            for fn in fn_list:
                self._fn_map[fn.qualified_name] = fn

    def analyze(self) -> list[TaintPath]:
        """Run taint analysis on all Java functions."""
        self.taint_paths = []

        for fn_list in self.symbol_table.functions.values():
            if len(self.taint_paths) >= self.max_paths:
                break
            for fn in fn_list:
                if len(self.taint_paths) >= self.max_paths:
                    break
                if not fn.ast_body:
                    continue
                # Seed method parameters as sources if they match
                pretainted = self._seed_params_as_sources(fn)
                self._analyze_block(fn.ast_body, pretainted, fn, 0)

        return self.taint_paths

    def _seed_params_as_sources(self, fn: FunctionIR) -> dict[str, TaintStep]:
        """Seed method parameters as taint sources when the method is a handler.

        A Java method is considered a handler if:
        - It has Spring annotations (@GetMapping, @PostMapping, etc.)
        - Its parameters are annotated (@RequestParam, @PathVariable, etc.)
        """
        tainted: dict[str, TaintStep] = {}

        # Check if this is a handler method (has mapping annotations)
        is_handler = any(
            d in ("GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
                  "RequestMapping", "PatchMapping")
            for d in fn.decorators
        )

        if not is_handler:
            return tainted

        # Seed all parameters as sources
        for param in fn.params:
            tainted[param] = TaintStep(
                file_path=fn.file_path,
                line=fn.line,
                kind="source",
                variable_or_expr=param,
                detail=f"handler method parameter: {param}",
            )

        return tainted

    def _analyze_block(
        self,
        body: list,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Walk a block of statements forward, tracking taint."""
        for child in body:
            self._handle_statement(child, tainted, fn, depth)

    def _handle_statement(
        self,
        node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Route a statement node to the appropriate handler."""
        if node.type == "local_variable_declaration":
            self._handle_local_var_decl(node, tainted, fn, depth)

        elif node.type == "expression_statement":
            for child in node.named_children:
                if child.type == "method_invocation":
                    self._handle_method_call(child, tainted, fn, depth)
                elif child.type == "assignment_expression":
                    self._handle_assignment(child, tainted, fn, depth)

        elif node.type == "assignment_expression":
            self._handle_assignment(node, tainted, fn, depth)

        elif node.type == "if_statement":
            for child in node.named_children:
                if child.type in ("block",):
                    self._analyze_block(list(child.children), tainted, fn, depth)
                # Also handle if without braces (single statement)

        elif node.type == "block":
            self._analyze_block(list(node.children), tainted, fn, depth)

        elif node.type in ("try_statement", "try_with_resources_statement"):
            for child in node.named_children:
                if child.type == "block":
                    self._analyze_block(list(child.children), tainted, fn, depth)
                elif child.type == "catch_clause":
                    for gc in child.named_children:
                        if gc.type == "block":
                            self._analyze_block(list(gc.children), tainted, fn, depth)

        elif node.type == "for_statement":
            for child in node.named_children:
                if child.type == "block":
                    self._analyze_block(list(child.children), tainted, fn, depth)

        elif node.type == "while_statement":
            for child in node.named_children:
                if child.type == "block":
                    self._analyze_block(list(child.children), tainted, fn, depth)

        elif node.type == "return_statement":
            pass  # Nothing to track for return values at top level

    def _handle_local_var_decl(
        self,
        node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Handle a local variable declaration like 'String query = expr;'."""
        for child in node.named_children:
            if child.type == "variable_declarator":
                self._handle_declarator(child, tainted, fn, depth)

    def _handle_declarator(
        self,
        node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Handle a variable declarator like 'query = expr'."""
        var_name = ""
        value_node: Node | None = None

        for child in node.named_children:
            if child.type == "identifier":
                var_name = _node_text(child)
            elif child.type in ("method_invocation",):
                self._handle_method_call(child, tainted, fn, depth)
                value_node = child
            elif child.type in ("binary_expression",):
                value_node = child
            elif child.type in ("identifier",):
                value_node = child

        if var_name and value_node:
            self._propagate_to_var(var_name, value_node, tainted, fn, node)

    def _handle_assignment(
        self,
        node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Handle an assignment like 'x = expr;'."""
        lhs: str | None = None
        rhs: Node | None = None

        for child in node.named_children:
            if child.type == "identifier":
                lhs = _node_text(child)
            elif child.type == "field_access":
                lhs = _node_text(child)
            elif child.type in ("method_invocation",):
                rhs = child
            elif child.type in ("binary_expression", "identifier", "string_literal"):
                rhs = child

        if lhs and rhs:
            self._propagate_to_var(lhs, rhs, tainted, fn, node)

    def _propagate_to_var(
        self,
        var_name: str,
        value_node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        node: Node,
    ) -> None:
        """Check if value_node is a source or references tainted vars, propagate taint."""
        val_text = _node_text(value_node)

        # 1. Direct source match
        for src in self._sources:
            if val_text == src or val_text.startswith(src):
                tainted[var_name] = TaintStep(
                    file_path=fn.file_path,
                    line=node.start_point[0] + 1 if node.start_point else fn.line,
                    kind="source",
                    variable_or_expr=var_name,
                    detail=f"assigned from source: {src}",
                )
                return

            # method_invocation source like request.getParameter(...)
            if value_node.type == "method_invocation":
                call_name = _extract_call_name_v3(value_node)
                if call_name == src or f"{src}" == val_text.split("(")[0]:
                    tainted[var_name] = TaintStep(
                        file_path=fn.file_path,
                        line=node.start_point[0] + 1 if node.start_point else fn.line,
                        kind="source",
                        variable_or_expr=var_name,
                        detail=f"assigned from source: {src}",
                    )
                    return

        # 2. Propagation: check if value references tainted variables
        refs = _get_identifiers_in_node(value_node)
        for ref in refs:
            if ref in tainted:
                tainted[var_name] = TaintStep(
                    file_path=fn.file_path,
                    line=node.start_point[0] + 1 if node.start_point else fn.line,
                    kind="propagation",
                    variable_or_expr=var_name,
                    detail=f"propagated from {ref}",
                )
                return

    def _handle_method_call(
        self,
        node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Process a method_invocation: check sink, handle inter-procedural."""
        call_name = _extract_call_name_v3(node)
        if not call_name:
            return

        # Get argument texts and check which are tainted
        args = _get_invocation_args(node)
        arg_texts = [_node_text(a) for a in args]
        tainted_args: list[str] = []
        for arg_node in args:
            for ref in _get_identifiers_in_node(arg_node):
                if ref in tainted and ref not in tainted_args:
                    tainted_args.append(ref)

        # 1. Check if this call is a source (e.g., request.getParameter)
        if not tainted_args:
            obj_name = _get_call_object_name(node)
            for src in self._sources:
                # Match both "getParameter" and "request.getParameter"
                if call_name == src or f"{obj_name}.{call_name}" == src:
                    result_var = f"<{call_name}_result>"
                    tainted[result_var] = TaintStep(
                        file_path=fn.file_path,
                        line=node.start_point[0] + 1 if node.start_point else fn.line,
                        kind="source",
                        variable_or_expr=result_var,
                        detail=f"call to source: {src}",
                    )
                    break

        # 2. Check sink
        if tainted_args:
            for sink_name, severity in self._sinks.items():
                if self._matches_sink(call_name, sink_name):
                    self._emit_path(
                        source=tainted[tainted_args[0]],
                        sink_name=sink_name,
                        call_name=call_name,
                        call_node=node,
                        fn=fn,
                        tainted_args=tainted_args,
                    )
                    break

        # 3. Inter-procedural
        if tainted_args and depth < self.max_depth:
            self._inter_procedural(node, tainted, fn, depth, tainted_args)

    def _matches_sink(self, actual: str, pattern: str) -> bool:
        """Check if a call name matches a sink pattern.

        Rules like Python taint engine:
        - exact match: exec == exec
        - dotted match: Runtime.exec matches pattern 'exec' (ends with)
        - fully qualified: java.lang.Runtime.exec matches 'Runtime.exec'
        """
        if actual == pattern:
            return True
        if "." in pattern:
            # Pattern has dots, exact match required
            return actual == pattern
        if "." in actual:
            # Call is dotted, pattern is bare: obj.exec -> matches exec
            return actual.endswith("." + pattern)
        return False

    def _emit_path(
        self,
        source: TaintStep,
        sink_name: str,
        call_name: str,
        call_node: Node,
        fn: FunctionIR,
        tainted_args: list[str],
    ) -> None:
        """Create and record a TaintPath."""
        line = call_node.start_point[0] + 1 if call_node.start_point else fn.line
        path = TaintPath(
            source=source,
            sink=TaintStep(
                file_path=fn.file_path,
                line=line,
                kind="sink",
                variable_or_expr=call_name,
                detail=f"call to {call_name} with tainted args: {', '.join(tainted_args)}",
            ),
            confidence="high",
            source_rule_name=source.detail.replace("assigned from source: ", ""),
            sink_rule_name=sink_name,
        )
        # Deduplicate
        for existing in self.taint_paths:
            if (existing.sink.file_path == path.sink.file_path
                    and existing.sink.line == path.sink.line
                    and existing.sink.variable_or_expr == path.sink.variable_or_expr):
                return
        self.taint_paths.append(path)

    def _inter_procedural(
        self,
        call_node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
        tainted_args: list[str],
    ) -> None:
        """Follow taint through a method call (depth-limited)."""
        call_name = _extract_call_name_v3(call_node)
        if not call_name:
            return

        # Find callee
        callee_fn = self._fn_map.get(call_name)
        if callee_fn is None:
            # Try partial match
            for qname, fn_ir in self._fn_map.items():
                if qname.endswith("." + call_name):
                    callee_fn = fn_ir
                    break
        if callee_fn is None or not callee_fn.ast_body:
            return

        # Map tainted args to params
        args = _get_invocation_args(call_node)
        pretainted: dict[str, TaintStep] = {}
        for i, arg_node in enumerate(args):
            if i < len(callee_fn.params):
                for ref in _get_identifiers_in_node(arg_node):
                    if ref in tainted:
                        pretainted[callee_fn.params[i]] = tainted[ref]
                        break

        if not pretainted:
            return

        self._analyze_block(callee_fn.ast_body, pretainted, callee_fn, depth + 1)
