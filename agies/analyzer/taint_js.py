"""JavaScript-specific taint propagation engine for tree-sitter CST.

Walks tree-sitter CST nodes for JS/TS and detects taint flows
from sources (DOM APIs, Express request params) to sinks
(eval, innerHTML, document.write, etc).
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


def _get_call_name_js(node: Node) -> str:
    """Extract call name from a call_expression.

    eval(x) -> 'eval'
    console.log(x) -> 'console.log'
    window.location.toString() -> 'window.location.toString'
    """
    for child in node.named_children:
        if child.type == "identifier":
            return _node_text(child)
        elif child.type == "member_expression":
            parts: list[str] = []
            _extract_dotted(child, parts)
            return ".".join(parts)
    return ""


def _extract_dotted(node: Node, parts: list[str]) -> None:
    """Extract dotted name from a member_expression into parts list."""
    for child in node.children:
        if child.type == "identifier":
            parts.append(_node_text(child))
        elif child.type == "property_identifier":
            parts.append(_node_text(child))
        elif child.type == "member_expression":
            _extract_dotted(child, parts)
        elif child.type == "call_expression":
            _extract_dotted_from_call(child, parts)


def _extract_dotted_from_call(node: Node, parts: list[str]) -> None:
    """Extract dotted name from call_expression for member chain."""
    for child in node.named_children:
        if child.type == "identifier":
            parts.append(_node_text(child))
        elif child.type == "member_expression":
            _extract_dotted(child, parts)


def _collect_identifiers(node: Node) -> list[str]:
    """Collect all identifier names in a subtree."""
    names: list[str] = []

    def walk(n: Node) -> None:
        if n.type == "identifier":
            names.append(_node_text(n))
        for child in n.named_children:
            walk(child)

    walk(node)
    return names


def _get_call_args(node: Node) -> list[Node]:
    """Get argument nodes from a call_expression."""
    for child in node.named_children:
        if child.type == "arguments":
            return list(child.named_children)
    return []


class TaintEngineJS:
    """Forward taint propagation engine for JavaScript (tree-sitter CST)."""

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

        self._fn_map: dict[str, FunctionIR] = {}
        for fn_list in symbol_table.functions.values():
            for fn in fn_list:
                self._fn_map[fn.qualified_name] = fn

    def analyze(self) -> list[TaintPath]:
        """Run taint analysis on all JS/TS functions."""
        self.taint_paths = []

        for fn_list in self.symbol_table.functions.values():
            if len(self.taint_paths) >= self.max_paths:
                break
            for fn in fn_list:
                if len(self.taint_paths) >= self.max_paths:
                    break
                if not fn.ast_body:
                    continue
                # Seed params as sources for JS (params are a common entry point)
                pretainted = self._seed_params(fn)
                self._analyze_body(fn.ast_body, pretainted, fn, 0)

        return self.taint_paths

    def _seed_params(self, fn: FunctionIR) -> dict[str, TaintStep]:
        """Seed all function parameters as potential sources.

        In JS/TS, function params commonly carry user input:
        - Express route handlers: (req, res)
        - Event handlers: (event)
        - Function params in general
        """
        tainted: dict[str, TaintStep] = {}
        for param in fn.params:
            tainted[param] = TaintStep(
                file_path=fn.file_path,
                line=fn.line,
                kind="source",
                variable_or_expr=param,
                detail=f"function parameter: {param}",
            )
        return tainted

    def _analyze_body(
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
        if node.type in ("lexical_declaration", "variable_declaration"):
            self._handle_var_decl(node, tainted, fn, depth)

        elif node.type == "expression_statement":
            for child in node.named_children:
                if child.type == "call_expression":
                    self._handle_call(child, tainted, fn, depth)
                elif child.type == "assignment_expression":
                    self._handle_assignment(child, tainted, fn, depth)

        elif node.type == "assignment_expression":
            self._handle_assignment(node, tainted, fn, depth)

        elif node.type == "return_statement":
            # Check for call expressions inside return
            for child in node.named_children:
                if child.type == "call_expression":
                    self._handle_call(child, tainted, fn, depth)

        elif node.type == "if_statement":
            for child in node.named_children:
                if child.type == "statement_block":
                    self._analyze_body(list(child.children), tainted, fn, depth)

        elif node.type == "statement_block":
            self._analyze_body(list(node.children), tainted, fn, depth)

        elif node.type == "for_statement":
            for child in node.named_children:
                if child.type == "statement_block":
                    self._analyze_body(list(child.children), tainted, fn, depth)

        elif node.type == "while_statement":
            for child in node.named_children:
                if child.type == "statement_block":
                    self._analyze_body(list(child.children), tainted, fn, depth)

        elif node.type == "try_statement":
            for child in node.named_children:
                if child.type == "statement_block":
                    self._analyze_body(list(child.children), tainted, fn, depth)

        elif node.type == "switch_statement":
            for child in node.named_children:
                if child.type == "switch_body":
                    for case in child.named_children:
                        if case.type in ("switch_case", "switch_default"):
                            for cc in case.named_children:
                                if cc.type == "statement_block":
                                    self._analyze_body(list(cc.children), tainted, fn, depth)

    def _handle_var_decl(
        self,
        node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Handle const/let/var declarations."""
        for child in node.named_children:
            if child.type == "variable_declarator":
                var_name = ""
                value_node: Node | None = None
                for vc in child.named_children:
                    if vc.type == "identifier":
                        var_name = _node_text(vc)
                    elif vc.type in ("call_expression", "member_expression",
                                     "identifier", "binary_expression",
                                     "arrow_function", "function"):
                        value_node = vc
                        if vc.type == "call_expression":
                            self._handle_call(vc, tainted, fn, depth)

                if var_name and value_node:
                    self._propagate(var_name, value_node, tainted, fn, node, depth)

    def _handle_assignment(
        self,
        node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Handle assignment expressions like 'x = expr' or 'x.y = expr'.

        In assignment_expression, the LHS is the first named child,
        the RHS is the last named child. We handle them separately.
        """
        lhs_text: str | None = None
        lhs_property: str | None = None  # property name if LHS is a member expression
        rhs: Node | None = None
        ncs = list(node.named_children)
        if not ncs:
            return

        # First named child = LHS
        lhs = ncs[0]
        if lhs.type == "member_expression":
            lhs_text = _node_text(lhs)
            for mc in lhs.named_children:
                if mc.type == "property_identifier":
                    lhs_property = _node_text(mc)
        elif lhs.type == "identifier":
            lhs_text = _node_text(lhs)

        # Last named child = RHS (if more than one child)
        if len(ncs) > 1:
            rhs = ncs[-1]
            if rhs.type == "call_expression":
                self._handle_call(rhs, tainted, fn, depth)

        if not lhs_text or not rhs:
            return

        # Check for DOM sink assignments like innerHTML = tainted_var
        if lhs_property in ("innerHTML", "outerHTML"):
            rhs_idents = _collect_identifiers(rhs)
            for rhs_name in rhs_idents:
                if rhs_name in tainted:
                    self._emit_path(
                        source=tainted[rhs_name],
                        sink_name=lhs_property,
                        call_name=lhs_property,
                        call_node=node,
                        fn=fn,
                        tainted_args=[rhs_name],
                    )
            return

        # Normal taint propagation
        self._propagate(lhs_text, rhs, tainted, fn, node, depth)

    def _propagate(
        self,
        var_name: str,
        value_node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        stmt_node: Node,
        depth: int,
    ) -> None:
        """Check if value_node is a source or references tainted vars."""
        val_text = _node_text(value_node)
        line = stmt_node.start_point[0] + 1 if stmt_node.start_point else fn.line

        # 1. Direct source match
        for src in self._sources:
            if val_text == src or val_text.startswith(src):
                tainted[var_name] = TaintStep(
                    file_path=fn.file_path,
                    line=line,
                    kind="source",
                    variable_or_expr=var_name,
                    detail=f"assigned from source: {src}",
                )
                return

            # method_invocation source like localStorage.getItem(...)
            if value_node.type == "call_expression":
                call_name = _get_call_name_js(value_node)
                if call_name == src or call_name.endswith("." + src):
                    tainted[var_name] = TaintStep(
                        file_path=fn.file_path,
                        line=line,
                        kind="source",
                        variable_or_expr=var_name,
                        detail=f"assigned from source: {src}",
                    )
                    return

        # 2. Propagation from tainted variables
        refs = _collect_identifiers(value_node)
        for ref in refs:
            if ref in tainted:
                tainted[var_name] = TaintStep(
                    file_path=fn.file_path,
                    line=line,
                    kind="propagation",
                    variable_or_expr=var_name,
                    detail=f"propagated from {ref}",
                )
                return

        # 3. Check dotted property access like a.b.c
        if value_node.type == "member_expression":
            parts = val_text.split(".")
            for i in range(len(parts) - 1, 0, -1):
                prefix = ".".join(parts[:i])
                if prefix in tainted:
                    tainted[var_name] = TaintStep(
                        file_path=fn.file_path,
                        line=line,
                        kind="propagation",
                        variable_or_expr=var_name,
                        detail=f"propagated from {prefix}",
                    )
                    return

    def _handle_call(
        self,
        node: Node,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Process a call_expression: detect sources, sinks, inter-procedural."""
        call_name = _get_call_name_js(node)
        if not call_name:
            return

        args = _get_call_args(node)
        arg_texts = [_node_text(a) for a in args]
        tainted_args: list[str] = []
        for arg_node in args:
            for ref in _collect_identifiers(arg_node):
                if ref in tainted and ref not in tainted_args:
                    tainted_args.append(ref)

        # 1. Check if this call is itself a source
        if not tainted_args:
            for src in self._sources:
                if call_name == src or call_name.endswith("." + src):
                    result_var = f"<{call_name.split('.')[-1]}_result>"
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
        """Check if a call name matches a sink pattern."""
        if actual == pattern:
            return True
        if "." in pattern:
            return actual == pattern
        if "." in actual:
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
        """Follow taint through a function call (depth-limited)."""
        call_name = _get_call_name_js(call_node)
        if not call_name:
            return

        callee_fn = self._fn_map.get(call_name)
        if callee_fn is None:
            for qname, fn_ir in self._fn_map.items():
                if qname.endswith("." + call_name):
                    callee_fn = fn_ir
                    break
        if callee_fn is None or not callee_fn.ast_body:
            return

        args = _get_call_args(call_node)
        pretainted: dict[str, TaintStep] = {}
        for i, arg_node in enumerate(args):
            if i < len(callee_fn.params):
                for ref in _collect_identifiers(arg_node):
                    if ref in tainted:
                        pretainted[callee_fn.params[i]] = tainted[ref]
                        break

        if not pretainted:
            return

        self._analyze_body(callee_fn.ast_body, pretainted, callee_fn, depth + 1)
