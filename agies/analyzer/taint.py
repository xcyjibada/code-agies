"""Forward taint propagation engine with depth-limited inter-procedural tracking.

Algorithm:
  For each function:
    1. Build a set of tainted variables from source matches
    2. Walk each statement forward:
       - Assign: propagate taint to LHS if RHS is source or references tainted var
       - Call: check if any arg is tainted and call matches sink -> emit TaintPath
       - Call: if args tainted and not sanitizer -> mark return value as tainted
    3. Inter-procedural: when calling a known function with tainted args,
       recurse into it (depth-limited)
"""

from __future__ import annotations

import ast
from typing import Optional

from agies.analyzer.config import LanguageAnalysisConfig
from agies.analyzer.models import (
    CallGraph,
    FunctionIR,
    SymbolTable,
    TaintPath,
    TaintStep,
)


def _expr_to_str(node: ast.expr) -> str | None:
    """Convert an expression to a dotted string for pattern matching.

    Examples:
        Name('x') -> 'x'
        Attribute(Name('sys'), 'argv') -> 'sys.argv'
        Subscript(Attribute(...), ...) -> 'sys.argv[?]'
        Call(Name('input'), []) -> 'input(...)'
    """
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        value = _expr_to_str(node.value)
        if value is not None:
            return f"{value}.{node.attr}"
        return None
    elif isinstance(node, ast.Subscript):
        value = _expr_to_str(node.value)
        if value is not None:
            return f"{value}[?]"
        return None
    elif isinstance(node, ast.Call):
        func = _expr_to_str(node.func)
        if func is not None:
            return f"{func}(...)"
        return None
    elif isinstance(node, ast.Constant):
        return repr(node.value)
    elif isinstance(node, ast.List):
        return "[...]"
    elif isinstance(node, ast.Dict):
        return "{...}"
    elif isinstance(node, ast.Tuple):
        return "(...)"
    elif isinstance(node, ast.BinOp):
        left = _expr_to_str(node.left)
        right = _expr_to_str(node.right)
        if left and right:
            return f"{left} {type(node.op).__name__} {right}"
        return None
    return None


def _extract_name(node: ast.expr) -> str | None:
    """Extract a simple variable name from an expression target."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        base = _extract_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return None
    return None


def _is_source(value: ast.expr, sources: list[str]) -> tuple[bool, str]:
    """Check if an expression matches any source pattern.

    Returns (is_source, source_name).
    """
    expr_str = _expr_to_str(value)
    if expr_str is None:
        return False, ""

    for src in sources:
        # Exact match: "sys.argv" == "sys.argv"
        if expr_str == src:
            return True, src
        # Prefix match: "sys.argv[1]" → expr "sys.argv[?]" starts with "sys.argv"
        if expr_str.startswith(src):
            return True, src
        # Function call match: input() → "input(...)" for source "input"
        if expr_str == f"{src}(...)":
            return True, src

    return False, ""


def _is_sink(call_str: str, sinks: dict[str, str]) -> tuple[bool, str]:
    """Check if a call name matches any sink pattern.

    Rules:
    - Exact match: eval == eval ✓
    - Dotted call matching non-dotted sink: obj.eval ends with .eval ✓
    - Dotted call matching dotted sink: os.system == os.system ✓
    - Bare name vs dotted sink: run != subprocess.run ✗

    Returns (is_sink, sink_name).
    """
    for sink_name in sinks:
        if call_str == sink_name:
            return True, sink_name
        # Dotted call like "obj.eval" matching non-dotted sink "eval"
        if "." in call_str and "." not in sink_name:
            if call_str.endswith("." + sink_name):
                return True, sink_name
        # Dotted call matching dotted sink
        if "." in call_str and "." in sink_name:
            if call_str == sink_name:
                return True, sink_name
    return False, ""


def _is_sanitizer(call_str: str, sanitizers: list[str]) -> bool:
    """Check if a call name matches a sanitizer pattern."""
    for san in sanitizers:
        if call_str == san or call_str.endswith("." + san):
            return True
    return False


def _call_name_from_ast(call_node: ast.Call) -> str | None:
    """Extract the function name from a Call AST node as a dotted string."""
    func = call_node.func
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


class TaintEngine:
    """Forward taint propagation engine."""

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

        # Map function qname -> FunctionIR for call resolution
        self._fn_map: dict[str, FunctionIR] = {}
        for fn_list in symbol_table.functions.values():
            for fn in fn_list:
                self._fn_map[fn.qualified_name] = fn

    def analyze(self) -> list[TaintPath]:
        """Run taint analysis on all functions and return paths."""
        self.taint_paths = []

        for fn_list in self.symbol_table.functions.values():
            if len(self.taint_paths) >= self.max_paths:
                break
            for fn in fn_list:
                if len(self.taint_paths) >= self.max_paths:
                    break
                if not fn.ast_body:
                    continue
                self._analyze_function(fn, {}, 0)

        return self.taint_paths

    def _analyze_function(
        self,
        fn: FunctionIR,
        pretainted: dict[str, TaintStep],
        depth: int,
    ) -> set[str]:
        """Analyze a function body forward, tracking taint.

        Args:
            fn: The function to analyze
            pretainted: Parameters pre-seeded as tainted (var_name -> step)
            depth: Current call depth for inter-procedural tracking

        Returns:
            Set of variable names that are tainted when the function exits
            (for inter-procedural propagation).
        """
        tainted: dict[str, TaintStep] = dict(pretainted)

        body = fn.ast_body
        if not body:
            return set()

        for stmt in body:
            self._handle_stmt(stmt, tainted, fn, depth)

        return set(tainted.keys())

    def _handle_stmt(
        self,
        stmt: ast.stmt,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> bool:
        """Handle a single statement. Returns True if handled."""
        if isinstance(stmt, ast.Assign):
            self._handle_assign(stmt, tainted, fn, depth)
            return True

        if isinstance(stmt, ast.AnnAssign):
            self._handle_assign_node(stmt.target, stmt.value, tainted, fn, depth)
            return True

        if isinstance(stmt, ast.AugAssign):
            self._handle_assign_node(stmt.target, stmt.value, tainted, fn, depth)
            return True

        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            self._process_call(stmt.value, tainted, fn, depth)
            return True

        if isinstance(stmt, ast.Return):
            return True

        if isinstance(stmt, ast.If):
            for sub_stmt in stmt.body:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            for sub_stmt in stmt.orelse:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            return True

        if isinstance(stmt, (ast.Try, ast.TryStar)):
            for sub_stmt in stmt.body:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            for handler in stmt.handlers:
                for sub_stmt in handler.body:
                    self._handle_stmt(sub_stmt, tainted, fn, depth)
            for sub_stmt in stmt.orelse:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            for sub_stmt in stmt.finalbody:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            return True

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            for sub_stmt in stmt.body:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            for sub_stmt in stmt.orelse:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            return True

        if isinstance(stmt, (ast.While,)):
            for sub_stmt in stmt.body:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            for sub_stmt in stmt.orelse:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            return True

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for sub_stmt in stmt.body:
                self._handle_stmt(sub_stmt, tainted, fn, depth)
            return True

        return False

    def _handle_assign(
        self,
        stmt: ast.Assign,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Handle an assignment statement."""
        if stmt.value is None:
            return

        # Check if RHS is a call that might be a source
        if isinstance(stmt.value, ast.Call):
            self._process_call(stmt.value, tainted, fn, depth)

        # Propagate taint to targets
        for target in stmt.targets:
            self._handle_assign_node(target, stmt.value, tainted, fn, depth)

    def _handle_assign_node(
        self,
        target: ast.expr,
        value: ast.expr | None,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Handle propagating taint to a single assignment target."""
        if value is None:
            return

        target_name = _extract_name(target)
        if target_name is None:
            return

        # 1. Direct source match
        is_src, src_name = _is_source(value, self._sources)
        if is_src:
            tainted[target_name] = TaintStep(
                file_path=fn.file_path,
                line=target.lineno if hasattr(target, "lineno") else 0,
                kind="source",
                variable_or_expr=target_name,
                detail=f"assigned from source: {src_name}",
            )
            return

        # 2. Propagation from tainted variable
        # Check if the value is a reference to a tainted variable
        val_name = _extract_name(value)
        if val_name:
            # Direct taint propagation
            if val_name in tainted:
                tainted[target_name] = TaintStep(
                    file_path=fn.file_path,
                    line=target.lineno if hasattr(target, "lineno") else 0,
                    kind="propagation",
                    variable_or_expr=target_name,
                    detail=f"propagated from {val_name}",
                )
                return
            # Also check dotted name parts
            parts = val_name.split(".")
            for i in range(len(parts) - 1):
                prefix = ".".join(parts[: i + 1])
                if prefix in tainted:
                    tainted[target_name] = TaintStep(
                        file_path=fn.file_path,
                        line=target.lineno if hasattr(target, "lineno") else 0,
                        kind="propagation",
                        variable_or_expr=target_name,
                        detail=f"propagated from {prefix}",
                    )
                    return

        # 3. Check if value contains a reference to a tainted variable
        for node in ast.walk(value):
            if isinstance(node, ast.Name) and node.id in tainted:
                tainted[target_name] = TaintStep(
                    file_path=fn.file_path,
                    line=target.lineno if hasattr(target, "lineno") else 0,
                    kind="propagation",
                    variable_or_expr=target_name,
                    detail=f"propagated from {node.id} in expression",
                )
                return

    def _process_call(
        self,
        call_node: ast.Call,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
    ) -> None:
        """Process a function call node: check sink, track return taint."""
        call_name = _call_name_from_ast(call_node)
        if call_name is None:
            return

        # Check if this call has any tainted arguments
        tainted_args: list[str] = []
        for arg in call_node.args:
            arg_name = _extract_name(arg)
            if arg_name and arg_name in tainted:
                tainted_args.append(arg_name)

        # Also check keyword arguments
        for kw in call_node.keywords:
            kw_name = _extract_name(kw.value)
            if kw_name and kw_name in tainted:
                tainted_args.append(kw_name)

        # Check if the call itself produces a source
        is_src, src_name = _is_source(
            call_node, self._sources
        ) if not tainted_args else (False, "")

        # Check sink
        is_sink, sink_name = _is_sink(call_name, self._sinks)
        if is_sink and tainted_args:
            self._emit_taint_path(
                taint_source=tainted[tainted_args[0]],
                sink_name=sink_name,
                call_node=call_node,
                call_name=call_name,
                fn=fn,
                tainted_args=tainted_args,
            )

        # Check sanitizer
        is_sanitizer = _is_sanitizer(call_name, self._sanitizers)

        # If args tainted, mark return value tainted (unless sanitizer)
        if not is_sanitizer and (tainted_args or is_src):
            # Mark the "result" as tainted if the call is used in an assignment
            pass  # The assignment handler catches this via the call node

        # Inter-procedural: recurse into known called function
        if tainted_args and depth < self.max_depth:
            self._inter_procedural_propagate(call_node, tainted, fn, depth, tainted_args)

    def _emit_taint_path(
        self,
        taint_source: TaintStep,
        sink_name: str,
        call_node: ast.Call,
        call_name: str,
        fn: FunctionIR,
        tainted_args: list[str],
    ) -> None:
        """Create and record a TaintPath."""
        path = TaintPath(
            source=taint_source,
            sink=TaintStep(
                file_path=fn.file_path,
                line=call_node.lineno,
                kind="sink",
                variable_or_expr=call_name,
                detail=f"call to {call_name} with tainted args: {', '.join(tainted_args)}",
            ),
            confidence="high",
            source_rule_name=taint_source.detail.replace("assigned from source: ", ""),
            sink_rule_name=sink_name,
        )
        # Deduplicate: check if we already have this exact sink line
        for existing in self.taint_paths:
            if (existing.sink.file_path == path.sink.file_path
                    and existing.sink.line == path.sink.line
                    and existing.sink.variable_or_expr == path.sink.variable_or_expr):
                return
        self.taint_paths.append(path)

    def _inter_procedural_propagate(
        self,
        call_node: ast.Call,
        tainted: dict[str, TaintStep],
        fn: FunctionIR,
        depth: int,
        tainted_args: list[str],
    ) -> None:
        """Try to follow taint through a function call (depth-limited)."""
        call_name = _call_name_from_ast(call_node)
        if call_name is None:
            return

        # Find the callee in our symbol table
        callee_fn = self._fn_map.get(call_name)
        if callee_fn is None:
            # Try partial match
            for qname, fn_ir in self._fn_map.items():
                if qname.endswith("." + call_name):
                    callee_fn = fn_ir
                    break
        if callee_fn is None or not callee_fn.ast_body:
            return

        # Map actual tainted args to formal parameters
        pretainted: dict[str, TaintStep] = {}
        for i, arg_node in enumerate(call_node.args):
            if i < len(callee_fn.params):
                arg_name = _extract_name(arg_node)
                if arg_name and arg_name in tainted:
                    param_name = callee_fn.params[i]
                    pretainted[param_name] = tainted[arg_name]

        if not pretainted:
            return

        # Recursive analysis
        self._analyze_function(callee_fn, pretainted, depth + 1)
