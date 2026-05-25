"""Python source file parser: AST -> SourceFileIR."""

from __future__ import annotations

import ast
import os
from typing import Optional

from agies.analyzer.models import (
    ClassIR,
    FunctionIR,
    ImportIR,
    SourceFileIR,
)


def _extract_decorator_text(node: ast.expr) -> str:
    """Convert a decorator AST node to its string representation."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return _extract_decorator_text(node.value) + "." + node.attr
    elif isinstance(node, ast.Call):
        return _extract_decorator_text(node.func)
    return f"<decorator at line {getattr(node, 'lineno', 0)}>"


def _qualified_name(context: list[str], name: str) -> str:
    """Build qualified name from context path + name."""
    if context:
        return ".".join(context) + "." + name
    return name


class _IRBuilder(ast.NodeVisitor):
    """AST visitor that builds SourceFileIR for one file."""

    def __init__(self, file_path: str, source: str) -> None:
        self.file_path = file_path
        self.source = source
        self.source_file = SourceFileIR(file_path=file_path)
        self.source_file.line_count = source.count("\n") + 1
        self._scope_stack: list[str] = []  # class/function nesting for qualified names

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_function(node, is_method=bool(self._scope_stack))

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_function(node, is_method=bool(self._scope_stack))

    def _handle_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_method: bool) -> None:
        qname = _qualified_name(self._scope_stack, node.name)
        params = [arg.arg for arg in node.args.args]
        decorators = [_extract_decorator_text(d) for d in node.decorator_list]

        func_ir = FunctionIR(
            qualified_name=qname,
            file_path=self.file_path,
            line=node.lineno,
            column=node.col_offset,
            params=params,
            decorators=decorators,
            is_method=is_method,
            class_name=self._scope_stack[-1] if is_method else None,
            ast_body=node.body,
        )
        self.source_file.functions.append(func_ir)

        self._scope_stack.append(node.name)
        self.generic_visit(node)  # visit nested defs
        self._scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qname = _qualified_name(self._scope_stack, node.name)
        bases = [_extract_decorator_text(b) for b in node.bases]

        class_ir = ClassIR(
            qualified_name=qname,
            file_path=self.file_path,
            line=node.lineno,
            bases=bases,
        )
        self.source_file.classes.append(class_ir)

        self._scope_stack.append(node.name)
        self.generic_visit(node)  # visit methods
        self._scope_stack.pop()

        # Collect method qualified names
        for stmt in node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_qname = _qualified_name([qname], stmt.name)
                class_ir.methods.append(method_qname)

    def visit_Import(self, node: ast.Import) -> None:
        names = [(alias.name, alias.asname) for alias in node.names]
        import_ir = ImportIR(
            module=node.names[0].name,
            names=names,
            line=node.lineno,
            is_from=False,
            file_path=self.file_path,
        )
        self.source_file.imports.append(import_ir)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        names = [(alias.name, alias.asname) for alias in node.names]
        import_ir = ImportIR(
            module=node.module,
            names=names,
            line=node.lineno,
            is_from=True,
            file_path=self.file_path,
        )
        self.source_file.imports.append(import_ir)


def parse_file(file_path: str) -> SourceFileIR:
    """Parse a single Python file into a SourceFileIR."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except (OSError, PermissionError) as e:
        ir = SourceFileIR(file_path=file_path, parse_error=str(e))
        return ir

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        ir = SourceFileIR(file_path=file_path, parse_error=f"syntax error: {e}")
        return ir

    builder = _IRBuilder(file_path, source)
    builder.visit(tree)

    # Set function class_name from class methods list
    class_map = {}
    for cls in builder.source_file.classes:
        for m_qname in cls.methods:
            class_map[m_qname] = cls.qualified_name
    for fn in builder.source_file.functions:
        if fn.qualified_name in class_map:
            fn.class_name = class_map[fn.qualified_name]
            fn.is_method = True

    return builder.source_file


def parse_files(
    target: str,
    skip_dirs: Optional[set[str]] = None,
) -> list[SourceFileIR]:
    """Walk a directory and parse all Python files into SourceFileIR list."""
    if skip_dirs is None:
        skip_dirs = {
            ".git", ".svn", "__pycache__", "node_modules", "venv",
            ".venv", "dist", "build", ".egg-info", "eggs",
        }

    results: list[SourceFileIR] = []
    target = os.path.abspath(target)

    if os.path.isfile(target):
        if target.endswith(".py"):
            results.append(parse_file(target))
        return results

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in skip_dirs]
        for fname in files:
            if fname.endswith(".py"):
                fpath = os.path.join(root, fname)
                results.append(parse_file(fpath))

    return results
