"""Tree-sitter Java CST parser → SourceFileIR.

Maps Java AST nodes to the language-agnostic SourceFileIR format
so the existing symbol table, call graph, and taint pipeline can consume them.
"""

from __future__ import annotations

import os
from typing import Optional

from tree_sitter import Parser, Language, Node

import tree_sitter_java as tsjava

from agies.analyzer.models import (
    ClassIR,
    FunctionIR,
    ImportIR,
    SourceFileIR,
)

_LANG: Language | None = None
_PARSER: Parser | None = None


def _get_parser() -> Parser:
    global _LANG, _PARSER
    if _PARSER is None:
        _LANG = Language(tsjava.language())
        _PARSER = Parser(_LANG)
    return _PARSER


def _node_text(node: Node, source: bytes) -> str:
    return node.text.decode("utf-8") if node.text else ""


def _build_dotted(node: Node, source: bytes) -> str:
    """Walk a scoped_identifier tree and produce 'java.util.List'."""
    if node.type == "identifier" or (node.type == "."):
        return _node_text(node, source)
    parts = []
    for child in node.children:
        if child.type == ".":
            parts.append(".")
        else:
            parts.append(_build_dotted(child, source))
    return "".join(parts)


def _extract_dotted_from_import(node: Node, source: bytes) -> str:
    """Extract the dotted module name from an import_declaration's scoped_identifier."""
    for child in node.named_children:
        if child.type == "scoped_identifier":
            return _build_dotted(child, source)
    return ""


def _get_annotation_names(modifiers_node: Node, source: bytes) -> list[str]:
    """Extract annotation names from a method_declaration's modifiers."""
    names: list[str] = []
    for child in modifiers_node.children:
        if child.type == "marker_annotation":
            for gc in child.named_children:
                if gc.type == "identifier":
                    names.append(_node_text(gc, source))
        elif child.type == "normal_annotation":
            for gc in child.named_children:
                if gc.type == "identifier":
                    names.append(_node_text(gc, source))
        elif child.type == "single_member_annotation":
            for gc in child.named_children:
                if gc.type == "identifier":
                    names.append(_node_text(gc, source))
    return names


def _get_class_name(node: Node, source: bytes) -> str:
    for child in node.named_children:
        if child.type == "identifier":
            return _node_text(child, source)
    return "<anonymous>"


def _get_superclass(node: Node, source: bytes) -> str | None:
    for child in node.children:
        if child.type == "superclass":
            for gc in child.named_children:
                if gc.type in ("type_identifier", "scoped_identifier"):
                    return _build_dotted(gc, source) if gc.type == "scoped_identifier" else _node_text(gc, source)
    return None


def _get_method_name(node: Node, source: bytes) -> str | None:
    for child in node.named_children:
        if child.type == "identifier":
            return _node_text(child, source)
    return None


def _get_params(node: Node, source: bytes) -> list[str]:
    for child in node.named_children:
        if child.type == "formal_parameters":
            params: list[str] = []
            for gc in child.named_children:
                if gc.type == "formal_parameter":
                    param_name = ""
                    for param_child in gc.named_children:
                        if param_child.type == "identifier":
                            param_name = _node_text(param_child, source)
                            break
                    if param_name:
                        params.append(param_name)
            return params
    return []


def _get_modifiers(node: Node) -> Node | None:
    for child in node.children:
        if child.type == "modifiers":
            return child
    return None


def _get_body_children(node: Node) -> list[Node]:
    """Get the statement-level children from a method's block."""
    for child in node.named_children:
        if child.type == "block":
            return list(child.children)
    return []


def _qualified_name(context: list[str], name: str) -> str:
    if context:
        return ".".join(context) + "." + name
    return name


def _collect_interface_types(node: Node, source: bytes) -> list[str]:
    """Extract implement/interface type names from a class_declaration."""
    types: list[str] = []
    for child in node.children:
        if child.type == "interfaces":
            for gc in child.named_children:
                if gc.type in ("type_list",):
                    for tc in gc.named_children:
                        if tc.type in ("type_identifier", "scoped_identifier"):
                            types.append(_build_dotted(tc, source) if tc.type == "scoped_identifier" else _node_text(tc, source))
    return types


def parse_java_file(file_path: str) -> SourceFileIR:
    """Parse a single Java file into a SourceFileIR using tree-sitter."""
    source_bytes: bytes = b""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        source_bytes = source.encode("utf-8")
    except (OSError, PermissionError) as e:
        return SourceFileIR(file_path=file_path, language="java", parse_error=str(e))

    parser = _get_parser()
    tree = parser.parse(source_bytes)
    root = tree.root_node

    if root.type != "program":
        return SourceFileIR(file_path=file_path, language="java",
                            parse_error=f"unexpected root node type: {root.type}")

    ir = SourceFileIR(file_path=file_path, language="java")
    ir.line_count = source.count("\n") + 1 if source else 0
    scope_stack: list[str] = []

    for top_level in root.named_children:
        if top_level.type == "import_declaration":
            module = _extract_dotted_from_import(top_level, source_bytes)
            if module:
                ir.imports.append(ImportIR(
                    module=module,
                    names=[(module.split(".")[-1] if "." in module else module, None)],
                    line=top_level.start_point[0] + 1,
                    is_from=False,
                    file_path=file_path,
                ))
                # Also add a from-import style for easier resolution
                if "." in module:
                    ir.imports.append(ImportIR(
                        module=".".join(module.split(".")[:-1]),
                        names=[(module.split(".")[-1], None)],
                        line=top_level.start_point[0] + 1,
                        is_from=True,
                        file_path=file_path,
                    ))

        elif top_level.type == "class_declaration":
            _parse_class_declaration(top_level, ir, scope_stack, source_bytes, file_path)

    return ir


def _parse_class_declaration(
    node: Node,
    ir: SourceFileIR,
    scope_stack: list[str],
    source: bytes,
    file_path: str,
) -> None:
    """Parse a class_declaration node and add to SourceFileIR."""
    class_name = _get_class_name(node, source)
    qname = _qualified_name(scope_stack, class_name)
    bases: list[str] = []
    superclass = _get_superclass(node, source)
    if superclass:
        bases.append(superclass)
    bases.extend(_collect_interface_types(node, source))

    cls_ir = ClassIR(
        qualified_name=qname,
        file_path=file_path,
        line=node.start_point[0] + 1,
        bases=bases,
    )

    scope_stack.append(class_name)

    # Find class_body
    for child in node.named_children:
        if child.type == "class_body":
            for body_child in child.named_children:
                if body_child.type == "method_declaration":
                    _parse_method(body_child, ir, scope_stack, source, file_path, cls_ir)
                elif body_child.type == "class_declaration":
                    # Nested class
                    _parse_class_declaration(body_child, ir, scope_stack, source, file_path)
                elif body_child.type == "constructor_declaration":
                    _parse_constructor(body_child, ir, scope_stack, source, file_path, cls_ir)

    scope_stack.pop()
    ir.classes.append(cls_ir)


def _parse_method(
    node: Node,
    ir: SourceFileIR,
    scope_stack: list[str],
    source: bytes,
    file_path: str,
    cls_ir: ClassIR,
) -> None:
    """Parse a method_declaration into FunctionIR."""
    method_name = _get_method_name(node, source)
    if not method_name:
        return

    qname = _qualified_name(scope_stack, method_name)
    params = _get_params(node, source)
    modifiers_node = _get_modifiers(node)
    annotations: list[str] = []
    if modifiers_node:
        annotations = _get_annotation_names(modifiers_node, source)

    body_children = _get_body_children(node)

    func_ir = FunctionIR(
        qualified_name=qname,
        file_path=file_path,
        line=node.start_point[0] + 1,
        column=node.start_point[1],
        params=params,
        decorators=annotations,
        is_method=True,
        class_name=scope_stack[-1] if scope_stack else None,
        ast_body=body_children,
    )
    ir.functions.append(func_ir)
    cls_ir.methods.append(qname)


def _parse_constructor(
    node: Node,
    ir: SourceFileIR,
    scope_stack: list[str],
    source: bytes,
    file_path: str,
    cls_ir: ClassIR,
) -> None:
    """Parse a constructor_declaration into FunctionIR (named <init>)."""
    method_name = "<init>"
    qname = _qualified_name(scope_stack, method_name)
    params = _get_params(node, source)
    modifiers_node = _get_modifiers(node)
    annotations: list[str] = []
    if modifiers_node:
        annotations = _get_annotation_names(modifiers_node, source)

    body_children = _get_body_children(node)

    func_ir = FunctionIR(
        qualified_name=qname,
        file_path=file_path,
        line=node.start_point[0] + 1,
        column=node.start_point[1],
        params=params,
        decorators=annotations,
        is_method=True,
        class_name=scope_stack[-1] if scope_stack else None,
        ast_body=body_children,
    )
    ir.functions.append(func_ir)
    cls_ir.methods.append(qname)


def parse_files(
    target: str,
    skip_dirs: Optional[set[str]] = None,
) -> list[SourceFileIR]:
    """Walk a directory and parse all Java files into SourceFileIR list."""
    if skip_dirs is None:
        skip_dirs = {
            ".git", ".svn", "__pycache__", "node_modules", "venv",
            ".venv", "dist", "build", ".egg-info", "eggs",
        }

    results: list[SourceFileIR] = []
    target = os.path.abspath(target)

    if os.path.isfile(target):
        if target.endswith(".java"):
            results.append(parse_java_file(target))
        return results

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in skip_dirs]
        for fname in files:
            if fname.endswith(".java"):
                fpath = os.path.join(root, fname)
                results.append(parse_java_file(fpath))

    return results
