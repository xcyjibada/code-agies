"""Tree-sitter JavaScript/TypeScript CST parser → SourceFileIR.

Maps JS/TS AST nodes to the language-agnostic SourceFileIR format.
Supports both tree_sitter_javascript and tree_sitter_typescript.
"""

from __future__ import annotations

import os
from typing import Optional

from tree_sitter import Parser, Language, Node

from agies.analyzer.models import (
    ClassIR,
    FunctionIR,
    ImportIR,
    SourceFileIR,
)

_JS_LANG: Language | None = None
_TS_LANG: Language | None = None
_PARSER_CACHE: dict[str, Parser] = {}


def _get_parser(language: str = "javascript") -> Parser:
    """Get or create a parser for the given language."""
    global _JS_LANG, _TS_LANG
    if language not in _PARSER_CACHE:
        if language == "typescript":
            if _TS_LANG is None:
                import tree_sitter_typescript as tsts
                _TS_LANG = Language(tsts.language_typescript())
            _PARSER_CACHE["typescript"] = Parser(_TS_LANG)
        else:
            if _JS_LANG is None:
                import tree_sitter_javascript as tsjs
                _JS_LANG = Language(tsjs.language())
            _PARSER_CACHE["javascript"] = Parser(_JS_LANG)
    return _PARSER_CACHE[language]


def _node_text(node: Node, source: bytes) -> str:
    return node.text.decode("utf-8") if node.text else ""


def _qualified_name(context: list[str], name: str) -> str:
    if context:
        return ".".join(context) + "." + name
    return name


def _node_value(node: Node, source: bytes) -> str:
    """Get the text value of a node."""
    return _node_text(node, source)


def _get_identifier_text(node: Node, source: bytes) -> str:
    """Extract identifier text from various node types."""
    return _node_text(node, source)


def _extract_dotted_member(node: Node, source: bytes) -> str:
    """Convert a member_expression to a dotted string like 'req.query.name'."""
    parts: list[str] = []
    for child in node.children:
        if child.type == "identifier":
            parts.append(_node_text(child, source))
        elif child.type == "property_identifier":
            parts.append(_node_text(child, source))
        elif child.type == "member_expression":
            parts.append(_extract_dotted_member(child, source))
        elif child.type == "call_expression":
            # Call like obj.method() — just use the member expression part
            for gc in child.named_children:
                if gc.type == "member_expression":
                    parts.append(_extract_dotted_member(gc, source))
    return ".".join(p for p in parts if p)


def _get_call_name(node: Node, source: bytes) -> str:
    """Extract the call name from a call_expression.

    eval(x) -> 'eval'
    req.query.name -> 'req.query.name' or 'name'
    console.log(x) -> 'console.log'
    """
    for child in node.named_children:
        if child.type == "identifier":
            return _node_text(child, source)
        elif child.type == "member_expression":
            return _extract_dotted_member(child, source)
    return ""


def _get_call_line(node: Node) -> int:
    """Get the line number for a call_expression node."""
    return node.start_point[0] + 1 if node.start_point else 0


# ── Parsing helpers ──────────────────────────────────────────────────────

def _collect_identifiers_in_node(node: Node, source: bytes) -> list[str]:
    """Collect all variable references in a subtree."""
    names: list[str] = []

    def walk(n: Node) -> None:
        if n.type == "identifier":
            names.append(_node_text(n, source))
        for child in n.named_children:
            walk(child)

    walk(node)
    return names


def _get_formal_params(node: Node, source: bytes) -> list[str]:
    """Extract parameter names from formal_parameters."""
    params: list[str] = []
    for child in node.named_children:
        if child.type == "identifier":
            params.append(_node_text(child, source))
        elif child.type == "formal_parameters":
            # Handle nested params (destructuring)
            params.extend(_get_formal_params(child, source))
    return params


def _get_body_children(node: Node) -> list:
    """Get the statement-level children from a function body."""
    for child in node.named_children:
        if child.type == "statement_block":
            return list(child.children)
    return []


# ── File-level parsing ───────────────────────────────────────────────────

def _parse_require_call(node: Node, source: bytes, file_path: str) -> ImportIR | None:
    """Detect require('module') pattern."""
    if node.type != "call_expression":
        return None
    for child in node.named_children:
        if child.type == "identifier" and _node_text(child, source) == "require":
            for gc in node.named_children:
                if gc.type == "arguments":
                    for arg in gc.named_children:
                        if arg.type == "string":
                            module = _node_text(arg, source).strip("'\"")
                            return ImportIR(
                                module=module,
                                names=[(module.split("/")[-1] if "/" in module else module, None)],
                                line=node.start_point[0] + 1,
                                is_from=True,
                                file_path=file_path,
                            )
    return None


def _parse_import_statement(node: Node, source: bytes, file_path: str) -> list[ImportIR]:
    """Parse an ES module import statement.

    import x from 'y'
    import { a, b } from 'y'
    import * as x from 'y'
    """
    imports: list[ImportIR] = []
    module = ""
    names: list[tuple[str, Optional[str]]] = []

    for child in node.named_children:
        if child.type == "string":
            module = _node_text(child, source).strip("'\"")
        elif child.type == "import_clause":
            for clause_child in child.named_children:
                if clause_child.type == "identifier":
                    names.append((_node_text(clause_child, source), None))
                elif clause_child.type == "namespace_import":
                    names.append(("*", _get_first_identifier(clause_child, source)))
                elif clause_child.type == "named_imports":
                    for spec in clause_child.named_children:
                        if spec.type == "import_specifier":
                            name = _get_import_specifier_name(spec, source)
                            if name:
                                names.append(name)

    if module:
        imports.append(ImportIR(
            module=module,
            names=names,
            line=node.start_point[0] + 1,
            is_from=True if names else False,
            file_path=file_path,
        ))

    return imports


def _get_first_identifier(node: Node, source: bytes) -> str | None:
    for child in node.named_children:
        if child.type == "identifier":
            return _node_text(child, source)
    return None


def _get_import_specifier_name(node: Node, source: bytes) -> tuple[str, Optional[str]] | None:
    """Extract (name, alias) from an import_specifier like 'x as y'."""
    name = ""
    alias = None
    for child in node.named_children:
        if child.type == "identifier":
            if not name:
                name = _node_text(child, source)
            else:
                alias = _node_text(child, source)
    if name:
        return (name, alias)
    return None


def _add_to_ir(
    ir: SourceFileIR,
    functions: list[FunctionIR],
    classes: list[ClassIR],
    imports: list[ImportIR],
) -> None:
    """Add parsed symbols to the SourceFileIR."""
    ir.functions.extend(functions)
    ir.classes.extend(classes)
    ir.imports.extend(imports)


def parse_js_file(file_path: str, language: str = "javascript") -> SourceFileIR:
    """Parse a single JS/TS file into a SourceFileIR using tree-sitter."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        source_bytes = source.encode("utf-8")
    except (OSError, PermissionError) as e:
        return SourceFileIR(file_path=file_path, language=language, parse_error=str(e))

    try:
        parser = _get_parser(language)
    except ImportError as e:
        return SourceFileIR(file_path=file_path, language=language,
                            parse_error=f"tree-sitter-{language} not installed: {e}")

    tree = parser.parse(source_bytes)
    root = tree.root_node

    if root.type != "program":
        return SourceFileIR(file_path=file_path, language=language,
                            parse_error=f"unexpected root node type: {root.type}")

    ir = SourceFileIR(file_path=file_path, language=language)
    ir.line_count = source.count("\n") + 1 if source else 0
    scope_stack: list[str] = []
    module_exports: Optional[str] = None

    for top_level in root.named_children:
        _parse_top_level(top_level, ir, scope_stack, source_bytes, file_path)

    return ir


def _parse_top_level(
    node: Node,
    ir: SourceFileIR,
    scope_stack: list[str],
    source: bytes,
    file_path: str,
) -> None:
    """Parse a top-level statement from the program."""
    if node.type == "function_declaration":
        _parse_function_declaration(node, ir, scope_stack, source, file_path)

    elif node.type == "class_declaration":
        _parse_class_declaration(node, ir, scope_stack, source, file_path)

    elif node.type == "lexical_declaration":
        _parse_lexical_declaration(node, ir, scope_stack, source, file_path)

    elif node.type == "variable_declaration":
        _parse_lexical_declaration(node, ir, scope_stack, source, file_path)

    elif node.type == "expression_statement":
        for child in node.named_children:
            if child.type == "call_expression":
                imp = _parse_require_call(child, source, file_path)
                if imp:
                    ir.imports.append(imp)
            elif child.type in ("assignment_expression",):
                # Handle module.exports = ...
                lhs = ""
                for assign_child in child.named_children:
                    if assign_child.type == "member_expression":
                        lhs = _extract_dotted_member(assign_child, source)
                if lhs == "module.exports":
                    for assign_child in child.named_children:
                        if assign_child.type == "arrow_function":
                            _parse_arrow_as_function(
                                assign_child, "module.exports", ir, scope_stack, source, file_path, is_method=False
                            )

    elif node.type == "import_statement":
        imports = _parse_import_statement(node, source, file_path)
        ir.imports.extend(imports)

    elif node.type == "export_statement":
        # export default X or export function foo
        for child in node.named_children:
            if child.type == "function_declaration":
                _parse_function_declaration(child, ir, scope_stack, source, file_path)
            elif child.type == "class_declaration":
                _parse_class_declaration(child, ir, scope_stack, source, file_path)
            elif child.type == "lexical_declaration":
                _parse_lexical_declaration(child, ir, scope_stack, source, file_path)
            elif child.type == "identifier":
                # export default fnName — reference, not definition
                pass


def _parse_function_declaration(
    node: Node,
    ir: SourceFileIR,
    scope_stack: list[str],
    source: bytes,
    file_path: str,
) -> None:
    """Parse a function_declaration node."""
    func_name = ""
    params: list[str] = []
    body_children: list = []

    for child in node.named_children:
        if child.type == "identifier":
            func_name = _node_text(child, source)
        elif child.type == "formal_parameters":
            params = _get_formal_params(child, source)
        elif child.type == "statement_block":
            body_children = list(child.children)

    if not func_name:
        return

    qname = _qualified_name(scope_stack, func_name)
    is_method = bool(scope_stack)

    func_ir = FunctionIR(
        qualified_name=qname,
        file_path=file_path,
        line=node.start_point[0] + 1,
        params=params,
        is_method=is_method,
        class_name=scope_stack[-1] if is_method else None,
        ast_body=body_children,
    )
    ir.functions.append(func_ir)


def _parse_arrow_as_function(
    node: Node,
    func_name: str,
    ir: SourceFileIR,
    scope_stack: list[str],
    source: bytes,
    file_path: str,
    is_method: bool,
) -> None:
    """Parse an arrow_function as a named function."""
    if not func_name:
        return

    params: list[str] = []
    body_children: list = []

    for child in node.named_children:
        if child.type == "formal_parameters" or child.type == "identifier":
            if child.type == "identifier":
                params.append(_node_text(child, source))
            else:
                params = _get_formal_params(child, source)
        elif child.type == "statement_block":
            body_children = list(child.children)

    qname = _qualified_name(scope_stack, func_name)
    func_ir = FunctionIR(
        qualified_name=qname,
        file_path=file_path,
        line=node.start_point[0] + 1,
        params=params,
        is_method=is_method,
        class_name=scope_stack[-1] if is_method else None,
        ast_body=body_children,
    )
    ir.functions.append(func_ir)


def _parse_lexical_declaration(
    node: Node,
    ir: SourceFileIR,
    scope_stack: list[str],
    source: bytes,
    file_path: str,
) -> None:
    """Parse const/let/var that may contain function expressions or require() calls."""
    for child in node.named_children:
        if child.type == "variable_declarator":
            var_name = ""
            value_node: Node | None = None
            for vc in child.named_children:
                if vc.type == "identifier":
                    var_name = _node_text(vc, source)
                elif vc.type in ("arrow_function", "function", "call_expression"):
                    value_node = vc

            if not value_node:
                continue

            if value_node.type == "arrow_function":
                _parse_arrow_as_function(
                    value_node, var_name, ir, scope_stack, source, file_path,
                    is_method=bool(scope_stack),
                )
            elif value_node.type == "function":
                inner_name = var_name
                for fchild in value_node.named_children:
                    if fchild.type == "identifier":
                        inner_name = _node_text(fchild, source)

                qname = _qualified_name(scope_stack, inner_name)
                params: list[str] = []
                body_children: list = []
                for fchild in value_node.named_children:
                    if fchild.type == "formal_parameters":
                        params = _get_formal_params(fchild, source)
                    elif fchild.type == "statement_block":
                        body_children = list(fchild.children)

                ir.functions.append(FunctionIR(
                    qualified_name=qname,
                    file_path=file_path,
                    line=value_node.start_point[0] + 1,
                    params=params,
                    is_method=bool(scope_stack),
                    class_name=scope_stack[-1] if scope_stack else None,
                    ast_body=body_children,
                ))
            elif value_node.type == "call_expression":
                # Check for require('module') pattern
                imp = _parse_require_call(value_node, source, file_path)
                if imp:
                    ir.imports.append(imp)


def _parse_class_declaration(
    node: Node,
    ir: SourceFileIR,
    scope_stack: list[str],
    source: bytes,
    file_path: str,
) -> None:
    """Parse a class_declaration node."""
    class_name = ""
    class_body_node: Node | None = None

    for child in node.named_children:
        if child.type == "identifier":
            class_name = _node_text(child, source)
        elif child.type == "class_body":
            class_body_node = child

    if not class_name:
        return

    qname = _qualified_name(scope_stack, class_name)

    cls_ir = ClassIR(
        qualified_name=qname,
        file_path=file_path,
        line=node.start_point[0] + 1,
    )

    scope_stack.append(class_name)

    if class_body_node:
        for body_child in class_body_node.named_children:
            if body_child.type == "method_definition":
                method_name = ""
                method_params: list[str] = []
                method_body: list = []

                for mc in body_child.named_children:
                    if mc.type == "property_identifier":
                        method_name = _node_text(mc, source)
                    elif mc.type == "formal_parameters":
                        method_params = _get_formal_params(mc, source)
                    elif mc.type == "statement_block":
                        method_body = list(mc.children)

                if method_name:
                    method_qname = _qualified_name(scope_stack, method_name)
                    ir.functions.append(FunctionIR(
                        qualified_name=method_qname,
                        file_path=file_path,
                        line=body_child.start_point[0] + 1,
                        params=method_params,
                        is_method=True,
                        class_name=scope_stack[-1],
                        ast_body=method_body,
                    ))
                    cls_ir.methods.append(method_qname)

    scope_stack.pop()
    ir.classes.append(cls_ir)


def parse_files(
    target: str,
    language: str = "javascript",
    skip_dirs: Optional[set[str]] = None,
) -> list[SourceFileIR]:
    """Walk a directory and parse all JS/TS files into SourceFileIR list."""
    if skip_dirs is None:
        skip_dirs = {
            ".git", ".svn", "__pycache__", "node_modules", "venv",
            ".venv", "dist", "build", ".egg-info", "eggs",
        }

    extension = ".js" if language == "javascript" else ".ts"
    results: list[SourceFileIR] = []
    target = os.path.abspath(target)

    if os.path.isfile(target):
        if target.endswith(extension) or (language == "javascript" and target.endswith(".jsx")):
            lang = "typescript" if target.endswith((".ts", ".tsx")) else "javascript"
            results.append(parse_js_file(target, language=lang))
        return results

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in skip_dirs]
        for fname in files:
            if language == "javascript" and (fname.endswith(".js") or fname.endswith(".jsx")):
                fpath = os.path.join(root, fname)
                results.append(parse_js_file(fpath, language="javascript"))
            elif language == "typescript" and (fname.endswith(".ts") or fname.endswith(".tsx")):
                fpath = os.path.join(root, fname)
                results.append(parse_js_file(fpath, language="typescript"))

    return results
