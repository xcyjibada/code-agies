"""Pydantic data models for static analysis IR, call graph, taint, and findings."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


# ── Location ────────────────────────────────────────────────────────────

class Location(BaseModel):
    """Source code location."""
    file_path: str
    line: int = 1
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def short_str(self) -> str:
        if self.end_line and self.end_line != self.line:
            return f"{self.file_path}:{self.line}-{self.end_line}"
        return f"{self.file_path}:{self.line}"


# ── Source Code IR ──────────────────────────────────────────────────────

class FunctionIR(BaseModel):
    """Intermediate representation of a function/method definition."""
    qualified_name: str
    file_path: str
    line: int
    column: int = 0
    params: list[str] = []
    decorators: list[str] = []
    is_method: bool = False
    class_name: Optional[str] = None
    ast_body: list = []  # list[ast.stmt] — transient, excluded from serialization

    model_config = {"arbitrary_types_allowed": True}


class ClassIR(BaseModel):
    """Intermediate representation of a class definition."""
    qualified_name: str
    file_path: str
    line: int
    bases: list[str] = []
    methods: list[str] = []


class ImportIR(BaseModel):
    """Intermediate representation of an import statement."""
    module: str
    names: list[tuple[str, Optional[str]]] = []  # (name, alias)
    line: int = 0
    is_from: bool = False
    file_path: str = ""


class SourceFileIR(BaseModel):
    """Intermediate representation of a parsed source file."""
    file_path: str
    language: str = "python"
    functions: list[FunctionIR] = []
    classes: list[ClassIR] = []
    imports: list[ImportIR] = []
    line_count: int = 0
    parse_error: Optional[str] = None


# ── Symbol Table ────────────────────────────────────────────────────────

class SymbolTable(BaseModel):
    """Flat index of all symbols across parsed files."""
    files: dict[str, SourceFileIR] = {}
    functions: dict[str, list[FunctionIR]] = {}   # qualified_name -> list (overloads)
    classes: dict[str, list[ClassIR]] = {}
    unresolved_names: list[tuple[str, str, int]] = []  # (file_path, name, line)


# ── Call Graph ──────────────────────────────────────────────────────────

class CallGraphNode(BaseModel):
    """A node in the call graph (a function or method)."""
    qualified_name: str
    file_path: str
    line: int


class CallGraphEdge(BaseModel):
    """An edge in the call graph (caller -> callee)."""
    caller_qname: str
    callee_qname: str
    call_line: int
    resolved: bool = True


class CallGraph(BaseModel):
    """Complete call graph for the analyzed project."""
    nodes: dict[str, CallGraphNode] = {}
    edges: list[CallGraphEdge] = []
    unresolved_calls: list[tuple[str, str, int]] = []  # (file, call_text, line)


# ── Taint ───────────────────────────────────────────────────────────────

class TaintStep(BaseModel):
    """A single step in a taint propagation path."""
    file_path: str
    line: int
    kind: str  # "source", "propagation", "sink", "sanitizer"
    variable_or_expr: str = ""
    detail: str = ""


class TaintPath(BaseModel):
    """A complete source-to-sink taint flow."""
    source: TaintStep
    propagation_steps: list[TaintStep] = []
    sink: TaintStep
    confidence: str = "medium"  # high / medium / low
    call_depth: int = 0
    source_rule_name: str = ""
    sink_rule_name: str = ""


# ── Findings ────────────────────────────────────────────────────────────

class AnalyzerFinding(BaseModel):
    """A structured finding from static analysis."""
    rule_id: str
    severity: str  # critical / high / medium / low / info
    title: str
    description: str
    file_path: str
    line_number: int
    taint_path: Optional[TaintPath] = None
    call_chain: list[tuple[str, int]] = []  # (file_path, line) sequence
    suggestion: str = ""


# ── Top-level Result ────────────────────────────────────────────────────

class AnalysisResult(BaseModel):
    """Top-level result from a full analyzer run."""
    files_parsed: int = 0
    files_failed: int = 0
    functions_count: int = 0
    classes_count: int = 0
    call_graph_edges: int = 0
    unresolved_calls: int = 0
    taint_paths: list[TaintPath] = []
    findings: list[AnalyzerFinding] = []
    errors: list[str] = []
