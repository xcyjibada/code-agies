"""Static analysis engine: parser, symbol table, call graph, taint, and findings.

Multi-language support: auto-detects language per file and uses the
appropriate parser and taint engine.
"""

from __future__ import annotations

import os
from typing import Optional

from agies.analyzer.models import AnalysisResult, SourceFileIR
from agies.analyzer.config import AnalysisConfig, build_default_config
from agies.analyzer.parser import parse_files as parse_python_files
from agies.analyzer.symbol_table import SymbolTableBuilder
from agies.analyzer.call_graph import CallGraphBuilder
from agies.analyzer.taint import TaintEngine
from agies.analyzer.findings import augment_result

__all__ = [
    "Analyzer",
    "AnalysisResult",
    "AnalysisConfig",
    "build_default_config",
]


class Analyzer:
    """Top-level static analyzer. Orchestrates the full pipeline.

    Multi-language support: detects language per file and routes
    to the appropriate parser and taint engine.

    Usage:
        analyzer = Analyzer()
        result = analyzer.run("/path/to/project")
        for finding in result.findings:
            print(f"{result.severity}: {result.title}")
    """

    def __init__(self, config: Optional[AnalysisConfig] = None) -> None:
        self.config = config or build_default_config()

    def run(self, target: str, language: str = "auto") -> AnalysisResult:
        """Run the full static analysis pipeline on *target*.

        Args:
            target: File or directory to analyze.
            language: One of "auto", "python", "java", "javascript".
                      "auto" detects per file from extension.

        Returns an AnalysisResult with parsed files, call graph,
        taint paths, and findings.
        """
        result = AnalysisResult()

        # Step 1: Parse — collect files by language
        source_files = self._parse_files(target, language)
        for sf in source_files:
            if sf.parse_error:
                result.files_failed += 1
                result.errors.append(f"{sf.file_path}: {sf.parse_error}")
            else:
                result.files_parsed += 1
                result.functions_count += len(sf.functions)
                result.classes_count += len(sf.classes)

        if not source_files:
            result.errors.append("No source files found")
            return result

        # Step 2: Build symbol table
        builder = SymbolTableBuilder(source_files)
        symbol_table = builder.build()

        # Step 3: Build call graph
        cg_builder = CallGraphBuilder(source_files, symbol_table)
        call_graph = cg_builder.build()
        result.call_graph_edges = len(call_graph.edges)
        result.unresolved_calls = len(call_graph.unresolved_calls)

        # Step 4: Run taint analysis per language
        for lang_name in set(sf.language for sf in source_files if not sf.parse_error):
            lang_config = self.config.languages.get(lang_name)
            if lang_config is None:
                result.errors.append(f"No config for language: {lang_name}")
                continue

            if lang_name == "java":
                java_taint_cls = self._get_java_taint()
                if java_taint_cls is None:
                    result.errors.append("tree-sitter-java not installed; skipping Java taint analysis")
                    continue
                engine = java_taint_cls(
                    lang_config=lang_config,
                    symbol_table=symbol_table,
                    call_graph=call_graph,
                    max_depth=self.config.max_call_depth,
                    max_paths=self.config.max_taint_paths,
                )
            elif lang_name == "javascript":
                js_taint_cls = self._get_js_taint()
                if js_taint_cls is None:
                    result.errors.append("tree-sitter-javascript not installed; skipping JS taint analysis")
                    continue
                engine = js_taint_cls(
                    lang_config=lang_config,
                    symbol_table=symbol_table,
                    call_graph=call_graph,
                    max_depth=self.config.max_call_depth,
                    max_paths=self.config.max_taint_paths,
                )
            else:
                engine = TaintEngine(
                    lang_config=lang_config,
                    symbol_table=symbol_table,
                    call_graph=call_graph,
                    max_depth=self.config.max_call_depth,
                    max_paths=self.config.max_taint_paths,
                )

            result.taint_paths.extend(engine.analyze())

        # Step 5: Generate findings
        if result.taint_paths:
            augment_result(result, self.config)

        return result

    def _get_java_parser(self):
        """Lazy import of Java parser (optional dependency)."""
        try:
            from agies.analyzer.parser_java import parse_files as _jp
            return _jp
        except ImportError:
            return None

    def _get_java_taint(self):
        """Lazy import of Java taint engine (optional dependency)."""
        try:
            from agies.analyzer.taint_java import TaintEngineJava as _tj
            return _tj
        except ImportError:
            return None

    def _get_js_parser(self):
        """Lazy import of JS parser (optional dependency)."""
        try:
            from agies.analyzer.parser_js import parse_files as _jp
            return _jp
        except ImportError:
            return None

    def _get_js_taint(self):
        """Lazy import of JS taint engine (optional dependency)."""
        try:
            from agies.analyzer.taint_js import TaintEngineJS as _tj
            return _tj
        except ImportError:
            return None

    def _parse_files(self, target: str, language: str) -> list[SourceFileIR]:
        """Parse files in target, selecting parsers by language."""
        if language == "python":
            return parse_python_files(target)
        elif language == "java":
            java_parser = self._get_java_parser()
            if java_parser is None:
                return []
            return java_parser(target)
        elif language in ("javascript", "typescript"):
            js_parser = self._get_js_parser()
            if js_parser is None:
                return []
            return js_parser(target, language=language)
        elif language == "auto":
            # Group by extension and parse accordingly
            all_files: list[SourceFileIR] = []
            py_results = parse_python_files(target)
            all_files.extend(py_results)

            has_java = self._detect_java(target)
            if has_java:
                java_parser = self._get_java_parser()
                if java_parser:
                    java_results = java_parser(target)
                    seen_paths = {sf.file_path for sf in all_files if not sf.parse_error}
                    for jf in java_results:
                        if jf.file_path not in seen_paths:
                            all_files.append(jf)

            has_js = self._detect_js(target)
            if has_js:
                js_parser = self._get_js_parser()
                if js_parser:
                    js_results = js_parser(target, language="javascript")
                    seen_paths = {sf.file_path for sf in all_files if not sf.parse_error}
                    for jf in js_results:
                        if jf.file_path not in seen_paths:
                            all_files.append(jf)
            return all_files
        else:
            # Unsupported language
            return []

    @staticmethod
    def _detect_java(target: str) -> bool:
        """Quick check if the target contains .java files."""
        target = os.path.abspath(target)
        if os.path.isfile(target):
            return target.endswith(".java")
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if fname.endswith(".java"):
                    return True
        return False

    @staticmethod
    def _detect_js(target: str) -> bool:
        """Quick check if the target contains .js/.jsx/.ts/.tsx files."""
        target = os.path.abspath(target)
        if os.path.isfile(target):
            return target.endswith((".js", ".jsx", ".ts", ".tsx"))
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if fname.endswith((".js", ".jsx", ".ts", ".tsx")):
                    return True
        return False
