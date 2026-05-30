"""Tree-sitter based SAST pattern matching engine.

Usage::

    matcher = SASTMatcher()
    matcher.load_rules("agies/engine/rules")

    # On a source string (e.g. from a SourceFunction)
    results = matcher.match_source('print(eval(user_input))', "python")

    # On a file
    results = matcher.match_file("src/db.py")

    # On a SourceFunction
    results = matcher.match_function(fn)
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any

from agies.engine.v2.sast import MatchResult, SASTRule, confidence_from_severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Global matcher singleton
# ---------------------------------------------------------------------------

_global_matcher: SASTMatcher | None = None


def get_matcher(rules_dir: str | None = None) -> SASTMatcher:
    """Return a shared SASTMatcher singleton.

    The matcher is initialized once with rules from *rules_dir* (defaults to
    ``agies/engine/rules`` relative to this file).
    """
    global _global_matcher
    if _global_matcher is not None:
        return _global_matcher

    if rules_dir is None:
        rules_dir = str(Path(__file__).resolve().parent.parent / "rules")

    _global_matcher = SASTMatcher()
    _global_matcher.load_rules(rules_dir)
    return _global_matcher


# ---------------------------------------------------------------------------
# Parser cache (reuse extractor's lazy-init)
# ---------------------------------------------------------------------------

_parsers: dict[str, Any] = {}


def _get_lang(lang_id: str) -> Any:
    """Return a tree-sitter Language for *lang_id* (cached)."""
    if lang_id not in _parsers:
        if lang_id == "python":
            import tree_sitter_python as tspy
            _parsers[lang_id] = __import__("tree_sitter").Language(tspy.language())
        elif lang_id == "java":
            import tree_sitter_java as tsjava
            _parsers[lang_id] = __import__("tree_sitter").Language(tsjava.language())
        elif lang_id == "javascript":
            import tree_sitter_javascript as tsjs
            _parsers[lang_id] = __import__("tree_sitter").Language(tsjs.language())
        elif lang_id == "typescript":
            import tree_sitter_typescript as tsts
            _parsers[lang_id] = __import__("tree_sitter").Language(
                tsts.language_typescript()
            )
        else:
            raise ValueError(f"Unsupported language: {lang_id}")
    return _parsers[lang_id]


def _get_parser(lang_id: str) -> Any:
    """Return a tree-sitter Parser for *lang_id*."""
    lang = _get_lang(lang_id)
    return __import__("tree_sitter").Parser(lang)


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------


def load_rules_from_dir(rules_dir: str) -> list[SASTRule]:
    """Load all ``.yaml`` / ``.yml`` rule files from *rules_dir* (recursive)."""
    import yaml

    rules: list[SASTRule] = []
    base = Path(rules_dir)
    if not base.is_dir():
        logger.warning("SAST rules dir not found: %s", rules_dir)
        return rules

    for yaml_path in sorted(base.rglob("*.yaml")) + sorted(base.rglob("*.yml")):
        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f)
        except Exception as exc:
            logger.warning("SAST: skipping bad rule file %s: %s", yaml_path, exc)
            continue

        if not data:
            continue

        # Single rule or list of rules
        items = data if isinstance(data, list) else [data]
        for item in items:
            try:
                rules.append(SASTRule(**item))
            except Exception as exc:
                logger.warning(
                    "SAST: skipping invalid rule in %s: %s", yaml_path, exc
                )
    return rules


# ---------------------------------------------------------------------------
# Language helper
# ---------------------------------------------------------------------------

_EXT_TO_LANG = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


def _ext_to_lang(path: str) -> str:
    """Map a file path to a language id."""
    ext = os.path.splitext(path)[1].lower()
    return _EXT_TO_LANG.get(ext, "")


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------


class SASTMatcher:
    """Tree-sitter based pattern matching engine.

    Maintains a compiled rule set and runs them against source code.
    Rules are grouped by language and compiled once on load.
    """

    def __init__(self, rules: list[SASTRule] | None = None) -> None:
        self._rules: list[SASTRule] = rules or []
        self._compiled: dict[str, list[tuple[SASTRule, Any]]] = {}
        """language → [(rule, compiled_query)]"""
        self._rebuild_compiled()

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: SASTRule) -> None:
        """Register a single rule."""
        self._rules.append(rule)
        self._rebuild_compiled()

    def load_rules(self, rules_dir: str) -> None:
        """Load all rule YAML files from *rules_dir*."""
        loaded = load_rules_from_dir(rules_dir)
        self._rules.extend(loaded)
        self._rebuild_compiled()
        logger.info("SASTMatcher: loaded %d rules from %s", len(loaded), rules_dir)

    def _rebuild_compiled(self) -> None:
        """Compile all queries grouped by language."""
        from tree_sitter import Query

        self._compiled.clear()
        for rule in self._rules:
            lang = rule.language
            if lang not in self._compiled:
                self._compiled[lang] = []
            try:
                ts_lang = _get_lang(lang)
                query = Query(ts_lang, rule.query)
                self._compiled[lang].append((rule, query))
            except Exception as exc:
                logger.warning(
                    "SASTMatcher: failed to compile rule '%s': %s",
                    rule.id,
                    exc,
                )

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match_source(
        self,
        source: str,
        language: str,
        file_path: str = "",
    ) -> list[MatchResult]:
        """Run all rules for *language* against *source* string."""
        if language not in self._compiled:
            return []

        from tree_sitter import QueryCursor

        source_bytes = source.encode("utf-8")
        parser = _get_parser(language)
        tree = parser.parse(source_bytes)
        results: list[MatchResult] = []

        for rule, query in self._compiled[language]:
            cursor = QueryCursor(query)
            for _pattern_idx, cap in cursor.matches(tree.root_node):
                nodes = cap.get(rule.capture_group)
                if not nodes:
                    continue
                for node in nodes:
                    text = (
                        node.text.decode("utf-8")
                        if node.text
                        else ""
                    )
                    # Apply match_any filter
                    if rule.match_any is not None and text not in rule.match_any:
                        continue
                    results.append(
                        MatchResult(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            language=language,
                            file_path=file_path,
                            line_number=node.start_point[0] + 1,
                            column=node.start_point[1],
                            matched_text=text[:200],
                            message=rule.message,
                            cwe=list(rule.cwe),
                        )
                    )

        return results

    def match_file(
        self,
        file_path: str,
        language: str = "",
    ) -> list[MatchResult]:
        """Run rules against a source file."""
        if not language:
            language = _ext_to_lang(file_path)
            if not language:
                return []

        try:
            with open(file_path, "rb") as f:
                raw = f.read()
        except OSError as exc:
            logger.warning("SASTMatcher: can't read %s: %s", file_path, exc)
            return []

        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            return []

        return self.match_source(source, language, file_path=file_path)

    def match_function(
        self,
        fn: Any,
    ) -> list[MatchResult]:
        """Run rules against a SourceFunction or similar object.

        Expects ``fn`` to have ``.body``, ``.file_path`` (or no file_path
        when body alone was provided), and the language is inferred from
        the file extension.
        """
        file_path = getattr(fn, "file_path", "") or ""
        language = _ext_to_lang(file_path)
        if not language and hasattr(fn, "body"):
            # No file → treat as generic source
            source = fn.body
            return self.match_source(source, "python", file_path=file_path)
        if not language:
            return []
        return self.match_file(file_path, language)
