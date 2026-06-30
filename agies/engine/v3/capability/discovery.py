"""Capability Discovery Engine — AST-based business capability detection.

Scans source code and identifies product-level capabilities,
completely independent of dangerous API detection.

Pipeline::

    Source Code
         ↓
    Feature Pattern Matching (taxonomy.match_source)
         ↓
    Invariant Extraction (invariant_library.for_feature)
         ↓
    Question Generation (question_bank.for_feature)
         ↓
    CapabilityResult[features, invariants, questions]

Usage::

    from agies.engine.v3.capability.discovery import discover_capabilities

    results = discover_capabilities(function_index)
    for result in results:
        print(result.feature.name)
        for q in result.questions:
            print(f"  Q: {q.question}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agies.engine.v3.capability.taxonomy import (
    Feature,
    FeatureTaxonomy,
    load_taxonomy,
)
from agies.engine.v3.capability.invariants import (
    Invariant,
    InvariantLibrary,
    load_invariant_library,
)
from agies.engine.v3.capability.questions import (
    FeatureQuestion,
    QuestionBank,
    load_question_bank,
)

logger = logging.getLogger(__name__)


@dataclass
class CapabilityResult:
    """Result of capability discovery for a single code unit."""

    function_name: str
    """Name of the function/class analyzed."""

    file_path: str
    """Absolute path to the source file."""

    line_start: int = 0
    """Starting line number."""

    source_code: str = ""
    """Function/class source code."""

    features: list[Feature] = field(default_factory=list)
    """Detected business capabilities."""

    invariants: list[Invariant] = field(default_factory=list)
    """Security invariants relevant to these features."""

    questions: list[FeatureQuestion] = field(default_factory=list)
    """Auto-generated security questions for these features."""

    feature_ids: list[str] = field(default_factory=list)
    """Convenience: flat list of detected feature IDs."""

    def has_features(self) -> bool:
        """Whether any features were detected."""
        return len(self.features) > 0


class CapabilityDiscoveryEngine:
    """Engine that discovers business capabilities in source code.

    Uses FeatureTaxonomy pattern matching (no LLM) for the initial
    detection pass, then enriches with invariants and questions.
    """

    def __init__(
        self,
        taxonomy: FeatureTaxonomy | None = None,
        invariants: InvariantLibrary | None = None,
        questions: QuestionBank | None = None,
    ):
        self._taxonomy = taxonomy or load_taxonomy()
        self._invariants = invariants or load_invariant_library()
        self._questions = questions or load_question_bank()
        self._results: list[CapabilityResult] = []

    @property
    def results(self) -> list[CapabilityResult]:
        return list(self._results)

    def scan_source(self, function_name: str, source_code: str,
                    file_path: str = "", line_start: int = 0) -> CapabilityResult:
        """Scan a single function/class source for capabilities.

        Parameters
        ----------
        function_name : str
            Name of the function or class.
        source_code : str
            Source code of the function/class.
        file_path : str
            File path for context.
        line_start : int
            Starting line number.

        Returns
        -------
        CapabilityResult
        """
        # Match source code against feature detection patterns
        features = self._taxonomy.match_source(source_code)

        # Also match function name (catches cases where the function
        # name itself reveals the capability)
        name_features = self._taxonomy.match_function_name(function_name)
        seen_ids = {f.id for f in features}
        for nf in name_features:
            if nf.id not in seen_ids:
                features.append(nf)
                seen_ids.add(nf.id)

        # Collect invariants from matched features
        all_invariants: list[Invariant] = []
        seen_inv = set()
        for feat in features:
            for inv in self._invariants.for_feature(feat):
                if inv.id not in seen_inv:
                    all_invariants.append(inv)
                    seen_inv.add(inv.id)

        # Collect questions from matched features
        feature_ids = [f.id for f in features]
        questions = self._questions.for_features(feature_ids)

        result = CapabilityResult(
            function_name=function_name,
            file_path=file_path,
            line_start=line_start,
            source_code=source_code,
            features=features,
            invariants=all_invariants,
            questions=questions,
            feature_ids=feature_ids,
        )
        self._results.append(result)
        return result

    def scan_index(self, function_index) -> list[CapabilityResult]:
        """Scan all functions in a FunctionIndex for capabilities.

        Parameters
        ----------
        function_index : FunctionIndex
            The project's function index (from tree-sitter extraction).

        Returns
        -------
        list[CapabilityResult]
        """
        if not hasattr(function_index, "funcs"):
            logger.warning("FunctionIndex has no 'funcs' attribute")
            return []

        count_before = len(self._results)
        for fn in function_index.funcs:
            body = fn.body or ""
            if not body.strip():
                continue
            self.scan_source(
                function_name=fn.name,
                source_code=body,
                file_path=fn.file_path,
                line_start=fn.line_start,
            )

        new_results = self._results[count_before:]
        logger.info(
            "Capability scan: %d functions → %d capability results",
            len(function_index.funcs), len(new_results),
        )
        return new_results


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def discover_capabilities(
    function_index=None,
    source_entries: list[tuple[str, str, str, int]] | None = None,
) -> list[CapabilityResult]:
    """Discover business capabilities in source code.

    Parameters
    ----------
    function_index : FunctionIndex, optional
        Project function index for batch scanning.
    source_entries : list of (name, source, filepath, lineno), optional
        Explicit source code entries to scan.

    Returns
    -------
    list[CapabilityResult]
    """
    engine = CapabilityDiscoveryEngine()

    if function_index is not None:
        return engine.scan_index(function_index)

    if source_entries:
        for name, source, fpath, lineno in source_entries:
            engine.scan_source(name, source, fpath, lineno)
        return engine.results

    logger.warning("No input provided to discover_capabilities")
    return []
