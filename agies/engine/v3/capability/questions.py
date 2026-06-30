"""Feature → Question mapping — auto-generate security questions.

When a Feature is detected, the system automatically generates
questions about trust boundaries, invariants, and state changes.

These questions are NOT vulnerabilities — they guide the LLM
to reason about the security implications of each feature.

Usage::

    bank = load_question_bank()
    questions = bank.for_feature("reference_expansion")
    for q in questions:
        print(q.question)
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_QUESTIONS_PATH = os.path.join(_DATA_DIR, "feature_questions.yaml")


@dataclass
class FeatureQuestion:
    """A security question generated when a Feature is detected."""

    id: str
    """Unique question identifier, e.g. ``"Q-REF-001"``."""

    question: str
    """The question to ask about this feature."""

    probes: list[dict[str, str]] = field(default_factory=list)
    """What this question probes: trust boundaries, invariants, state."""

    feature_id: str = ""
    """The feature ID this question belongs to (set by QuestionBank)."""


@dataclass
class QuestionBank:
    """Container for feature→question mappings."""

    mappings: dict[str, list[FeatureQuestion]] = field(default_factory=dict)
    """Feature ID → list of questions."""

    _all_questions: list[FeatureQuestion] = field(default_factory=list, repr=False)

    def for_feature(self, feature_id: str) -> list[FeatureQuestion]:
        """Get all questions for a given feature.

        Parameters
        ----------
        feature_id : str
            Feature identifier, e.g. ``"reference_expansion"``.

        Returns
        -------
        list[FeatureQuestion]
        """
        return self.mappings.get(feature_id, [])

    def for_features(self, feature_ids: list[str]) -> list[FeatureQuestion]:
        """Get questions for multiple features, deduplicated.

        Parameters
        ----------
        feature_ids : list[str]
            Feature identifiers.

        Returns
        -------
        list[FeatureQuestion]
        """
        seen: set[str] = set()
        results: list[FeatureQuestion] = []
        for fid in feature_ids:
            for q in self.mappings.get(fid, []):
                if q.id not in seen:
                    seen.add(q.id)
                    results.append(q)
        return results

    def all(self) -> list[FeatureQuestion]:
        """Get all questions in the bank."""
        return self._all_questions


def load_question_bank(path: str | None = None) -> QuestionBank:
    """Load the feature→question bank from a YAML file.

    Parameters
    ----------
    path : str or None
        Path to the YAML file.  If ``None``, uses the default
        ``data/feature_questions.yaml`` shipped with the package.

    Returns
    -------
    QuestionBank
    """
    path = path or _QUESTIONS_PATH
    if not os.path.isfile(path):
        logger.warning("Question bank not found: %s", path)
        return QuestionBank()

    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    mappings: dict[str, list[FeatureQuestion]] = {}
    all_questions: list[FeatureQuestion] = []

    for entry in raw.get("feature_questions", []):
        fid = entry.get("feature_id", "")
        questions = []
        for q_entry in entry.get("questions", []):
            q = FeatureQuestion(
                id=q_entry.get("id", ""),
                question=q_entry.get("question", ""),
                probes=q_entry.get("probes", []),
                feature_id=fid,
            )
            questions.append(q)
            all_questions.append(q)
        mappings[fid] = questions

    bank = QuestionBank(mappings=mappings, _all_questions=all_questions)
    q_count = len(all_questions)
    f_count = len(mappings)
    logger.info("Loaded %d questions for %d features from bank", q_count, f_count)
    return bank
