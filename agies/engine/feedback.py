"""Cross-scan feedback loop — persistent learning for Director PageRank.

P5: When the verification agent confirms a vulnerability or repeatedly
judges a SAST signal as false positive, that information persists in
``.agies/feedback.json`` so the Director gives higher/lower weight to
relevant functions on subsequent scans.

Usage::

    store = FeedbackStore.load("/project/.agies/feedback.json")

    # Record after verification
    for finding in state.verified_findings:
        if finding.get("triggerable") or finding.get("verified"):
            store.add_confirmed_vuln(finding.get("function_name", ""))
        if not finding.get("triggerable"):
            rule_ids = _extract_sast_rules(finding)
            for rid in rule_ids:
                store.add_false_positive(finding.get("file_path", ""), rid)

    # Apply to Director
    director = Director(project_path, feedback_store=store)
    cards = director.run()
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIRMED_BOOST: float = 5.0
"""PageRank edge-weight multiplier for a function whose name matches a
previously confirmed vulnerability."""

FP_SUPPRESS_MUL: float = 0.3
"""Signal multiplier applied to every signal tag in a file that has been
repeatedly flagged as false positive."""

FP_THRESHOLD: int = 2
"""Minimum false-positive counts before suppression activates."""

# ---------------------------------------------------------------------------
# SAST rule extraction
# ---------------------------------------------------------------------------

_SAST_PATTERN = re.compile(r"\[SAST:([^\]]+)\]")


def _extract_sast_rules(finding: dict[str, Any]) -> list[str]:
    """Extract SAST rule IDs from a verified finding's evidence field.

    Handles both list and string formats:

    - List: ``["[SAST:py-eval-exec] eval test (line 1, severity=critical)"]``
    - String: ``"[SAST:py-eval-exec] eval test (line 1, severity=critical)"``
    """
    evidence = finding.get("evidence")
    if not evidence:
        return []

    if isinstance(evidence, list):
        text = " ".join(str(e) for e in evidence)
    else:
        text = str(evidence)

    return _SAST_PATTERN.findall(text)


# ---------------------------------------------------------------------------
# FeedbackStore
# ---------------------------------------------------------------------------


@dataclass
class FeedbackStore:
    """Persistent cross-scan feedback that adjusts future Director PageRank.

    Two mechanisms:

    1. **Confirmed vulns** — function names verified as triggerable get a
       ``CONFIRMED_BOOST`` (5x) multiplier on PageRank edge weights.

    2. **False positives** — when a SAST rule fires in a specific file and
       the verification agent repeatedly judges it false positive, the file
       enters the ``suppressed`` set and all its signal tags get a
       ``FP_SUPPRESS_MUL`` (0.3x) multiplier.

    JSON format on disk::

        {
          "confirmed_idents": {"execute_query": 2, "parse_data": 1},
          "fp_counts": {"user_dao.py": {"py-sql-injection": 3}},
          "version": 1
        }
    """

    confirmed_idents: dict[str, int] = field(default_factory=dict)
    """Function name (identifier) → number of times confirmed as triggerable."""

    fp_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    """rel_fname → {rule_id → false-positive count}."""

    version: int = 1

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def add_confirmed_vuln(self, function_name: str) -> None:
        """Increment confirmation count for *function_name*."""
        if not function_name:
            return
        self.confirmed_idents[function_name] = (
            self.confirmed_idents.get(function_name, 0) + 1
        )
        logger.debug(
            "Feedback: confirmed ident '%s' (count=%d)",
            function_name,
            self.confirmed_idents[function_name],
        )

    def add_false_positive(self, file_path: str, rule_id: str) -> None:
        """Increment FP count for *(file_path, rule_id)* pair."""
        if not file_path or not rule_id:
            return
        self.fp_counts.setdefault(file_path, {})
        self.fp_counts[file_path][rule_id] = (
            self.fp_counts[file_path].get(rule_id, 0) + 1
        )
        logger.debug(
            "Feedback: FP for %s / %s (count=%d)",
            file_path,
            rule_id,
            self.fp_counts[file_path][rule_id],
        )

    # ------------------------------------------------------------------
    # Querying (consumed by Director)
    # ------------------------------------------------------------------

    def get_confirmed_idents(self) -> set[str]:
        """Return the set of function names whose PageRank should be boosted."""
        return set(self.confirmed_idents.keys())

    def get_suppressed_files(self) -> set[str]:
        """Return rel_fname values whose signals should be deweighted.

        A file enters the suppressed set when a (file_path, rule_id) pair
        has been flagged as false positive ``>= FP_THRESHOLD`` times.
        """
        suppressed: set[str] = set()
        for rel_fname, rules in self.fp_counts.items():
            for _rule_id, count in rules.items():
                if count >= FP_THRESHOLD:
                    suppressed.add(rel_fname)
                    break
        return suppressed

    def has_feedback(self) -> bool:
        """Return True if any feedback has been recorded."""
        return bool(self.confirmed_idents) or bool(self.fp_counts)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed_idents": dict(self.confirmed_idents),
            "fp_counts": {k: dict(v) for k, v in self.fp_counts.items()},
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeedbackStore:
        return cls(
            confirmed_idents=data.get("confirmed_idents", {}),
            fp_counts=data.get("fp_counts", {}),
            version=data.get("version", 1),
        )

    def save(self, path: str) -> None:
        """Persist feedback to JSON at *path*.

        Gracefully handles permission errors (e.g. in tests with synthetic
        paths like ``/project/.agies/feedback.json``).
        """
        dirname = os.path.dirname(path)
        if dirname and not os.path.exists(dirname):
            try:
                os.makedirs(dirname, exist_ok=True)
            except (OSError, PermissionError) as exc:
                logger.warning("Feedback: cannot create directory %s (%s)", dirname, exc)
                return
        try:
            with open(path, "w") as f:
                json.dump(self.to_dict(), f, indent=2, sort_keys=True)
            logger.debug("Feedback saved to %s", path)
        except (OSError, PermissionError) as exc:
            logger.warning("Feedback: cannot write to %s (%s)", path, exc)

    @classmethod
    def load(cls, path: str) -> FeedbackStore:
        """Load feedback from JSON at *path*, or return empty store."""
        if not os.path.isfile(path):
            logger.debug("Feedback: no store at %s, starting fresh.", path)
            return cls()
        try:
            with open(path) as f:
                data = json.load(f)
            logger.debug("Feedback: loaded from %s", path)
            return cls.from_dict(data)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Feedback: failed to load %s (%s), starting fresh.", path, exc)
            return cls()

    # ------------------------------------------------------------------
    # Batch recording from verified findings
    # ------------------------------------------------------------------

    @classmethod
    def record_from_findings(
        cls,
        verified_findings: list[dict[str, Any]],
        store: FeedbackStore | None = None,
    ) -> FeedbackStore:
        """Create or update a FeedbackStore from a list of verified findings.

        Each finding is inspected:
        - ``triggerable=True`` or ``verified=True`` → ``add_confirmed_vuln(function_name)``
        - ``triggerable=False`` with SAST evidence → ``add_false_positive(file_path, rule_id)``
        """
        if store is None:
            store = cls()

        for finding in verified_findings:
            is_triggerable = finding.get("triggerable", False) or finding.get("verified", False)

            if is_triggerable:
                fn = finding.get("function_name", "")
                if not fn:
                    # Legacy pipeline: try file_path as fallback
                    fp = finding.get("file_path", "")
                    if fp:
                        fn = os.path.splitext(os.path.basename(fp))[0]
                store.add_confirmed_vuln(fn)

            else:
                # False positive — extract SAST rule IDs from evidence
                rule_ids = _extract_sast_rules(finding)
                for rid in rule_ids:
                    store.add_false_positive(finding.get("file_path", ""), rid)

        return store
