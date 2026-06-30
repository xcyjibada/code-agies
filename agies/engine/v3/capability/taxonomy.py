"""Feature taxonomy — load and query business capability definitions.

Defines what product-level capabilities a piece of code introduces,
independent of specific API names or implementation details.

Usage::

    taxonomy = load_taxonomy()
    all_features = taxonomy.features
    ref_feature = taxonomy.get("reference_expansion")
    matches = taxonomy.match_source("def _resolve_api_key_from_input($ENV_VAR): ...")
"""

from __future__ import annotations

import os
import re
import logging
from dataclasses import dataclass, field
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_TAXONOMY_PATH = os.path.join(_DATA_DIR, "feature_taxonomy.yaml")


@dataclass
class Feature:
    """A business capability feature."""

    id: str
    """Unique feature identifier, e.g. ``"reference_expansion"``."""

    name: str
    """Human-readable name, e.g. ``"Reference Expansion"``."""

    description: str
    """What the feature enables the user to do."""

    examples: list[str] = field(default_factory=list)
    """Concrete examples of this feature in code."""

    detection_patterns: list[dict[str, str]] = field(default_factory=list)
    """Patterns for AST-based detection: ``{"regex": "..."}`` entries."""

    security_relevance: str = ""
    """Why this feature is security-relevant."""

    _compiled: list[re.Pattern] = field(default_factory=list, repr=False)
    """Compiled regex patterns from detection_patterns."""


@dataclass
class FeatureTaxonomy:
    """Container for all business capability features."""

    features: list[Feature] = field(default_factory=list)
    _by_id: dict[str, Feature] = field(default_factory=dict, repr=False)

    def get(self, feature_id: str) -> Feature | None:
        """Look up a feature by its identifier."""
        return self._by_id.get(feature_id)

    def match_source(self, source_code: str) -> list[Feature]:
        """Match source code against all feature detection patterns.

        Returns a list of :class:`Feature` instances whose detection
        patterns match the source code.
        """
        matched: list[Feature] = []
        for feature in self.features:
            for pattern in feature._compiled:
                if pattern.search(source_code):
                    matched.append(feature)
                    break
        return matched

    def match_function_name(self, name: str) -> list[Feature]:
        """Match a function/class name against detection patterns.

        Useful for quick pre-filtering; for accuracy, use
        :meth:`match_source` with the full function body.
        """
        matched: list[Feature] = []
        for feature in self.features:
            for pattern in feature._compiled:
                if pattern.search(name):
                    matched.append(feature)
                    break
        return matched


def load_taxonomy(path: str | None = None) -> FeatureTaxonomy:
    """Load the feature taxonomy from a YAML file.

    Parameters
    ----------
    path : str or None
        Path to the YAML file.  If ``None``, uses the default
        ``data/feature_taxonomy.yaml`` shipped with the package.

    Returns
    -------
    FeatureTaxonomy
    """
    path = path or _TAXONOMY_PATH
    if not os.path.isfile(path):
        logger.warning("Feature taxonomy not found: %s", path)
        return FeatureTaxonomy()

    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    features: list[Feature] = []
    for entry in raw.get("features", []):
        patterns = entry.get("detection_patterns", [])
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p["regex"]))
            except (KeyError, re.error) as e:
                logger.debug("Bad pattern in %s: %s", entry.get("id"), e)

        features.append(Feature(
            id=entry.get("id", ""),
            name=entry.get("name", ""),
            description=entry.get("description", ""),
            examples=entry.get("examples", []),
            detection_patterns=patterns,
            security_relevance=entry.get("security_relevance", ""),
            _compiled=compiled,
        ))

    taxonomy = FeatureTaxonomy(features=features)
    taxonomy._by_id = {f.id: f for f in features}
    logger.info("Loaded %d feature types from taxonomy", len(features))
    return taxonomy
