"""Security Invariant Library — load and query invariant definitions.

Invariants are security properties that MUST hold for a given domain.
When a Feature is detected, its associated invariants are checked.

Usage::

    library = load_invariant_library()
    opaque = library.get("secret_opaque")
    for inv in library.for_feature("reference_expansion"):
        print(inv.name)
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_INVARIANTS_PATH = os.path.join(_DATA_DIR, "invariant_library.yaml")


@dataclass
class Invariant:
    """A security invariant — a property that must hold."""

    id: str
    """Unique invariant identifier, e.g. ``"secret_opaque"``."""

    name: str
    """Human-readable name, e.g. ``"Secret Opaque"``."""

    category: str
    """Invariant type: OPAQUE, IMMUTABLE, BOUNDED, MONOTONIC, VERIFIED,
    FRESH, CONSISTENT, COMPLETE."""

    applies_to: list[str] = field(default_factory=list)
    """Domains this invariant applies to."""

    description: str = ""
    """What this invariant guarantees."""

    violation: str = ""
    """What happens if the invariant is violated."""

    examples: list[str] = field(default_factory=list)
    """Concrete violation examples."""


@dataclass
class InvariantLibrary:
    """Container for all security invariants."""

    invariants: list[Invariant] = field(default_factory=list)
    _by_id: dict[str, Invariant] = field(default_factory=dict, repr=False)

    def get(self, invariant_id: str) -> Invariant | None:
        """Look up an invariant by its identifier."""
        return self._by_id.get(invariant_id)

    def for_domain(self, domain: str) -> list[Invariant]:
        """Get all invariants that apply to a given domain.

        Parameters
        ----------
        domain : str
            Domain name, e.g. ``"secret"``, ``"plugin"``, ``"token"``.

        Returns
        -------
        list[Invariant]
        """
        return [inv for inv in self.invariants if domain in inv.applies_to]

    def for_feature(self, feature) -> list[Invariant]:
        """Get invariants relevant to a feature.

        Uses the feature's ``id`` and ``name`` to match against
        invariant ``applies_to`` domains.

        Parameters
        ----------
        feature : Feature
            A business capability feature (from taxonomy).

        Returns
        -------
        list[Invariant]
        """
        matched: set[str] = set()
        results: list[Invariant] = []
        for inv in self.invariants:
            for domain in inv.applies_to:
                if domain in feature.id or domain in feature.name.lower():
                    if inv.id not in matched:
                        matched.add(inv.id)
                        results.append(inv)
                        break
        return results


def load_invariant_library(path: str | None = None) -> InvariantLibrary:
    """Load the invariant library from a YAML file.

    Parameters
    ----------
    path : str or None
        Path to the YAML file.  If ``None``, uses the default
        ``data/invariant_library.yaml`` shipped with the package.

    Returns
    -------
    InvariantLibrary
    """
    path = path or _INVARIANTS_PATH
    if not os.path.isfile(path):
        logger.warning("Invariant library not found: %s", path)
        return InvariantLibrary()

    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    invariants: list[Invariant] = []
    for entry in raw.get("invariants", []):
        invariants.append(Invariant(
            id=entry.get("id", ""),
            name=entry.get("name", ""),
            category=entry.get("category", ""),
            applies_to=entry.get("applies_to", []),
            description=entry.get("description", ""),
            violation=entry.get("violation", ""),
            examples=entry.get("examples", []),
        ))

    library = InvariantLibrary(invariants=invariants)
    library._by_id = {inv.id: inv for inv in invariants}
    logger.info("Loaded %d invariants from library", len(invariants))
    return library
