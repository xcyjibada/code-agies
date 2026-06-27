"""Cross-type attack chain correlation — Phase E.

Scans all completed ``AgentPhaseResult`` findings and correlates them into
multi-step attack chains.  Three correlation modes:

1. **Type-based** (existing): ``_CHAIN_DEFS`` — hardcoded vuln type pairs
   (SSRF→RCE, LFI→RCE, etc.) that share a function.
2. **Module-overlap** (op.md §Feature Composition): two findings in the same
   module/file that can be invoked sequentially by an attacker — one produces
   input the other consumes.
3. **Assumption conflict** (op.md §System Assumptions): one path's assumptions
   are violated by another path's behavior.

Architecture
------------
Implemented as a Phase E post-processing step in ``runner.py``.  Reads
``AgentPhaseResult`` list + ``BlackboardAggregator``, outputs chain candidates
as additional ``AgentPhaseResult`` entries with ``vuln_type`` = ``"CHAIN:..."``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from agies.engine.v3.aggregator.blackboard import BlackboardAggregator
from agies.engine.v3.aggregator.models import AgentPhaseResult

logger = logging.getLogger(__name__)

# ── Hardcoded chain definitions (fast path) ──────────────────────────────
# Each chain: (name, [vuln_types_in_order], impact_type, description)
# Order matters: first type = entry, last = impact.

_CHAIN_DEFS: list[tuple[str, list[str], str, str]] = [
    (
        "SSRF→RCE",
        ["SSRF", "RCE"],
        "RCE",
        "SSRF entry + Deserialization: external fetch returns attacker-controlled "
        "data that gets deserialized without validation.",
    ),
    (
        "LFI→RCE",
        ["LFI", "AFO"],
        "RCE",
        "File read + File write: attacker reads sensitive config via LFI, "
        "then writes malicious files via AFO.",
    ),
    (
        "SSRF→AFO→RCE",
        ["SSRF", "AFO"],
        "RCE",
        "SSRF download + File write: attacker-controlled URL is fetched and "
        "response body written to disk without validation.",
    ),
    (
        "SSTI→RCE",
        ["SSTI", "RCE"],
        "RCE",
        "Template injection → Code execution: template engine evaluates "
        "attacker-controlled template string.",
    ),
    (
        "XSS→RCE",
        ["XSS", "RCE"],
        "RCE",
        "Stored/Reflected XSS + eval: attacker script reaches a JS eval() sink.",
    ),
    (
        "SSRF→XXE",
        ["SSRF", "XXE"],
        "LFI",
        "SSRF + XXE: attacker-controlled DTD loads external resources via SSRF.",
    ),
    (
        "SQLI→AFO",
        ["SQLI", "AFO"],
        "RCE",
        "SQL injection → File write: DB query with INTO OUTFILE writes to filesystem.",
    ),
]

# Entry-type vulns — they read/receive external data
_ENTRY_TYPES: set[str] = {"SSRF", "LFI", "SSTI", "XSS", "SQLI"}

# Impact-type vulns — they write/execute
_IMPACT_TYPES: set[str] = {"RCE", "AFO"}

# ── Module-level chain patterns (op.md §Feature Composition) ────────────
# Pairs where an "entry" type and an "impact" type in the same module can chain.
_ENTRY_IMPACT_PAIRS: list[tuple[str, str, str, str]] = [
    ("SSRF", "RCE", "RCE", "Module-local SSRF→RCE: entry function fetches data "
     "from attacker-controlled URL and sink function deserializes within same module."),
    ("SSRF", "AFO", "RCE", "Module-local SSRF→AFO: entry fetches, sink writes to disk."),
    ("LFI", "AFO", "RCE", "Module-local LFI→AFO: entry reads files, sink writes files."),
]


# ── Functions ───────────────────────────────────────────────────────────


def _get_functions_for_result(
    result: AgentPhaseResult,
    path_slices: list[Any] | None,
) -> set[str]:
    """Extract function names mentioned in a finding.

    Uses:
    1. ``result.contradictions`` — each entry has a ``func`` field
    2. ``path_slices`` — each slice has ``sink`` and ``entry`` fields
    """
    funcs: set[str] = set()

    for c in result.contradictions:
        f = c.get("func", "")
        if f and f != "?":
            funcs.add(f)

    if path_slices:
        for ps in path_slices:
            if hasattr(ps, "path_id") and ps.path_id == result.path_id:
                if hasattr(ps, "sink") and ps.sink:
                    funcs.add(ps.sink)
                if hasattr(ps, "entry") and ps.entry:
                    funcs.add(ps.entry)
                break
            elif isinstance(ps, dict) and ps.get("path_id") == result.path_id:
                if ps.get("sink"):
                    funcs.add(ps["sink"])
                if ps.get("entry"):
                    funcs.add(ps["entry"])
                break

    return funcs


def _get_module_path(result: AgentPhaseResult, path_slices: list[Any] | None) -> str:
    """Extract the file/module path for a finding.

    Returns a normalized absolute path or empty string.
    """
    if path_slices:
        for ps in path_slices:
            sid = ps.path_id if hasattr(ps, "path_id") else ps.get("path_id", "")
            if sid == result.path_id:
                sink_file = (
                    ps.sink_file if hasattr(ps, "sink_file")
                    else ps.get("sink_file", "")
                )
                if sink_file:
                    return os.path.normpath(sink_file.split(":")[0])
    return ""


def _check_module_overlap(
    phase_results: list[AgentPhaseResult],
    path_slices: list[Any] | None,
) -> list[AgentPhaseResult]:
    """Find chain candidates where entry and impact types share a module.

    Unlike type-based chaining which requires *shared functions*, module-level
    chaining only requires the two findings to live in the same source file.
    This catches composition vulnerabilities where one function reads/produces
    data that another function in the same file consumes unsafely.
    """
    chain_results: list[AgentPhaseResult] = []
    by_module: dict[str, list[AgentPhaseResult]] = {}

    for r in phase_results:
        mod = _get_module_path(r, path_slices)
        if not mod:
            continue
        by_module.setdefault(mod, []).append(r)

    for mod, findings in by_module.items():
        if len(findings) < 2:
            continue

        for entry_type, impact_type, impact_label, desc in _ENTRY_IMPACT_PAIRS:
            entries = [
                f for f in findings
                if (f.actual_vuln_type or f.vuln_type).upper() == entry_type
                and f.is_vulnerable
            ]
            impacts = [
                f for f in findings
                if (f.actual_vuln_type or f.vuln_type).upper() == impact_type
                and f.is_vulnerable
            ]
            for ef in entries:
                for impf in impacts:
                    chain_name = f"{entry_type}→{impact_type}"
                    chain_conf = max(1, int((ef.confidence * impf.confidence) ** 0.5))
                    chain_path_id = (
                        f"MODULE:{chain_name}:{ef.path_id}+{impf.path_id}"
                    )

                    chain_results.append(AgentPhaseResult(
                        path_id=chain_path_id,
                        vuln_type=f"CHAIN:{chain_name}",
                        score=min(ef.score, impf.score),
                        confidence=chain_conf,
                        analysis=(
                            f"Module-level attack chain: {chain_name}\n"
                            f"  Module: {mod}\n"
                            f"  Step 1 ({entry_type}): {ef.path_id}\n"
                            f"  Step 2 ({impact_type}): {impf.path_id}\n"
                            f"  Description: {desc}\n"
                            f"  Impact: {impact_label}"
                        ),
                        is_vulnerable=True,
                        actual_vuln_type=impact_label,
                    ))
                    logger.info(
                        "Module chain: %s (conf=%d, mod=%s)",
                        chain_path_id, chain_conf, mod,
                    )

    return chain_results


def _check_assumption_conflicts(
    phase_results: list[AgentPhaseResult],
    blackboard: BlackboardAggregator | None,
    path_slices: list[Any] | None,
) -> list[AgentPhaseResult]:
    """Find chains where one path's assumptions are broken by another path.

    Scans Blackboard for ``[ASSUMPTION ...]`` knowledge entries and looks for
    conflicts:
    - Path A assumes PATH_STABILITY, Path B performs a write operation in the
      same module → potential symlink swap chain
    - Path A assumes CHECK_USE_ATOMICITY, Path B reads the same resource in
      a different request → TOCTOU chain
    """
    if not blackboard:
        return []

    chain_results: list[AgentPhaseResult] = []

    # Collect violable assumptions from the blackboard
    # Knowledge entries with "[ASSUMPTION" prefix and violable=True
    assumption_entries: list[dict] = []
    try:
        # blackboard._knowledge is a dict[function_name, list[KnowledgeEntry]]
        for fn, entries in blackboard._knowledge.items():  # type: ignore[attr-defined]
            for entry in entries:
                val = entry.value if hasattr(entry, "value") else entry.get("value", "")
                if "[ASSUMPTION" in val and "violable=True" in val:
                    assumption_entries.append({
                        "function": fn,
                        "text": val,
                        "source_path_id": getattr(entry, "source_path_id", ""),
                    })
    except Exception:
        logger.debug("Assumption conflict scan: could not read blackboard knowledge")
        return chain_results

    if not assumption_entries:
        return chain_results

    # For each violable assumption, look for a path that could trigger the violation
    # Group findings by module for efficient matching
    findings_by_mod: dict[str, list[AgentPhaseResult]] = {}
    for r in phase_results:
        mod = _get_module_path(r, path_slices)
        if mod:
            findings_by_mod.setdefault(mod, []).append(r)

    for ae in assumption_entries:
        atype_match = __import__("re").search(r"\[ASSUMPTION (\w+)\]", ae["text"])
        atype = atype_match.group(1) if atype_match else "?"
        desc_match = __import__("re").search(r"\] (.+?) \|", ae["text"])
        desc = desc_match.group(1) if desc_match else "?"

        # Find paths in the same module that could be the trigger
        for mod, findings in findings_by_mod.items():
            if ae["function"] in mod:
                for rf in findings:
                    if rf.path_id == ae["source_path_id"]:
                        continue  # same path, skip
                    if not rf.is_vulnerable and rf.confidence < 4:
                        continue

                    chain_name = f"ASSUMPTION:{atype}"
                    chain_path_id = f"ASSUMP:{rf.path_id}+{ae['source_path_id']}"

                    chain_results.append(AgentPhaseResult(
                        path_id=chain_path_id,
                        vuln_type=chain_name,
                        score=rf.score,
                        confidence=max(1, min(10, rf.confidence - 1)),
                        analysis=(
                            f"Assumption conflict chain\n"
                            f"  Violated assumption: {atype}\n"
                            f"  Assumption detail: {desc}\n"
                            f"  Trigger path: {rf.path_id} ({rf.vuln_type})\n"
                            f"  Source path: {ae['source_path_id']}\n"
                            f"  Module: {mod}\n"
                            f"  Conflict: a path in the same module may "
                            f"trigger conditions that break this assumption"
                        ),
                        is_vulnerable=rf.is_vulnerable,
                    ))
                    logger.info(
                        "Assumption conflict: %s (type=%s, mod=%s)",
                        chain_path_id, atype, mod,
                    )
                break

    return chain_results


def correlate_chains(
    phase_results: list[AgentPhaseResult],
    path_slices: list[Any] | None = None,
    blackboard: BlackboardAggregator | None = None,
) -> list[AgentPhaseResult]:
    """Scan all findings and correlate them into attack chains.

    Three correlation modes:
    1. Type-based: hardcoded vuln type pairs with shared functions
    2. Module-overlap: entry+impact in the same module
    3. Assumption conflict: one path's assumptions violated by another

    Parameters
    ----------
    phase_results : list[AgentPhaseResult]
        All completed Phase D findings.
    path_slices : list[Any] | None
        Original path slice objects (for metadata extraction).
    blackboard : BlackboardAggregator | None
        Blackboard with assumption analysis knowledge.

    Returns
    -------
    list[AgentPhaseResult]
        Additional chain findings with ``vuln_type`` starting with ``"CHAIN:"``.
    """
    if not phase_results:
        return []

    chain_results: list[AgentPhaseResult] = []

    # ── Mode 1: Type-based correlation (existing) ──
    by_type: dict[str, list[AgentPhaseResult]] = {}
    for r in phase_results:
        vt = r.actual_vuln_type or r.vuln_type
        by_type.setdefault(vt, []).append(r)

    for chain_name, required_types, impact, description in _CHAIN_DEFS:
        available = []
        for vt in required_types:
            findings = by_type.get(vt, [])
            if not findings:
                break
            available.append(findings)
        else:
            entry_findings = available[0]
            impact_findings = available[1] if len(available) > 1 else []

            for entry_f in entry_findings:
                entry_funcs = _get_functions_for_result(entry_f, path_slices)
                if not entry_funcs:
                    continue
                for impact_f in impact_findings:
                    impact_funcs = _get_functions_for_result(impact_f, path_slices)
                    if not impact_funcs:
                        continue
                    shared = entry_funcs & impact_funcs
                    if not shared:
                        continue
                    entry_conf = entry_f.confidence or 5
                    impact_conf = impact_f.confidence or 5
                    chain_conf = max(1, int((entry_conf * impact_conf) ** 0.5))
                    shared_str = ", ".join(sorted(shared)[:3])
                    reported_vt = "RCE" if impact == "RCE" else impact
                    chain_path_id = f"{chain_name}:{entry_f.path_id}+{impact_f.path_id}"

                    chain_results.append(AgentPhaseResult(
                        path_id=chain_path_id,
                        vuln_type=f"CHAIN:{chain_name}",
                        score=min(entry_f.score, impact_f.score),
                        confidence=chain_conf,
                        analysis=(
                            f"Attack chain: {chain_name}\n"
                            f"  Step 1 ({entry_f.vuln_type}): {entry_f.path_id}\n"
                            f"  Step 2 ({impact_f.vuln_type}): {impact_f.path_id}\n"
                            f"  Shared functions: {shared_str}\n"
                            f"  Description: {description}\n"
                            f"  Impact: {reported_vt}"
                        ),
                        is_vulnerable=True,
                        actual_vuln_type=reported_vt,
                    ))
                    logger.info(
                        "Type chain: %s (conf=%d, shared=%s)",
                        chain_path_id, chain_conf, shared_str,
                    )
                    break

    # ── Mode 2: Module-level overlap ──
    try:
        module_chains = _check_module_overlap(phase_results, path_slices)
        chain_results.extend(module_chains)
    except Exception as exc:
        logger.debug("Module overlap chain scan failed: %s", exc)

    # ── Mode 3: Assumption conflict ──
    try:
        assumption_chains = _check_assumption_conflicts(
            phase_results, blackboard, path_slices,
        )
        chain_results.extend(assumption_chains)
    except Exception as exc:
        logger.debug("Assumption conflict chain scan failed: %s", exc)

    if chain_results:
        logger.info(
            "Chain correlation: %d attack chain(s) found (%d type, %d module, %d assumption)",
            len(chain_results),
            len([c for c in chain_results if c.vuln_type.startswith("CHAIN:") and "ASSUMP" not in c.vuln_type and "MODULE" not in c.vuln_type]),
            len([c for c in chain_results if "MODULE" in c.vuln_type]),
            len([c for c in chain_results if "ASSUMP" in c.vuln_type]),
        )

    return chain_results
