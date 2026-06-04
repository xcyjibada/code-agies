"""Path scoring, sorting, and Explore/Exploit slot allocation.

Core of Phase B — takes raw CodeQL paths and produces ranked ``PathSlice`` s.

Design
------
- **score_path()**: static scoring (sink weight × length penalty × …)
- **select_top_k()**: static coarse filter → optional LLM micro-filter
- **is_anomalous()**: flag paths with non-standard sinks for Explore slots
- **Explore/Exploit separation**: 25 exploit + 5 explore (default)

See ``docs/v3/plan.md`` Phase B for detailed rationale.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agies.engine.v3.codeql.models import CodeQlPath, VulnType
from agies.engine.v3.slicer.models import PathSlice, SortResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sink danger-weight table
# ---------------------------------------------------------------------------

SINK_WEIGHTS: dict[str, float] = {
    # RCE — exec, eval, subprocess
    "exec": 1.0, "eval": 1.0, "compile": 0.9,
    "subprocess.call": 1.0, "subprocess.Popen": 1.0,
    "subprocess.run": 0.9, "subprocess.check_output": 0.9,
    "subprocess.check_call": 0.9, "subprocess.getoutput": 0.8,
    "subprocess.getstatusoutput": 0.8,
    "os.system": 1.0, "os.popen": 1.0,
    "Runtime.exec": 1.0, "ProcessBuilder": 0.9,
    # Deserialization
    "pickle.loads": 0.9, "pickle.load": 0.9,
    "yaml.load": 0.9, "yaml.unsafe_load": 0.9,
    "jsonpickle.decode": 0.8,
    # LFI — file read
    "open": 0.6, "file": 0.5,
    "pathlib.Path.read_text": 0.5, "pathlib.Path.read_bytes": 0.5,
    "pathlib.Path.open": 0.6,
    # SSRF — outbound requests
    "requests.get": 0.5, "requests.post": 0.5,
    "requests.put": 0.5, "requests.request": 0.5,
    "urllib.request.urlopen": 0.6, "urllib.request.urlretrieve": 0.6,
    "httpx.get": 0.5, "httpx.post": 0.5,
    "aiohttp.ClientSession.get": 0.5,
    # SQLI — database queries
    "execute": 0.8, "executemany": 0.8, "executescript": 0.8,
    "cursor.execute": 0.8, "connection.execute": 0.7,
    # XSS — template rendering
    "render_template_string": 0.6, "format": 0.4,
    "Markup": 0.5,
    # AFO — file write
    "pathlib.Path.write_text": 0.6, "pathlib.Path.write_bytes": 0.6,
    # IDOR — direct object reference
    "get_object_or_404": 0.5, "queryset.filter": 0.4,
}

KNOWN_SINKS: set[str] = set(SINK_WEIGHTS.keys())

# Common sanitize/validate/escape function name patterns
_VALIDATION_PATTERNS: re.Pattern = re.compile(
    r"(sanitize|validate|escape|clean|purge|filter|check|verify|is_safe|is_valid)",
    re.IGNORECASE,
)

# Test/generated file patterns to exclude
_EXCLUDE_DIR_PATTERNS: re.Pattern = re.compile(
    r"(^|/)(test|tests|__pycache__|node_modules|\.git|"
    r"gen(?:erated)?|vendor|third_party|migrations|mock)s?/",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Static scoring
# ---------------------------------------------------------------------------


def score_path(path: CodeQlPath) -> float:
    """Static risk score for a single source→sink path (0-1).

    Factors
    -------
    - Sink danger weight (40% contribution)
    - Path length penalty — longer paths are harder to exploit (20%)
    - Validation bypass bonus — sanitized paths are high-value targets (20%)
    - Full-path completeness bonus (15%)
    - Cross-module bonus — multi-module flows are riskier (5%)

    Note on sanitizer handling
    --------------------------
    Unlike early v3 drafts that *penalized* paths with sanitizers (``score *= 0.5``),
    this implementation *bonuses* them (+0.2). Rationale: real-world 0-days
    are disproportionately sanitizer bypasses, not missing sanitizers.
    See ``docs/v3/revisions_from_op.md`` for the discussion that drove this change.
    """
    score = 0.0

    # 1. Sink danger weight (40%)
    weight = _sink_weight(path.sink)
    score += weight * 0.40

    # 2. Path length penalty — fewer hops = more reliable exploit (20%)
    num_nodes = len(path.nodes) if path.nodes else 1
    length_penalty = 1.0 / (1.0 + 0.1 * max(0, num_nodes - 3))
    score += length_penalty * 0.20

    # 3. Validation bypass bonus — "写了校验但没写对" is high-value (20%)
    #    Also checks node function names for validation patterns
    has_validation = _has_validation(path)
    if has_validation:
        score += 0.20

    # 4. Full-path completeness (15%)
    if path.is_full_path:
        score += 0.15

    # 5. Cross-module bonus — multi-module flows cross trust boundaries (5%)
    if _cross_module_bonus(path):
        score += 0.05

    return min(score, 1.0)


def _sink_weight(sink_name: str) -> float:
    """Look up sink danger weight, falling back to 0.3 for unknown sinks."""
    return SINK_WEIGHTS.get(sink_name, 0.3)


def _has_validation(path: CodeQlPath) -> bool:
    """Check whether a path passes through sanitize/validate/escape functions."""
    if _VALIDATION_PATTERNS.search(path.sink):
        return True
    for node in path.nodes:
        if _VALIDATION_PATTERNS.search(node.function_name):
            return True
    return False


def _cross_module_bonus(path: CodeQlPath) -> bool:
    """Detect whether a path crosses module boundaries."""
    files: set[str] = set()
    files.add(path.source_file)
    files.add(path.sink_file)
    for node in path.nodes:
        files.add(node.file_path)
    return len(files) >= 3


# ---------------------------------------------------------------------------
# Top-K selection
# ---------------------------------------------------------------------------


def select_top_k(
    paths: list[CodeQlPath],
    *,
    max_exploit: int = 25,
    max_explore: int = 5,
    exclude_test: bool = True,
    llm_filter: bool = False,
) -> SortResult:
    """Static coarse filter + optional LLM micro-selection.

    Pipeline
    --------
    1. Exclude test/generated paths (unless ``exclude_test=False``)
    2. Score all remaining paths via ``score_path()``
    3. Mark validation-passing paths as [BYPASS_TARGET]
    4. Select top ``max_exploit`` for Exploit slot
    5. ``is_anomalous()`` → top ``max_explore`` for Explore slot
    6. Fill remaining Explore slots from Exploit candidates

    Parameters
    ----------
    paths : list[CodeQlPath]
        Raw paths from one or more CodeQL queries.
    max_exploit : int
        Number of exploit-slot paths (default 25).
    max_explore : int
        Number of explore-slot paths (default 5).
    exclude_test : bool
        Skip paths in test/generated directories (default True).
    llm_filter : bool
        Enable optional LLM semantic filter stage (default False, not yet implemented).
    """
    # Step 1: Exclude test/generated
    if exclude_test:
        paths = [p for p in paths if not _in_excluded_dir(p)]

    total_input = len(paths)

    # Step 2: Score & sort
    scored: list[tuple[float, CodeQlPath]] = [
        (score_path(p), p) for p in paths
    ]
    scored.sort(key=lambda x: -x[0])

    # Step 3: Separate into candidate pool
    candidates = scored[:max_exploit + max_explore]
    remaining_pool = scored[max_exploit + max_explore:]

    # Step 4: Allocate exploit slots (top N)
    exploit_raw = [p for _, p in candidates[:max_exploit]]

    # Step 5: Allocate explore slots from the rest
    explore_candidates = candidates[max_exploit:] + remaining_pool
    explore_scores, explore_paths = zip(*explore_candidates) if explore_candidates else ([], [])
    explore_raw = _select_explore(
        list(explore_paths),
        slots=max_explore,
        exploit_fill=exploit_raw[max_exploit - max_explore:],
    )

    # Step 6: Build PathSlice objects
    exploit = [
        _to_slice(p, idx=i, slot="exploit")
        for i, p in enumerate(exploit_raw)
    ]
    explore = [
        _to_slice(p, idx=i, slot="explore")
        for i, p in enumerate(explore_raw)
    ]

    return SortResult(
        exploit=exploit,
        explore=explore,
        total_input=total_input,
        total_output=len(exploit) + len(explore),
    )


def _in_excluded_dir(path: CodeQlPath) -> bool:
    """Check if a path lies in a test/generated/vendor directory."""
    for node_summary in [path.source_file, path.sink_file]:
        if _EXCLUDE_DIR_PATTERNS.search(node_summary):
            return True
    for node in path.nodes:
        if _EXCLUDE_DIR_PATTERNS.search(node.file_path):
            return True
    return False


def _to_slice(
    path: CodeQlPath,
    idx: int,
    slot: str = "exploit",
) -> PathSlice:
    """Convert a scored CodeQlPath to a PathSlice with explore metadata."""
    score = score_path(path)
    reasons = is_anomalous(path) if slot == "explore" else []

    return PathSlice(
        id=f"{path.vuln_type.value}-{idx:03d}",
        vuln_type=path.vuln_type,
        source=path.source,
        source_file=f"{path.source_file}:{path.source_line}",
        sink=path.sink,
        sink_file=f"{path.sink_file}:{path.sink_line}",
        score=score,
        is_full_path=path.is_full_path,
        has_validation=_has_validation(path),
        assigned_slot=slot,
        anomaly_reasons=reasons,
        # code_block is empty here — filled lazily by PathCodeLoader
    )


# ---------------------------------------------------------------------------
# Explore-slot selection
# ---------------------------------------------------------------------------


def _select_explore(
    candidates: list[CodeQlPath],
    slots: int = 5,
    exploit_fill: list[CodeQlPath] | None = None,
) -> list[CodeQlPath]:
    """Fill Explore slots — first from anomalous paths, then from Exploit fill pool."""
    # Score by anomaly count
    scored: list[tuple[int, CodeQlPath]] = []
    for path in candidates:
        reasons = is_anomalous(path)
        if reasons:
            scored.append((len(reasons), path))

    scored.sort(key=lambda x: -x[0])
    selected = [p for _, p in scored[:slots]]

    # Fill remaining slots from Exploit pool
    if len(selected) < slots and exploit_fill:
        fill_needed = slots - len(selected)
        selected.extend(exploit_fill[:fill_needed])

    return selected


def is_anomalous(path: CodeQlPath) -> list[str]:
    """Determine whether a path is anomalous — qualifies for Explore slot.

    Returns a list of anomaly reasons (empty = not anomalous).
    """
    reasons: list[str] = []

    # 1. Sink not in predefined list — non-standard sink
    if path.sink not in KNOWN_SINKS:
        reasons.append("non_std_sink")

    # 2. Complex custom logic — functions average > 100 lines
    if _avg_function_size(path) > 100:
        reasons.append("complex_custom_logic")

    # 3. Unusual naming — not common get/set/parse/validate/…
    if _has_unusual_names(path):
        reasons.append("unusual_naming")

    # 4. Multi-module — crosses many module boundaries
    if _module_count(path) > 3:
        reasons.append("multi_module_flow")

    return reasons


def _avg_function_size(path: CodeQlPath) -> float:
    """Estimate average function size (crude: use node count as proxy)."""
    if not path.nodes:
        return 0.0
    return len(path.nodes) / max(1, len(path.nodes))


_COMMON_NAMES: set[str] = {
    "get", "set", "parse", "validate", "check", "format",
    "load", "save", "read", "write", "open", "close",
    "init", "run", "start", "stop", "handle", "process",
    "transform", "convert", "build", "create", "delete",
    "update", "insert", "query", "find", "search",
    "filter", "map", "reduce", "apply", "call",
}


def _has_unusual_names(path: CodeQlPath) -> bool:
    """Check if path contains unusually named functions."""
    unusual = 0
    total = 0
    for node in path.nodes:
        total += 1
        parts = node.function_name.replace("-", "_").split("_")
        if len(parts) >= 2 and not any(
            p.lower() in _COMMON_NAMES for p in parts
        ):
            unusual += 1
    # Skip single-function paths (trivially "unusual")
    if total <= 1:
        return False
    return unusual / max(1, total) > 0.5


def _module_count(path: CodeQlPath) -> int:
    """Count distinct top-level modules touched by this path."""
    modules: set[str] = set()
    modules.add(_top_module(path.source_file))
    modules.add(_top_module(path.sink_file))
    for node in path.nodes:
        modules.add(_top_module(node.file_path))
    return len(modules)


def _top_module(file_path: str) -> str:
    """Extract the top-level package/directory from a file path."""
    parts = file_path.replace("\\", "/").split("/")
    return parts[0] if parts else ""


# ---------------------------------------------------------------------------
# LLM micro-filter (stub — Phase B Step 2)
# ---------------------------------------------------------------------------


def llm_semantic_filter(
    slices: list[PathSlice],
    max_slices: int = 30,
) -> list[PathSlice]:
    """Optional LLM-based semantic filter over ranked slices.

    Not yet implemented. For now, just returns the top N by score.
    """
    slices.sort(key=lambda s: -s.score)
    return slices[:max_slices]


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------


def summarize_sort(result: SortResult) -> str:
    """Human-readable summary of the sorting result."""
    return (
        f"Sort: {result.total_input} paths → "
        f"{len(result.exploit)} exploit + "
        f"{len(result.explore)} explore = "
        f"{result.total_output} slices"
    )


def summarize_path(slice_: PathSlice) -> str:
    """One-line summary of a path slice."""
    tag = "[EXPLOIT]" if slice_.assigned_slot == "exploit" else "[EXPLORE]"
    reasons = f" ({', '.join(slice_.anomaly_reasons)})" if slice_.anomaly_reasons else ""
    return (
        f"{tag} {slice_.id}: {slice_.source} → {slice_.sink} "
        f"score={slice_.score:.2f}{reasons}"
    )
