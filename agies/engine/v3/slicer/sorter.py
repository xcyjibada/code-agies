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

from agies.engine.v3.codeql.models import CodeQlPath, VulnType, Reachability
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
    # XSS — output rendering
    "Markup": 0.5, "format": 0.4,
    # AFO — file write
    "pathlib.Path.write_text": 0.6, "pathlib.Path.write_bytes": 0.6,
    # XXE — XML parsing with insecure defaults (CWE-611)
    "lxml.etree.parse": 0.7, "lxml.etree.fromstring": 0.7,
    "lxml.etree.XMLParser": 0.7,
    "xml.etree.ElementTree.parse": 0.7, "xml.etree.ElementTree.fromstring": 0.7,
    "lxml.objectify.parse": 0.7, "lxml.objectify.fromstring": 0.7,
    "xml.dom.minidom.parse": 0.7, "xml.dom.minidom.parseString": 0.7,
    "xml.sax.parse": 0.7, "xml.sax.parseString": 0.7,
    # Common import aliases for XXE (body-detected via \bTemplate\b / BeautifulSoup regex)
    "BeautifulSoup": 0.7,
    "ElementTree.fromstring": 0.7, "ElementTree.parse": 0.7,
    "etree.parse": 0.7, "etree.fromstring": 0.7, "etree.XMLParser": 0.7,
    # SSTI — Server-Side Template Injection (CWE-1336)
    "render_template_string": 0.8,
    "jinja2.Template": 0.8, "jinja2.Environment": 0.8,
    "Template": 0.8, "Template.render": 0.8,
    "Environment.from_string": 0.8,
    "mako.template.Template": 0.8,
    # IDOR — direct object reference
    "get_object_or_404": 0.5, "queryset.filter": 0.4,
    # REDOS — regex operations
    "glob": 0.6, "re.compile": 0.7, "re.match": 0.6,
    "re.search": 0.6, "re.findall": 0.5, "re.fullmatch": 0.5,
    "re.sub": 0.5, "fnmatch.translate": 0.5, "fnmatch.filter": 0.5,
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
    #    For body-detected sinks, use the body call weight (e.g. pickle.loads
    #    inside dequeue) instead of the parent function name.
    weight = _sink_weight(
        path.sink,
        body_sink_call=getattr(path, "body_sink_call", ""),
        body_detected=getattr(path, "body_detected", False),
    )
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

    # 6. Reachability adjustment
    #    EXTERNAL_API: public API inference — small bonus for context.
    #    NOTE: BODY_ONLY 惩罚 (score *= 0.8) 已于 2026-06-12 移除。
    #    原因：BODY_ONLY 路径已经天然缺失调用链分数（无完整路径加成、
    #    无跨模块加成），额外惩罚使其结构性低于所有 CHAIN 路径，
    #    导致高风险 sink（如 pickle.loads 体内检测）被排除出 top 45。
    #    实验验证：移除后 FAISS load_local → pickle.loads 路径才能进分析。
    reach = getattr(path, "reachability", Reachability.CHAIN)
    if reach == Reachability.EXTERNAL_API:
        score += 0.05  # public API context = slightly more actionable

    # 7. Body-detected bonus — functions with dangerous calls in their body
    #    (e.g. ``dequeue`` containing ``pickle.loads``) are harder to find by
    #    name alone. Give a small boost so they compete better for exploit slots.
    # Body-detected bonus — functions with dangerous calls in their body
    # (e.g. ``dequeue`` containing ``pickle.loads``) are harder to detect by
    # name alone. The +0.15 boost compensates for the length penalty that
    # disproportionately affects deep call chains found via body regex.
    if getattr(path, "body_detected", False):
        score += 0.15

    # 8. Reachability score bonus (Phase 3)
    #    If the path source is in the reachability matrix's known sources,
    #    and/or the source→sink pair is confirmed reachable, add a small bump.
    bonus = getattr(path, "reachability_score_bonus", 0.0)
    score += bonus

    return min(max(score, 0.0), 1.0)


def _sink_weight(sink_name: str, body_sink_call: str = "", body_detected: bool = False) -> float:
    """Look up sink danger weight.

    For body-detected sinks (e.g. ``dequeue`` whose body calls ``pickle.loads``),
    use the body call's weight instead of the parent function name's weight.
    Falls back to 0.3 for truly unknown sinks.
    """
    if body_detected and body_sink_call:
        return SINK_WEIGHTS.get(body_sink_call, SINK_WEIGHTS.get(sink_name, 0.3))
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

    # Step 3: Guarantee at least one exploit slot per vuln type
    #   Reserve the path for each unique vuln type, preferring paths where
    #   the sink name is a KNOWN sink function (not an intermediate helper).
    #   This prevents a single dominant vuln type (e.g. 13 LFI) from crowding
    #   out rarer types (e.g. 2 REDOS) that are often higher-value.
    by_type: dict[str, list[tuple[float, CodeQlPath]]] = {}
    for s, p in scored:
        by_type.setdefault(p.vuln_type.value, []).append((s, p))

    exploit_raw: list[CodeQlPath] = []
    used_keys: set[str] = set()
    for vt in sorted(by_type.keys()):
        candidates = by_type[vt]
        # Prefer known direct sink over intermediate helper function
        best = max(candidates, key=lambda x: (1.0 if x[1].sink in KNOWN_SINKS else 0.0, x[0]))
        exploit_raw.append(best[1])
        used_keys.add(best[1].key)

    # Step 4: Fill remaining exploit slots from the rest by score
    remaining_scored = [(s, p) for s, p in scored if p.key not in used_keys]
    slots_left = max_exploit - len(exploit_raw)
    if slots_left > 0:
        for s, p in remaining_scored[:slots_left]:
            exploit_raw.append(p)
            used_keys.add(p.key)
    else:
        exploit_raw = exploit_raw[:max_exploit]

    # Step 5: Allocate explore slots from leftover candidates
    explore_pool = [(s, p) for s, p in remaining_scored if p.key not in used_keys]
    explore_scores, explore_paths = zip(*explore_pool) if explore_pool else ([], [])
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
    """Check if a path lies in a test/generated/vendor directory.

    Body-detected sinks (e.g. ``dequeue`` with ``pickle.loads`` in body) are
    exempt from test exclusion because they have no telltale sink name and the
    entry point may be a test file even though the real exploit path goes
    through a different (non-static-traceable) entry like a network socket.
    """
    reach = getattr(path, "reachability", Reachability.CHAIN)
    if reach in (Reachability.BODY_ONLY, Reachability.EXTERNAL_API):
        return False
    if getattr(path, "body_detected", False):
        return False
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
        nodes=[n.__dict__ for n in path.nodes] if path.nodes else [],
        reachability=getattr(path, "reachability", Reachability.CHAIN),
        cpg_data_flow_evidence=getattr(path, "cpg_data_flow_evidence", ""),
        cross_file_flow=getattr(path, "cross_file_flow", ""),
        body_detected=getattr(path, "body_detected", False),
        body_sink_call=getattr(path, "body_sink_call", ""),
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
    """Fill Explore slots — anomalous paths first, then Exploit fill pool.

    Body-detected high-severity sinks (e.g. ``dequeue`` whose body contains
    ``pickle.loads``) are pre-pended to the anomaly score so they get priority
    even when their anomaly reasons are generic.
    """
    scored: list[tuple[float, CodeQlPath]] = []
    for path in candidates:
        reasons = is_anomalous(path)
        reach = getattr(path, "reachability", Reachability.CHAIN)
        if not reasons and reach == Reachability.CHAIN:
            continue
        # Base score: anomaly count
        base = float(len(reasons))
        # Reachability-aware bonus:
        #   BODY_ONLY: high-value body call, lower confidence
        #   EXTERNAL_API: public API, moderate confidence
        if reach == Reachability.BODY_ONLY:
            base += 0.5  # boost above any non-body path with same anomaly count
        elif reach == Reachability.EXTERNAL_API:
            base += 0.8  # public API: more actionable than bare BODY_ONLY
        elif getattr(path, "body_detected", False):
            base += 0.5  # fallback: old attribute-based detection
        scored.append((base, path))

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
    reach_tag = f" [{slice_.reachability.value}]" if slice_.reachability != Reachability.CHAIN else ""
    return (
        f"{tag}{reach_tag} {slice_.id}: {slice_.source} → {slice_.sink} "
        f"score={slice_.score:.2f}{reasons}"
    )
