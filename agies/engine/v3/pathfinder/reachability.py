"""Source → Sink reachability matrix.

Computes which source functions can reach which sink types through the
static call graph.  This is the deterministic foundation that replaces
the LLM guessing "can this parameter reach that sink?".

Three capabilities:
1. **Static call graph enhancement** — forward+reverse transitive closure
2. **Reachability matrix** — for each source, which sink types are reachable
3. **CPG-based data flow query** — "does parameter P reach sink call S?"

Usage::

    from agies.engine.v3.pathfinder.reachability import ReachabilityMatrix

    matrix = ReachabilityMatrix(index, extra_sinks={...})
    matrix.compute()

    # Which sinks can "handle_request" reach?
    for sink_name, vtype in matrix.get_reachable_sinks("handle_request"):
        print(f"  {sink_name} -> {vtype}")

    # Which sources can reach "exec"?
    for src in matrix.get_reachable_sources("exec"):
        print(f"  {src}")
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agies.engine.v2.sourcer.models import FunctionIndex
from agies.engine.v3.codeql.models import VulnType
from agies.engine.v3.pathfinder.sink_patterns import classify_sink

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Source function auto-detection
# ──────────────────────────────────────────────────────────────────────

_SOURCE_PATTERNS = [
    # Web framework handlers
    "handle_", "process_", "dispatch_", "route_",
    "middleware", "intercept",
    # HTTP-method-named functions
    "get", "post", "put", "delete", "patch", "head", "options",
    # Method prefixes common in Django/Flask/Starlette views
    "get_", "post_", "put_", "delete_", "patch_",
    # Framework entry points
    "as_view", "view_func", "endpoint",
    # ASGI/WSGI
    "__call__",  # ASGI app entry point
    "run",       # CLI entry points
    "main",      # Script entry points
]


def auto_detect_sources(index: FunctionIndex) -> dict[str, str]:
    """Auto-detect source functions from the function index.

    Returns ``{func_name: reason}`` — e.g. ``{"handle_request": "handle_ pattern"}``.
    """
    sources: dict[str, str] = {}

    # Check edge cases: first try the call graph
    # Functions with no callers are potential entry points
    all_funcs = {fn.name for fn in index.funcs}
    called_funcs: set[str] = set()
    if index.call_graph:
        # Reverse graph has callee → set[caller]. So reverse keys are callees.
        called_funcs = set(index.call_graph.keys())

    for fn in index.funcs:
        name = fn.name
        if name in sources:
            continue

        # Pattern-based detection
        for pattern in _SOURCE_PATTERNS:
            if name == pattern or name.startswith(pattern):
                sources[name] = f"{pattern} pattern"
                break

        # Functions in the project with no callers are likely entry points
        if name not in sources and name not in called_funcs:
            # Check if it's not a private/helper
            if not name.startswith("_") and name not in sources:
                # Only flag if it has reasonable params (takes arguments)
                if "def " in fn.signature and "(" in fn.signature:
                    # Quick check: has at least one param besides self/cls
                    sig = fn.signature.split("(")[1].split(")")[0] if "(" in fn.signature else ""
                    params = [p.strip() for p in sig.split(",") if p.strip() and p.strip() not in ("self", "cls", "")]
                    if len(params) >= 1:
                        sources[name] = "uncalled function with params"

    logger.info(
        "Reachability: %d source functions detected",
        len(sources),
    )
    return sources


# ──────────────────────────────────────────────────────────────────────
# Call graph transitive closure
# ──────────────────────────────────────────────────────────────────────


def build_forward_graph(index: FunctionIndex) -> dict[str, set[str]]:
    """Build forward call graph ``{caller: {callees}}`` from the reverse index.

    ``index.call_graph`` is ``callee → {callers}``.  This inverts it.
    """
    forward: dict[str, set[str]] = defaultdict(set)

    if not index.call_graph:
        return dict(forward)

    for callee, callers in index.call_graph.items():
        for caller in callers:
            forward[caller].add(callee)

    return dict(forward)


def _bfs_closure(
    forward_graph: dict[str, set[str]],
    start_node: str,
    max_depth: int,
) -> tuple[str, set[str]]:
    """BFS from *start_node* — helper for ``compute_transitive_closure``."""
    visited: set[str] = set()
    queue = deque([(start_node, 0)])
    while queue:
        current, depth = queue.popleft()
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        for callee in forward_graph.get(current, set()):
            if callee not in visited:
                queue.append((callee, depth + 1))
    visited.discard(start_node)
    return start_node, visited


def compute_transitive_closure(
    forward_graph: dict[str, set[str]],
    max_depth: int = 15,
) -> dict[str, set[str]]:
    """BFS transitive closure of the call graph from each node.

    Returns ``{func_name: {transitively_reachable_funcs}}``.
    """
    closure: dict[str, set[str]] = {}
    workers = min(8, (os.cpu_count() or 1) + 4)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        fut_to_node = {
            executor.submit(_bfs_closure, forward_graph, n, max_depth): n
            for n in list(forward_graph.keys())
        }
        for future in as_completed(fut_to_node):
            start, visited = future.result()
            closure[start] = visited

    return closure


# ──────────────────────────────────────────────────────────────────────
# Reachability matrix
# ──────────────────────────────────────────────────────────────────────


def _bfs_source(
    forward: dict[str, set[str]],
    sink_map: dict[str, VulnType],
    src_name: str,
    max_depth: int = 15,
) -> tuple[str, list[tuple[str, VulnType]]] | tuple[str, None]:
    """BFS from *src_name* through *forward*, collecting reachable sinks.

    Helper for ``ReachabilityMatrix.compute()`` — thread-safe per-source.
    Returns ``(src_name, list[(sink, VulnType)])`` or ``(src_name, None)``.
    """
    reachable: list[tuple[str, VulnType]] = []
    visited: set[str] = set()
    queue = deque([(src_name, 0)])
    while queue:
        current, depth = queue.popleft()
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        if current in sink_map:
            reachable.append((current, sink_map[current]))
        for callee in forward.get(current, set()):
            if callee not in visited:
                queue.append((callee, depth + 1))
    return src_name, reachable if reachable else None


class ReachabilityMatrix:
    """Source → Sink reachability matrix.

    After calling ``.compute()``, you can query:
    - ``get_reachable_sinks(source_name)`` → list of ``(sink_name, VulnType)``
    - ``get_reachable_sources(sink_name)`` → list of source names
    - ``get_all_pairs()`` → list of ``(source, sink_name, VulnType)``
    """

    def __init__(
        self,
        index: FunctionIndex,
        extra_sinks: dict[str, VulnType] | None = None,
    ) -> None:
        self._index = index
        self._extra_sinks = extra_sinks or {}
        self._sources: dict[str, str] = {}  # func_name → detection_reason
        self._matrix: dict[str, list[tuple[str, VulnType]]] = {}
        # source_name → [(sink_name, VulnType), ...]
        self._reverse: dict[str, list[str]] = {}
        # sink_name → [source_name, ...]
        self._closure: dict[str, set[str]] = {}
        self._computed = False

    def compute(self) -> None:
        """Build the matrix: detect sources → transitive closure → filter sinks."""
        index = self._index
        if not index or not index.funcs:
            logger.warning("ReachabilityMatrix: empty index")
            self._computed = True
            return

        # 1. Detect source functions
        self._sources = auto_detect_sources(index)

        # 2. Build forward graph + transitive closure from sources only
        #    (we only need closure from source nodes)
        forward = build_forward_graph(index)

        # 3. For each source, compute which sink functions are reachable
        #    Pre-build sink lookup for fast checking
        sink_map: dict[str, VulnType] = {}
        for fn in index.funcs:
            vtype = classify_sink(fn.name)
            if vtype is None:
                vtype = self._extra_sinks.get(fn.name)
            if vtype is not None:
                sink_map[fn.name] = vtype

        if not sink_map:
            logger.info("ReachabilityMatrix: no sinks found in project")
            self._computed = True
            return

        # 4. Compute matrix: for each source, BFS → check if reachable func is a sink
        source_list = list(self._sources.keys())
        workers = min(8, (os.cpu_count() or 1) + 4)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            fut_to_src = {
                executor.submit(_bfs_source, forward, sink_map, src): src
                for src in source_list
            }
            for future in as_completed(fut_to_src):
                src_name, reachable = future.result()
                if reachable is not None:
                    self._matrix[src_name] = reachable

        # 5. Build reverse index: sink_name → [source_name, ...]
        for src_name, sink_list in self._matrix.items():
            for sink_name, _ in sink_list:
                self._reverse.setdefault(sink_name, []).append(src_name)

        # 6. Store transitive closure for agent queries
        self._closure = compute_transitive_closure(forward)

        self._computed = True
        total_pairs = sum(len(v) for v in self._matrix.values())
        logger.info(
            "Reachability: %d source→sink pairs (%d sources, %d sinks)",
            total_pairs, len(self._matrix), len(sink_map),
        )

    # ── Query API ──

    def get_reachable_sinks(self, source_name: str) -> list[tuple[str, VulnType]]:
        """Get all (sink_name, VulnType) reachable from *source_name*."""
        if not self._computed:
            return []
        return self._matrix.get(source_name, [])

    def get_reachable_sources(self, sink_name: str) -> list[str]:
        """Get all source function names that can reach *sink_name*."""
        if not self._computed:
            return []
        return self._reverse.get(sink_name, [])

    def get_all_pairs(self) -> list[tuple[str, str, VulnType]]:
        """Get all ``(source_name, sink_name, VulnType)`` triples."""
        if not self._computed:
            return []
        pairs: list[tuple[str, str, VulnType]] = []
        for src_name, sink_list in self._matrix.items():
            for sink_name, vtype in sink_list:
                pairs.append((src_name, sink_name, vtype))
        return pairs

    def is_reachable(self, source_name: str, sink_name: str) -> bool:
        """Check if *source_name* can transitively reach *sink_name*."""
        if not self._computed:
            return False
        sink_list = self._matrix.get(source_name, [])
        return any(sink_name == s for s, _ in sink_list)

    def get_closure(self, func_name: str) -> set[str]:
        """Get all functions transitively reachable from *func_name*.
        Returns empty set for unknown functions."""
        return self._closure.get(func_name, set())

    @property
    def sources(self) -> dict[str, str]:
        """Auto-detected source functions and their detection reason."""
        return dict(self._sources)

    @property
    def stats(self) -> dict[str, int]:
        """Summary statistics."""
        return {
            "sources": len(self._sources),
            "sinks": len(set(s for sinks in self._matrix.values() for s, _ in sinks)),
            "pairs": sum(len(v) for v in self._matrix.values()),
        }
