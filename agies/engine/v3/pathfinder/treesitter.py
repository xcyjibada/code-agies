"""Tree-sitter based path discovery — replaces CodeQL Phase A.

Uses the existing ``agies.engine.v2.sourcer`` (extractor + loader) to
build a project-wide call graph, then discovers source→sink paths by:

1. Building a ``FunctionIndex`` with full call graph
2. Searching all function names for sink patterns (exec, eval, open, …)
3. For each sink, BFS backwards through the call graph to build call chains
4. Packaging each chain as a ``CodeQlPath`` object

The output is identical to what ``CodeQLQueryRunner`` would produce, so
downstream modules (slicer → prompts → agents) work unchanged.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agies.engine.v2.sourcer.loader import build_index
from agies.engine.v2.sourcer.models import FunctionIndex, SourceFunction

from agies.engine.v3.codeql.models import (
    CodeQlPath,
    PathNode,
    QueryResult,
    Reachability,
    VulnType,
    VULN_LABELS,
)
from agies.engine.v3.pathfinder.sink_patterns import (
    classify_sink,
    classify_sensitive_body,
    detect_logic_signal,
    SENSITIVE_CALL_PATTERNS,
    KNOWN_SINK_NAMES,
)
from agies.engine.v3.pathfinder.framework_sinks import (
    detect_frameworks,
    find_framework_sinks,
)

logger = logging.getLogger(__name__)

# How many caller-hops to trace back from a sink (max path depth).
_MAX_BACKTRACK_DEPTH = 8


class TreeSitterPathFinder:
    """Phase A path discovery using tree-sitter (no CodeQL needed).

    Usage::

        finder = TreeSitterPathFinder(project_path)
        results = finder.run_all()
        for r in results:
            print(f"{r.label}: {r.total_sinks} sinks")

    The output ``list[QueryResult]`` matches what ``CodeQLQueryRunner.run_all()``
    returns, so it can be plugged directly into the existing v3 pipeline.
    """

    def __init__(
        self,
        project_path: str,
        *,
        max_depth: int = _MAX_BACKTRACK_DEPTH,
        excluded_dirs: set[str] | None = None,
        extra_sinks: dict[str, VulnType] | None = None,
    ) -> None:
        self._project_path = os.path.abspath(project_path)
        self._max_depth = max_depth
        self._excluded_dirs = excluded_dirs or {
            ".git", "__pycache__", "node_modules", "venv", ".venv",
            "dist", "build", ".tox", ".eggs", "egg-info",
            ".mypy_cache", ".pytest_cache",
        }
        self._index: FunctionIndex | None = None
        self._cpg_builder: Any = None  # CpgBuilder (lazy, optional)
        self._extra_sinks: dict[str, VulnType] = extra_sinks or {}
        """Phase 0 LLM-discovered sinks — checked when classify_sink() returns None."""

    # ------------------------------------------------------------------
    # Extra sinks from Phase 0
    # ------------------------------------------------------------------

    def set_extra_sinks(self, sinks: dict[str, VulnType]) -> None:
        """Inject Phase 0 LLM-discovered sinks.

        These are checked in ``run_all()`` after the static ``classify_sink()``
        returns ``None``, allowing dynamic sink discovery to augment the
        hand-maintained pattern list.
        """
        self._extra_sinks = dict(sinks)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_index(self) -> FunctionIndex:
        """Build the function index with call graph.

        Can be called separately to inspect the index before running queries.
        """
        if self._index is None:
            logger.info("TreeSitterPathFinder: building index for %s", self._project_path)
            self._index = build_index(
                project_path=self._project_path,
            )
            logger.info(
                "TreeSitterPathFinder: %d functions, %d files",
                len(self._index.funcs),
                len(self._index.sources),
            )
        return self._index

    def build_cpg(self) -> None:
        """Build the CPG for data flow evidence (lazy, optional).

        Called automatically by ``run_all()``.  Can be called separately
        to control timing or skip CPG build entirely.
        """
        if self._cpg_builder is not None:
            return
        from agies.engine.v3.graph.builder import CpgBuilder  # lazy import
        self._cpg_builder = CpgBuilder(
            self._project_path,
            excluded_dirs=self._excluded_dirs,
        )
        self._cpg_builder.build()

    def _enrich_with_cpg(
        self,
        path: CodeQlPath,
        sink_fn: SourceFunction,
    ) -> None:
        """Add CPG data flow evidence to a CodeQlPath (in-place).

        Traces WRITES_TO edges within the sink function's line range
        from the sink call argument back to function parameters or
        source values.  Stores a human-readable chain on
        ``path.cpg_data_flow_evidence``.
        """
        if self._cpg_builder is None or not self._cpg_builder.built:
            return

        G = self._cpg_builder.graph
        from agies.engine.v3.graph.models import (
            WRITES_TO, ATTR_TEXT, ATTR_LINE,
        )

        # Build {var_name → [(val_text, line_number)]} within sink fn scope
        fn_start = sink_fn.line_start
        fn_end = sink_fn.line_end
        assignments: dict[str, list[tuple[str, int]]] = defaultdict(list)

        for u, v, d in G.edges(data=True):
            if d.get("relationship") != WRITES_TO:
                continue
            u_line = G.nodes[u].get(ATTR_LINE, 0)
            if u_line < fn_start or u_line > fn_end:
                continue
            var_text = G.nodes[v].get(ATTR_TEXT, "")
            val_text = G.nodes[u].get(ATTR_TEXT, "")
            if var_text and val_text:
                assignments[var_text].append((val_text, u_line))

        if not assignments:
            return

        # Extract sink call arguments from the function body
        sink_name = path.body_sink_call or sink_fn.name
        body = sink_fn.body or ""
        arg_names: list[str] = []
        m = re.search(rf'\b{re.escape(sink_name)}\s*\(([^)]*)\)', body)
        if m:
            arg_names = [a.strip() for a in m.group(1).split(",") if a.strip()]
        if not arg_names:
            return

        # Skips names that should not be traced (Python discard convention)
        def _is_traceable(name: str) -> bool:
            return bool(name) and name != "_" and not name.startswith("__")

        # Trace the first argument backwards through assignments
        arg_name = arg_names[0]
        if not _is_traceable(arg_name):
            return
        known_vars = {v for v in assignments if _is_traceable(v)}
        current = arg_name
        steps: list[str] = []
        visited: set[str] = set()

        for _ in range(12):  # max 12 hops
            if current in visited or not _is_traceable(current):
                break
            visited.add(current)

            if current not in assignments:
                break
            val_text, val_line = assignments[current][-1]

            # Skip self-assignments
            if val_text == current:
                break

            # Truncate long expressions
            display_val = val_text[:50] + "…" if len(val_text) > 50 else val_text
            steps.append(f"{display_val} → {current} (L{val_line})")

            # Determine next variable to trace
            if val_text in known_vars:
                current = val_text
            else:
                tokens = re.split(r"[\s+\-*/%()\[\]{},.:;=<>!&|^~'\"]+", val_text)
                next_var: str | None = None
                for t in tokens:
                    if t in known_vars and t != current and t != arg_name:
                        next_var = t
                        break
                if next_var is not None:
                    current = next_var
                else:
                    break

        if steps:
            path.cpg_data_flow_evidence = "CPG: " + " → ".join(steps)

    def run_all(self) -> list[QueryResult]:
        """Run all sink queries against the project.

        Returns one ``QueryResult`` per vulnerability type with the
        discovered paths.
        """
        start = time.time()
        index = self.build_index()

        if not index.funcs:
            logger.warning("TreeSitterPathFinder: no functions found in %s", self._project_path)
            return []

        # Build CPG for data flow evidence enrichment
        self.build_cpg()

        # Discover sinks grouped by VulnType
        sinks_by_type: dict[VulnType, list[SourceFunction]] = defaultdict(list)
        for fn in index.funcs:
            vtype = classify_sink(fn.name)
            if vtype is None and self._extra_sinks:
                vtype = self._extra_sinks.get(fn.name)
            if vtype is not None:
                sinks_by_type[vtype].append(fn)

        # Build results per VulnType
        results: list[QueryResult] = []
        for vtype in VulnType:
            if vtype == VulnType.UNKNOWN:
                continue
            sinks = sinks_by_type.get(vtype, [])
            label = VULN_LABELS.get(vtype, str(vtype))

            if not sinks:
                results.append(QueryResult(
                    vuln_type=vtype,
                    label=label,
                    total_sinks=0,
                    paths=[],
                    duration_seconds=time.time() - start,
                ))
                continue

            paths: list[CodeQlPath] = []
            workers = min(8, (os.cpu_count() or 1) + 4)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                fut_to_fn = {
                    executor.submit(self._build_path, index, sink_fn, vtype): sink_fn
                    for sink_fn in sinks[:20]
                }
                for future in as_completed(fut_to_fn):
                    try:
                        path = future.result()
                    except Exception:
                        logger.exception(
                            "Path build failed for '%s'", fut_to_fn[future].name
                        )
                        continue
                    if path is not None:
                        self._enrich_with_cpg(path, fut_to_fn[future])
                        paths.append(path)

            results.append(QueryResult(
                vuln_type=vtype,
                label=label,
                total_sinks=len(paths),
                paths=paths,
                duration_seconds=time.time() - start,
            ))

        elapsed = time.time() - start
        total = sum(r.total_sinks for r in results)
        logger.info(
            "TreeSitterPathFinder: %d queries, %d sinks total (%.1fs)",
            len(results), total, elapsed,
        )

        # Second pass: sensitive body detection
        # Cap per-vuln-type to 20 (same as named-sink cap on line 138) to
        # prevent OOM on large codebases where broad patterns like \bopen\(,
        # \bexecute\b, or re\.match match thousands of functions.
        # ── Tree-sitter based import alias resolution (op.md) ──
        # Resolve "from lxml import etree" → etree.parse → lxml.etree.parse
        # so sink patterns (fully qualified) match aliased calls.
        # Uses a per-file cache: parse each unique file once with tree-sitter.
        _ts_parsed: dict[str, tuple[Any, bytes]] = {}
        _ts_import_maps: dict[str, dict[str, str]] = {}

        def _body_for_detection(fn: SourceFunction) -> str:
            """Return function body with import aliases expanded."""
            body = fn.body or ""
            if not body or not fn.file_path:
                return body
            if fn.file_path not in _ts_import_maps:
                try:
                    from agies.engine.v2.sourcer.extractor import _get_parser
                    _, parser = _get_parser("python")
                    with open(fn.file_path, "rb") as f:
                        source_bytes = f.read()
                    tree = parser.parse(source_bytes)
                    root_node = tree.root_node
                    _ts_parsed[fn.file_path] = (root_node, source_bytes)
                    _ts_import_maps[fn.file_path] = _parse_local_imports(
                        root_node, source_bytes,
                    )
                except Exception:
                    _ts_import_maps[fn.file_path] = {}
            aliases = _ts_import_maps.get(fn.file_path, {})
            if not aliases:
                return body

            # Expand aliases in body: replace alias. → qualified. using regex
            expanded = body
            for alias, qualified in sorted(aliases.items(), key=lambda x: -len(x[0])):
                expanded = re.sub(
                    rf'\b{re.escape(alias)}\.',
                    f'{qualified}.',
                    expanded,
                )
            return expanded

        sensitive_count = 0
        _body_per_type: dict[VulnType, int] = defaultdict(int)
        _max_body_per_type = 20
        for fn in index.funcs:
            if classify_sink(fn.name) is not None:
                continue
            if self._extra_sinks and fn.name in self._extra_sinks:
                continue
            if not fn.body:
                continue
            vtype = classify_sensitive_body(_body_for_detection(fn))
            if vtype is None:
                continue
            if _body_per_type[vtype] >= _max_body_per_type:
                continue
            _body_per_type[vtype] += 1
            path = self._build_path(index, fn, vtype, body_detected=True)
            if path is None:
                continue
            self._enrich_with_cpg(path, fn)

            # Tag as body-detected and record the match for sorter scoring.
            # _build_body_only_path already sets these fields for orphans,
            # but for paths with callers the post-hoc tagging is still needed.
            if not path.body_detected:
                path.body_detected = True
            if not path.body_sink_call:
                # Use expanded body (with import alias resolution) so fully-qualified
                # sink patterns like lxml\.etree\.parse match aliased calls like
                # etree.parse after from lxml import etree.
                expanded = _body_for_detection(fn)
                for pattern, vt in SENSITIVE_CALL_PATTERNS:
                    if vt == vtype:
                        m = pattern.search(expanded)
                        if m:
                            raw = m.group().strip("(")
                            # Extract just the function call name for SINK_WEIGHTS lookup.
                            # e.g. "BeautifulSoup(fp, \"xml\")" → "BeautifulSoup"
                            call_name = raw.split("(")[0].split()[0].strip(".")
                            path.body_sink_call = call_name or raw
                            break
            if not path.body_sink_call:
                path.body_sink_call = vtype.value
            sensitive_count += 1
            found = False
            for r in results:
                if r.vuln_type == vtype:
                    r.paths.append(path)
                    r.total_sinks = len(r.paths)
                    found = True
                    break
            if not found:
                results.append(QueryResult(
                    vuln_type=vtype,
                    label=VULN_LABELS.get(vtype, str(vtype)),
                    total_sinks=1,
                    paths=[path],
                    duration_seconds=time.time() - start,
                ))

        if sensitive_count:
            logger.info(
                "TreeSitterPathFinder: +%d sensitive-body paths (Explore candidates)",
                sensitive_count,
            )

        # Third pass: attribute taint bridge detection
        bridges = self._find_attr_taint_bridges(index)
        if bridges:
            logger.info(
                "TreeSitterPathFinder: +%d attribute taint bridge paths",
                len(bridges),
            )
            for path in bridges:
                # Enrich bridge paths with CPG data flow evidence
                sink_fns = index.lookup(path.sink)
                if sink_fns:
                    self._enrich_with_cpg(path, sink_fns[0])
                vt = path.vuln_type
                found = False
                for r in results:
                    if r.vuln_type == vt:
                        r.paths.append(path)
                        r.total_sinks = len(r.paths)
                        found = True
                        break
                if not found:
                    results.append(QueryResult(
                        vuln_type=vt,
                        label=VULN_LABELS.get(vt, str(vt)),
                        total_sinks=1,
                        paths=[path],
                        duration_seconds=time.time() - start,
                    ))

        # Fourth pass: logic signal detection
        # Scans functions not caught by sink/body/attr passes for patterns
        # suggesting logic vulnerabilities (type confusion, TOCTOU, IDOR, etc).
        # Unlike SENSITIVE_CALL_PATTERNS, LOGIC_SIGNAL_PATTERNS detect logic
        # flaws without dangerous API calls. Classified as SUSPICIOUS so the
        # LLM determines the actual vulnerability type via guard analysis.
        logic_count = 0
        _covered_fns: set[str] = set()
        for r in results:
            for p in r.paths:
                _covered_fns.add(p.sink)
        for fn in index.funcs:
            if fn.name in _covered_fns:
                continue
            if not fn.body:
                continue
            signal = detect_logic_signal(fn.body)
            if signal is None:
                continue
            path = self._build_body_only_path(index, fn, VulnType.SUSPICIOUS)
            if path is None:
                continue
            path.body_sink_call = f"[logic:{signal}]"
            logic_count += 1
            found = False
            for r in results:
                if r.vuln_type == VulnType.SUSPICIOUS:
                    r.paths.append(path)
                    r.total_sinks = len(r.paths)
                    found = True
                    break
            if not found:
                results.append(QueryResult(
                    vuln_type=VulnType.SUSPICIOUS,
                    label=VULN_LABELS.get(VulnType.SUSPICIOUS, "Suspicious"),
                    total_sinks=1,
                    paths=[path],
                    duration_seconds=time.time() - start,
                ))

        if logic_count:
            logger.info(
                "TreeSitterPathFinder: +%d logic signal paths (Explore candidates)",
                logic_count,
            )

        # ── Fifth pass: framework-level deserialization sinks ──
        # Detect web framework auto-deserialization patterns (Stapler config.xml
        # POST, Spring @RequestBody, Django REST ModelSerializer, FastAPI Pydantic).
        # Unlike previous passes, these don't have a telltale function name — the
        # "sink" is the framework's binding mechanism triggered by annotations.
        framework_sink_count = 0
        detected_frameworks = detect_frameworks(self._project_path)
        if detected_frameworks:
            fw_sinks = find_framework_sinks(
                self._project_path, index, detected_frameworks,
            )
            if fw_sinks:
                for fullname, vtype_str in fw_sinks.items():
                    # Convert string type back to VulnType
                    try:
                        vt = VulnType(vtype_str.upper())
                    except ValueError:
                        vt = VulnType.SUSPICIOUS

                    # Find the matching function in the index
                    matched_fn = None
                    for fn in index.funcs:
                        if fn.fullname == fullname:
                            matched_fn = fn
                            break

                    if matched_fn is None:
                        continue

                    # Build path from this framework sink
                    path = self._build_path(index, matched_fn, vt)
                    if path is None:
                        path = self._build_body_only_path(index, matched_fn, vt)
                    if path is None:
                        continue

                    if not path.body_sink_call:
                        path.body_sink_call = f"[fw:{fullname}]"
                    path.body_detected = True

                    framework_sink_count += 1
                    found = False
                    for r in results:
                        if r.vuln_type == vt:
                            r.paths.append(path)
                            r.total_sinks = len(r.paths)
                            found = True
                            break
                    if not found:
                        results.append(QueryResult(
                            vuln_type=vt,
                            label=VULN_LABELS.get(vt, str(vt)),
                            total_sinks=1,
                            paths=[path],
                            duration_seconds=time.time() - start,
                        ))

            if framework_sink_count:
                logger.info(
                    "TreeSitterPathFinder: +%d framework-level sink paths (Explore candidates)",
                    framework_sink_count,
                )

        return results

    def run_one(self, vuln_type: VulnType) -> QueryResult:
        """Run a single sink query for one vulnerability type."""
        index = self.build_index()
        label = VULN_LABELS.get(vuln_type, str(vuln_type))

        sinks = [
            fn for fn in index.funcs
            if classify_sink(fn.name) == vuln_type
            or (self._extra_sinks and self._extra_sinks.get(fn.name) == vuln_type)
        ]

        if not sinks:
            return QueryResult(
                vuln_type=vuln_type, label=label,
                total_sinks=0,
            )

        start = time.time()
        paths = []
        for sink_fn in sinks[:20]:
            path = self._build_path(index, sink_fn, vuln_type)
            if path is not None:
                paths.append(path)

        return QueryResult(
            vuln_type=vuln_type, label=label,
            total_sinks=len(paths), paths=paths,
            duration_seconds=time.time() - start,
        )

    # ------------------------------------------------------------------
    # Path building
    # ------------------------------------------------------------------

    def _build_path(
        self,
        index: FunctionIndex,
        sink_fn: SourceFunction,
        vuln_type: VulnType,
        body_detected: bool = False,
    ) -> CodeQlPath | None:
        """Build a CodeQlPath for one sink function.

        Traces backwards through ``index.call_graph`` to find callers.
        Creates a path from the deepest reachable caller to the sink.

        When ``body_detected=True`` and no callers are found, creates a
        single-node path with ``reachability=BODY_ONLY`` (or
        ``EXTERNAL_API`` if the function is a confirmed public API) instead
        of discarding the finding.

        Returns ``None`` if no path can be built (isolated function and
        not body-detected).  Body-detected orphans always return a path.
        """
        # Walk backwards to find the call chain
        chain = self._backtrack(index, sink_fn.name)
        if not chain:
            # Body orphan: function has no callers inside the project.
            # For body-detected functions, create a single-node path instead
            # of discarding — the dangerous call is visible in the body.
            if body_detected:
                return self._build_body_only_path(index, sink_fn, vuln_type)
            return None

        # The chain is ordered [deepest_caller, ..., intermediate, sink]
        entry_fn_name = chain[0]
        entry_fns = index.lookup(entry_fn_name)
        source_file = entry_fns[0].file_path if entry_fns else sink_fn.file_path

        # Build path nodes
        nodes: list[PathNode] = []
        for fname in chain:
            matching = index.lookup(fname)
            if matching:
                m = matching[0]
                nodes.append(PathNode(
                    function_name=m.name,
                    file_path=m.file_path,
                    line_number=m.line_start,
                    snippet=m.body or "",
                ))

        # Virtual taint compensation: detect HTTP controller entry points.
        # When the entry function is a web route handler, inject evidence
        # that the source is externally controllable.  This prevents
        # AdversaryAgent from dismissing the path with "no external input".
        proof = _detect_http_controller(entry_fns[0] if entry_fns else None)

        path = CodeQlPath(
            vuln_type=vuln_type,
            source=entry_fn_name,
            source_file=source_file,
            source_line=chain_node_line(index, entry_fn_name),
            sink=sink_fn.name,
            sink_file=sink_fn.file_path,
            sink_line=sink_fn.line_start,
            message=f"{vuln_type.value.upper()}: {sink_fn.name} at {sink_fn.file_path}:{sink_fn.line_start}",
            is_full_path=False,  # tree-sitter can't guarantee completeness
            confidence=0.5,
            nodes=nodes,
            source_controllability_proof=proof,
        )
        return path

    def _backtrack(
        self,
        index: FunctionIndex,
        sink_name: str,
    ) -> list[str] | None:
        """BFS backward through the call graph from a sink.

        Returns a list ``[caller, ..., sink]`` — the longest discovered
        chain (fewest hops with most callers).

        Uses parent-pointer BFS (O(N) memory) instead of list-copy BFS
        (O(N·depth)) to avoid OOM on large call graphs.

        Returns ``None`` if the sink is not in the call graph at all.
        """
        # call_graph is {callee_name: {caller_names}}
        if sink_name not in index.call_graph or not index.call_graph[sink_name]:
            return None

        # Parent-pointer BFS: each node's parent is the callee that
        # discovered it (shortest path).  We also track depth so we can
        # find the node farthest from the sink.
        queue: deque[str] = deque()
        queue.append(sink_name)
        parent: dict[str, str | None] = {sink_name: None}
        depth: dict[str, int] = {sink_name: 0}

        while queue:
            current = queue.popleft()
            current_depth = depth[current]

            if current_depth >= self._max_depth:
                continue

            callers = index.call_graph.get(current, set())
            for caller in callers:
                if caller not in parent:
                    parent[caller] = current
                    depth[caller] = current_depth + 1
                    queue.append(caller)

        if len(depth) <= 1:
            # Only the sink was reachable — no callers found
            return None

        # Find the deepest node (farthest from sink)
        deepest = max(depth, key=lambda n: depth[n])  # type: ignore[arg-type]

        # Reconstruct chain from deepest → sink
        chain: list[str] = []
        node: str | None = deepest
        while node is not None:
            chain.append(node)
            node = parent[node]
        chain.reverse()

        return chain

    # ------------------------------------------------------------------
    # Body orphan handling & public API detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_public_api(fn: SourceFunction, index: FunctionIndex) -> bool:
        """Check whether a function is a public API of the library.

        A function is considered a public API when:
        1. Its name doesn't start with ``_`` (not conventionally private)
        2. It's defined at module top level (not nested in another function)
           — approximated by checking if ``fn.line_start <= 10`` (near file top)
           or if there's no indentation in its signature line.
        3. Its parent module doesn't define ``__all__`` (meaning ``from module
           import *`` would expose this function), OR the function name appears
           in ``__all__``.

        This is intentionally conservative — false negatives (missing some
        public APIs) are safer than false positives (marking internal helpers
        as public).
        """
        name = fn.name
        # Private by convention
        if name.startswith("_"):
            return False

        # Not a public API if it's inside a class (class method needs
        # separate detection — handled by the caller if needed)
        file_path = fn.file_path
        if not file_path or not os.path.isfile(file_path):
            return False

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except OSError:
            return False

        # Check for __all__ in the file
        all_match = re.search(r"__all__\s*=\s*\[([^\]]*)\]", source, re.DOTALL)
        if all_match:
            # __all__ exists — function must be listed
            all_content = all_match.group(1)
            return f"'{name}'" in all_content or f'"{name}"' in all_content

        # No __all__ — function at module level is a public API if
        # it's defined outside any class and not conventionally private
        # Check: the function definition line starts at column 0
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith(f"def {name}(") or stripped.startswith(f"async def {name}("):
                # Column 0 = module-level definition
                if line == stripped:
                    return True
                break
            if stripped.startswith("class "):
                # Entered a class — module-level public functions
                # are defined before any class definition
                pass

        return False

    def _build_body_only_path(
        self,
        index: FunctionIndex,
        sink_fn: SourceFunction,
        vuln_type: VulnType,
    ) -> CodeQlPath:
        """Create a single-node path for a body-detected orphan function.

        Determines whether the function is a public API and sets
        reachability accordingly (``EXTERNAL_API`` or ``BODY_ONLY``).
        """
        # Start with a 0.2 base confidence — no call chain
        base_confidence = 0.2

        # Detect public API
        is_api = self._detect_public_api(sink_fn, index)
        reachability = Reachability.EXTERNAL_API if is_api else Reachability.BODY_ONLY

        # Build annotation for the virtual entry point
        proof = ""
        annotation = ""
        if is_api:
            source = "[EXTERNAL_CALLER]"
            annotation = "Public API — callable from external code"
            proof = (
                "Detected as library public API (module-level function "
                "or listed in __all__). The function is exposed to external "
                "callers who control its parameters."
            )
            base_confidence = 0.35
        else:
            source = "[BODY_DETECTED]"
            annotation = (
                "Found via body regex — contains dangerous API call "
                "(e.g. pickle.load, eval, open). No call chain found "
                "within this project."
            )

        # Build nodes: virtual entry + the sink function itself
        nodes: list[PathNode] = []
        if is_api:
            nodes.append(PathNode(
                function_name=annotation,
                file_path=sink_fn.file_path,
                line_number=sink_fn.line_start,
                snippet="",
            ))
        nodes.append(PathNode(
            function_name=sink_fn.name,
            file_path=sink_fn.file_path,
            line_number=sink_fn.line_start,
            snippet=sink_fn.body or "",
        ))

        # Record the body-level sink call for sorter scoring
        body_call = ""
        for pattern, vt in SENSITIVE_CALL_PATTERNS:
            if vt == vuln_type:
                m = pattern.search(sink_fn.body or "")
                if m:
                    body_call = m.group().strip("(")
                    # Extract just callable name for SINK_WEIGHTS lookup
                    body_call = body_call.split("(")[0].split()[0].strip(".")
                    break

        path = CodeQlPath(
            vuln_type=vuln_type,
            source=source,
            source_file=sink_fn.file_path,
            source_line=sink_fn.line_start,
            sink=sink_fn.name,
            sink_file=sink_fn.file_path,
            sink_line=sink_fn.line_start,
            message=(
                f"{vuln_type.value.upper()}: {sink_fn.name} at "
                f"{sink_fn.file_path}:{sink_fn.line_start} "
                f"[{annotation}]"
            ),
            is_full_path=False,
            confidence=base_confidence,
            nodes=nodes,
            body_detected=True,
            body_sink_call=body_call,
            reachability=reachability,
            source_controllability_proof=proof,
        )
        return path

    # ------------------------------------------------------------------
    # Attribute taint bridge detection (Phase A, third pass)
    # ------------------------------------------------------------------

    _ATTR_STORE_RE = re.compile(r"self\.(\w+)\s*=\s*(\w+)")
    _CTOR_FORWARD_RE = re.compile(r"self\.__class__\(\s*self\.\w+\s*,\s*(\w+)\s*\)")
    _SELF_ATTR_REF = re.compile(r"self\.(\w+)")

    @staticmethod
    def _extract_params(signature: str) -> set[str]:
        """Extract simple parameter names from a function signature."""
        m = re.search(r"\(([^)]*)\)", signature)
        if not m:
            return set()
        params: set[str] = set()
        for p in m.group(1).split(","):
            p = p.strip()
            if p in ("self", "cls", "", "*"):
                continue
            if p.startswith("*"):
                continue
            name = p.split("=")[0].split(":")[0].strip()
            if name and name not in ("self", "cls"):
                params.add(name)
        return params

    def _find_attr_taint_bridges(
        self, index: FunctionIndex,
        max_per_type: int = 20,
    ) -> list[CodeQlPath]:
        """Third pass: detect attribute taint bridges.

        Finds functions that store parameters into ``self.ATTR`` (or
        forward them through ``self.__class__()``) and matches them to
        functions in the same file that read ``self.ATTR`` and pass it
        to a known sink.

        *max_per_type* caps the number of bridge paths per vulnerability
        type (default 20), consistent with the caps used for named-sink
        and body-detection passes to prevent OOM on large codebases.

        Returns ``list[CodeQlPath]`` for the discovered bridge paths.
        """
        # Per-file grouping (proxy for class scoping)
        file_fns: dict[str, list[SourceFunction]] = defaultdict(list)
        for fn in index.funcs:
            file_fns[fn.file_path].append(fn)

        bridges: list[CodeQlPath] = []

        for file_path, fns in file_fns.items():
            # --- Step 1: detect forwarders ---
            # A forwarder is a function that passes a parameter to the
            # constructor via self.__class__(self.X, PARAM).  The param
            # ends up stored in the new object's attribute (set in __init__).
            forwarders: dict[str, list[str]] = defaultdict(list)
            # attr → [fn_name, ...]

            # --- Step 1b: detect direct stores ---
            # A store is a function that does self.ATTR = PARAM where
            # PARAM is a function parameter.
            stores: dict[str, list[str]] = defaultdict(list)
            # attr → [fn_name, ...]

            for fn in fns:
                sig = fn.signature or ""
                params = self._extract_params(sig)
                body = fn.body or ""

                # Constructor forwarders
                for m in self._CTOR_FORWARD_RE.finditer(body):
                    param = m.group(1)
                    if param in params:
                        forwarders[param].append(fn.name)

                # Direct attr stores
                for m in self._ATTR_STORE_RE.finditer(body):
                    attr, rhs = m.group(1), m.group(2)
                    if rhs in params:
                        stores[attr].append(fn.name)

            # --- Step 2: detect attr reads to sinks ---
            # Find functions that read self.ATTR in a call to a known
            # sink or sensitive API.
            reads: dict[str, list[tuple[str, str, VulnType]]] = defaultdict(list)
            # attr → [(fn_name, sink_name, vuln_type), ...]

            for fn in fns:
                body = fn.body or ""

                # All self.ATTR references in this function
                for attr_m in self._SELF_ATTR_REF.finditer(body):
                    attr = attr_m.group(1)

                    # Check KNOWN_SINK_NAMES: sink_func(self.attr, ...)
                    for sink_name in sorted(KNOWN_SINK_NAMES, key=len, reverse=True):
                        if sink_name not in body:
                            continue
                        call_pat = re.compile(
                            r"(?:self\.\w+\.)?"
                            + re.escape(sink_name)
                            + r"\([^)]*self\."
                            + re.escape(attr)
                            + r"\b[^)]*\)"
                        )
                        if call_pat.search(body):
                            vtype = classify_sink(sink_name)
                            if vtype:
                                reads[attr].append(
                                    (fn.name, sink_name, vtype)
                                )

                    # Check SENSITIVE_CALL_PATTERNS
                    for pat, vtype in SENSITIVE_CALL_PATTERNS:
                        if not pat.search(body):
                            continue
                        # Verify self.ATTR appears near the sensitive call
                        for pc in pat.finditer(body):
                            ctx_start = max(0, pc.start() - 10)
                            ctx_end = min(len(body), pc.end() + 80)
                            ctx = body[ctx_start:ctx_end]
                            if f"self.{attr}" in ctx:
                                reads[attr].append(
                                    (fn.name, pat.pattern[:30], vtype)
                                )
                                break

            # --- Step 3: link forwarders/stores to reads ---
            _bridge_count: dict[VulnType, int] = defaultdict(int)
            for attr in set(forwarders) | set(stores) & set(reads):
                # Prefer forwarders as backtrack source (cleaner call chains)
                source_fns = forwarders.get(attr, stores.get(attr, []))
                if not source_fns:
                    continue

                # Deduplicate: one bridge per (src_fn, rd_fn, vtype)
                seen_bridges: set[tuple[str, str, VulnType]] = set()

                for src_fn_name in source_fns:
                    src_fns = index.lookup(src_fn_name)
                    if not src_fns:
                        continue
                    src_fn = src_fns[0]

                    for rd_fn_name, sink_name, vtype in reads.get(attr, []):
                        key = (src_fn_name, rd_fn_name, vtype)
                        if key in seen_bridges:
                            continue
                        seen_bridges.add(key)

                        rd_fns = index.lookup(rd_fn_name)
                        if not rd_fns:
                            continue
                        rd_fn = rd_fns[0]

                        # Build backward chain from source function
                        chain = self._backtrack(index, src_fn_name)
                        if not chain:
                            chain = [src_fn_name]

                        # Build path nodes
                        nodes: list[PathNode] = []
                        for fname in chain:
                            matching = index.lookup(fname)
                            if matching:
                                m = matching[0]
                                nodes.append(PathNode(
                                    function_name=m.name,
                                    file_path=m.file_path,
                                    line_number=m.line_start,
                                    snippet=(m.body or "")[:200],
                                ))

                        # Bridge annotation node
                        annotation = (
                            f"[attr bridge: self.{attr} stored by"
                            f" {src_fn_name} → read by {rd_fn_name}]"
                        )
                        nodes.append(PathNode(
                            function_name=annotation,
                            file_path=rd_fn.file_path,
                            line_number=rd_fn.line_start,
                            snippet=(rd_fn.body or "")[:200],
                        ))

                        path = CodeQlPath(
                            vuln_type=vtype,
                            source=chain[0] if chain else src_fn_name,
                            source_file=src_fn.file_path,
                            source_line=src_fn.line_start,
                            sink=rd_fn_name,
                            sink_file=rd_fn.file_path,
                            sink_line=rd_fn.line_start,
                            message=(
                                f"{vtype.value.upper()}: {rd_fn_name}"
                                f" reads self.{attr} (stored by"
                                f" {src_fn_name})"
                            ),
                            is_full_path=False,
                            confidence=0.4,
                            nodes=nodes,
                        )
                        _bridge_count[vtype] += 1
                        if _bridge_count[vtype] <= max_per_type:
                            bridges.append(path)

        # Log types that hit the per-type cap (indicates large project where
        # bridge pass could cause OOM without the cap).
        capped = [(vt.name, n) for vt, n in _bridge_count.items() if n > max_per_type]
        if capped:
            logger.info(
                "Attr bridge caps hit — %s (total %d per type, kept %d)",
                ", ".join(f"{vt}={n}" for vt, n in capped),
                sum(n for _, n in capped),
                max_per_type,
            )

        return bridges

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary_text(self, results: list[QueryResult]) -> str:
        """Human-readable summary."""
        lines: list[str] = []
        total = 0
        for r in results:
            tag = "  SNK"
            total += r.total_sinks

            if r.total_sinks == 0:
                lines.append(f"{tag}  {r.label}: 0 sinks")
            else:
                lines.append(f"{tag}  {r.label}: {r.total_sinks} sinks")
                for path in r.paths[:5]:
                    lines.append(f"       ↳ {path.sink} at {path.sink_file}:{path.sink_line}")

        lines.insert(0, f"TreeSitterPathFinder: {len(results)} queries, {total} sinks")
        return "\n".join(lines)

    @property
    def index(self) -> FunctionIndex | None:
        """The built function index (None before build_index() is called)."""
        return self._index


# ---------------------------------------------------------------------------
# Tree-sitter Local Import Resolver (op.md)
#
# Resolves aliased calls to fully qualified names so sink patterns like
# ``lxml\.etree\.parse`` match real code like ``etree.parse(...)`` after
# ``from lxml import etree``.
#
# Only resolves when the file actually imports the alias — zero false
# positives for unaliased calls that happen to share a prefix name.
# ---------------------------------------------------------------------------


def _parse_local_imports(
    root_node: Any,
    source_bytes: bytes,
) -> dict[str, str]:
    """Scan a file's tree-sitter AST for import statements and build an
    ``{alias: fully_qualified_name}`` mapping.

    Cases handled::

        from lxml import etree                     -> "etree": "lxml.etree"
        from lxml import etree as et               -> "et": "lxml.etree"
        from lxml.etree import parse               -> "parse": "lxml.etree.parse"
        from lxml.etree import parse as lxml_parse -> "lxml_parse": "lxml.etree.parse"
        import lxml.etree                           -> "lxml.etree": "lxml.etree"
        import lxml.etree as ET                    -> "ET": "lxml.etree"
    """

    def _text(n: Any) -> str:
        return source_bytes[n.start_byte:n.end_byte].decode("utf-8", errors="replace")

    import_map: dict[str, str] = {}

    def _walk(node: Any) -> None:
        if node.type == "import_statement":
            for child in node.children:
                if child.type == "aliased_import":
                    name_node = child.child_by_field_name("name")
                    alias_node = child.child_by_field_name("alias")
                    if name_node and alias_node:
                        import_map[_text(alias_node)] = _text(name_node)
                elif child.type == "dotted_name":
                    import_map[_text(child)] = _text(child)

        elif node.type == "import_from_statement":
            # module = after "from", e.g. "lxml" or "lxml.etree"
            module = ""
            for child in node.children:
                if child.type == "dotted_name":
                    module = _text(child)
                    break
            if not module:
                return

            for child in node.children:
                if child.type == "aliased_import":
                    name_node = child.child_by_field_name("name")
                    alias_node = child.child_by_field_name("alias")
                    if name_node and alias_node:
                        import_map[_text(alias_node)] = f"{module}.{_text(name_node)}"
                elif child.type == "dotted_name" and _text(child) != module:
                    # from X import Y (no alias)
                    import_map[_text(child)] = f"{module}.{_text(child)}"

        # Don't recurse into function/class bodies — imports at file level only
        if node.type not in ("import_statement", "import_from_statement"):
            for child in node.children:
                _walk(child)

    _walk(root_node)
    return import_map


def _get_call_path(node: Any, source_bytes: bytes) -> str:
    """Extract the raw call path string from a tree-sitter call's function node.

    Handles both simple identifiers (``parse(...)``) and attribute chains
    (``etree.parse(...)``, ``lib.lxml.etree.parse(...)``).
    """

    def _text(n: Any) -> str:
        return source_bytes[n.start_byte:n.end_byte].decode("utf-8", errors="replace")

    if node.type == "identifier":
        return _text(node)
    if node.type == "attribute":
        obj_node = node.child_by_field_name("object")
        attr_node = node.child_by_field_name("attribute")
        if obj_node and attr_node:
            return f"{_get_call_path(obj_node, source_bytes)}.{_text(attr_node)}"
    return _text(node)


def _resolve_fqn(call_path: str, import_map: dict[str, str]) -> str:
    """Resolve an aliased call path to its fully qualified name.

    Example: ``"etree.parse"`` with ``{"etree": "lxml.etree"}``
    returns ``"lxml.etree.parse"``.  Unknown prefixes pass through unchanged.
    """
    parts = call_path.split(".")
    if not parts:
        return call_path
    prefix = parts[0]
    if prefix in import_map:
        return ".".join([import_map[prefix]] + parts[1:])
    return call_path


def chain_node_line(index: FunctionIndex, func_name: str) -> int:
    """Get the line number of a function in the call chain."""
    fns = index.lookup(func_name)
    return fns[0].line_start if fns else 0


def _detect_http_controller(fn: SourceFunction | None) -> str:
    """Detect whether a function is an externally-controllable HTTP controller.

    Returns a human-readable proof string, or empty string if not detected.

    Checks:
    - Flask/FastAPI style route decorators (``@app.get``, ``@app.post``, …)
    - Parameter names that typically carry user input (``request``, ``payload``,
      ``data``, ``body``, ``query``, ``form``, ``files``, ``json``)
    """
    if fn is None:
        return ""

    sig = fn.signature or ""
    body = fn.body or ""

    # Check body for route decorators (typically on the line before the
    # function definition, included in body by tree-sitter extraction)
    route_re = re.search(
        r"@\w+\.(?:get|post|put|delete|patch|route|api_route)\b",
        body,
    )
    if route_re:
        return (
            f"Verified HTTP Controller Entrypoint ({route_re.group()}) — "
            f"input is externally controllable via HTTP request"
        )

    # Check parameter names for web framework patterns
    web_params = {"request", "payload", "data", "body", "query",
                   "form", "files", "json", "incoming"}
    sig_params = set()
    # Extract params from function signature
    pm = re.search(r"\(([^)]*)\)", sig)
    if pm:
        for p in pm.group(1).split(","):
            name = p.strip().split("=")[0].split(":")[0].strip()
            if name and name not in ("self", "cls", "", "*"):
                sig_params.add(name)

    matched = sig_params & web_params
    if matched:
        return (
            f"Verified HTTP Controller Entrypoint "
            f"(parameters: {', '.join(sorted(matched))}) — "
            f"input is externally controllable via HTTP request"
        )

    return ""

