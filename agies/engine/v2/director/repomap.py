"""Risk-weighted RepoMap — adapted from Aider's tree-sitter RepoMap.

Core changes from Aider's original:
  - Replaced diskcache → in-memory dict cache
  - Removed pygments backfill refs (rely solely on tree-sitter)
  - Removed grep_ast / TreeContext (use agies' own parser init)
  - Removed tqdm / aider.* dependencies
  - **Added SAST signal weighting** — edges involving functions that
    emit high-risk signals (sql_sink, cmd_exec, …) get their weight
    multiplied by the signal's SIGNAL_MUL factor.
  - **Added entry point personalization** — files containing entry
    points get a huge personalization boost so they rank top.
  - **Returns (G, pagerank_scores) alongside ranked tags** for the
    aggregator's has_path analysis.
"""

from __future__ import annotations

import logging
import math
import os
from collections import Counter, defaultdict, namedtuple
from pathlib import Path
from typing import Any

from tree_sitter import Language, Node, Parser, Query, QueryCursor

from agies.engine.v2.feedback import CONFIRMED_BOOST, FP_SUPPRESS_MUL

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

Tag = namedtuple("Tag", "rel_fname fname line name kind signal_type".split())


# ---------------------------------------------------------------------------
# Pure-Python PageRank (no scipy dependency)
# ---------------------------------------------------------------------------


def _pagerank_pure(
    G,
    weight: str = "weight",
    personalization: dict[str, float] | None = None,
    damping: float = 0.85,
    max_iter: int = 100,
    tol: float = 1e-6,
) -> dict[str, float]:
    """Pure-Python PageRank implementation for MultiDiGraph.

    Avoids the scipy dependency of ``networkx.pagerank()``.
    Uses the power-iteration formulation:
        PR(n) = (1-d)/N + d * sum(PR(v) * w(v→n) / out_weight(v))
    """
    nodes = list(G.nodes)
    N = len(nodes)
    if N == 0:
        return {}

    # Default personalization: uniform
    if personalization is None:
        p = {n: 1.0 / N for n in nodes}
    else:
        p = {n: personalization.get(n, 0) for n in nodes}
        total = sum(p.values())
        if total > 0:
            # Normalize so sum(p) = N (matching networkx convention)
            scale = N / total
            p = {n: v * scale for n, v in p.items()}
        else:
            p = {n: 1.0 / N for n in nodes}

    # Precompute out-weight sums per node
    out_sum: dict[str, float] = {}
    for src in nodes:
        total_wt = sum(data.get(weight, 1.0) for _, _, data in G.out_edges(src, data=True))
        out_sum[src] = total_wt if total_wt > 0 else 1.0

    # Initialize ranks
    rank = {n: 1.0 / N for n in nodes}

    for _ in range(max_iter):
        prev = rank.copy()
        dangling_sum = sum(rank[n] for n in nodes if out_sum[n] == 0)

        for n in nodes:
            # Inbound rank from edges
            inbound = 0.0
            for src, _, data in G.in_edges(n, data=True):
                w = data.get(weight, 1.0)
                if out_sum[src] > 0 and w > 0:
                    inbound += prev[src] * w / out_sum[src]

            # Dangling nodes redistribute uniformly
            inbound += dangling_sum / N

            rank[n] = (1 - damping) * p[n] / N + damping * inbound

        # Convergence check
        diff = sum(abs(rank[n] - prev[n]) for n in nodes)
        if diff < tol:
            break

    return rank


# ---------------------------------------------------------------------------
# Language detection (replaces grep_ast.filename_to_lang)
# ---------------------------------------------------------------------------

EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".cs": "c_sharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".r": "r",
    ".m": "objc",
    ".mm": "objc",
    ".scala": "scala",
    ".sc": "scala",
}


def filename_to_lang(fname: str) -> str | None:
    """Map a filename to a language id for tree-sitter + .scm lookup."""
    ext = os.path.splitext(fname)[1].lower()
    return EXT_TO_LANG.get(ext)


# ---------------------------------------------------------------------------
# Parser factory (reuses agies' existing sourcer/extractor.py pattern)
# ---------------------------------------------------------------------------

_parsers: dict[str, tuple[Language, Parser]] = {}


def _get_parser(lang: str) -> tuple[Language, Parser]:
    """Return (Language, Parser) for the given language id."""
    if lang not in _parsers:
        # Same pattern as agies/engine/sourcer/extractor.py
        if lang == "python":
            import tree_sitter_python as tspy

            language = Language(tspy.language())
        elif lang == "java":
            import tree_sitter_java as tsjava

            language = Language(tsjava.language())
        elif lang == "javascript":
            import tree_sitter_javascript as tsjs

            language = Language(tsjs.language())
        elif lang == "typescript":
            import tree_sitter_typescript as tsts

            language = Language(tsts.language_typescript())
        elif lang == "ruby":
            import tree_sitter_ruby as tsruby

            language = Language(tsruby.language())
        elif lang == "go":
            import tree_sitter_go as tsgo

            language = Language(tsgo.language())
        elif lang == "rust":
            import tree_sitter_rust as tsrust

            language = Language(tsrust.language())
        elif lang == "c_sharp":
            import tree_sitter_c_sharp as tscs

            language = Language(tscs.language())
        else:
            raise ValueError(f"Unsupported language: {lang}")

        _parsers[lang] = (language, Parser(language))
    return _parsers[lang]


# ---------------------------------------------------------------------------
# .scm query file resolution
# ---------------------------------------------------------------------------

_QUERIES_DIR = Path(__file__).parent / "queries"


def get_scm_fname(lang: str) -> Path | None:
    """Return path to the .scm query file for *lang*, or None.

    Handles the ``js-tags.scm`` → ``javascript`` naming mismatch
    (file was named ``js-tags.scm`` historically, not ``javascript-tags.scm``).
    """
    path = _QUERIES_DIR / f"{lang}-tags.scm"
    if path.exists():
        return path
    if lang == "javascript":
        fallback = _QUERIES_DIR / "js-tags.scm"
        if fallback.exists():
            return fallback
    return None


# ---------------------------------------------------------------------------
# Tag extraction
# ---------------------------------------------------------------------------


def _run_captures(query: Query, node: Node) -> dict[str, list[Node]]:
    """tree-sitter 0.23.2+ compatible capture runner."""
    if hasattr(query, "captures"):
        return query.captures(node)
    cursor = QueryCursor(query)
    return cursor.captures(node)


def get_tags_raw(fname: str, rel_fname: str):
    """Extract def/ref/signal tags from *fname* using tree-sitter + .scm queries.

    Yields ``Tag`` namedtuples.
    """
    lang = filename_to_lang(fname)
    if not lang:
        return

    try:
        language, parser = _get_parser(lang)
    except (ImportError, ValueError) as err:
        logger.debug("Skipping %s: %s", fname, err)
        return

    query_scm = get_scm_fname(lang)
    if not query_scm:
        return
    query_source = query_scm.read_text()

    try:
        with open(fname, "rb") as f:
            code = f.read()
    except OSError:
        return
    if not code:
        return

    tree = parser.parse(code)
    captures = _run_captures(Query(language, query_source), tree.root_node)

    for tag_name, nodes in captures.items():
        for node in nodes:
            kind: str | None = None
            signal_type = ""

            if tag_name.startswith("name.definition."):
                kind = "def"
            elif tag_name.startswith("name.reference."):
                kind = "ref"
            elif tag_name.startswith("signal."):
                kind = "signal"
                signal_type = tag_name.split(".", 1)[1] if "." in tag_name else ""
            else:
                continue

            yield Tag(
                rel_fname=rel_fname,
                fname=fname,
                name=node.text.decode("utf-8") if node.text else "",
                kind=kind,
                line=node.start_point[0],
                signal_type=signal_type,
            )

    # Post-processing: detect recursive functions (function calling itself)
    if lang and tree and code:
        try:
            for rec_name in _find_recursive_funcs(lang, tree, code):
                yield Tag(
                    rel_fname=rel_fname,
                    fname=fname,
                    name=rec_name,
                    kind="signal",
                    line=0,
                    signal_type="recursion",
                )
        except Exception:
            # Recursion detection is best-effort
            pass


def _find_recursive_funcs(lang: str, tree, code: bytes) -> set[str]:
    """Return set of function names that call themselves recursively.

    Works by finding function definition nodes and checking whether their
    body byte-range contains a call node with the same identifier text.
    """
    language, _parser = _get_parser(lang)
    if not language:
        return set()

    recursive: set[str] = set()

    kwargs = {}
    if hasattr(language, "query"):
        kwargs = {}

    # Query: function definitions with name + body
    func_query = _run_captures(
        Query(language, "(function_definition name: (identifier) @func_name body: (_) @func_body)"),
        tree.root_node,
    )
    func_names = func_query.get("func_name", [])
    func_bodies = func_query.get("func_body", [])

    if not func_names:
        return set()

    # Build func_name → body_byte_range mapping
    func_ranges: list[tuple[str, int, int]] = []
    # Heuristic: pair name nodes with body nodes in order (they're alternated in captures)
    for i, name_node in enumerate(func_names):
        body_node = func_bodies[i] if i < len(func_bodies) else None
        if body_node is None:
            continue
        name = (name_node.text or b"").decode("utf-8")
        if name:
            func_ranges.append((name, body_node.start_byte, body_node.end_byte))

    if not func_ranges:
        return set()

    # Query: all call expressions with simple identifier callee
    call_query = _run_captures(
        Query(language, "(call function: (identifier) @call_name)"),
        tree.root_node,
    )
    call_nodes = call_query.get("call_name", [])

    for fname, body_start, body_end in func_ranges:
        for call_node in call_nodes:
            if call_node.start_byte < body_start or call_node.end_byte > body_end:
                continue
            call_name = (call_node.text or b"").decode("utf-8")
            if call_name == fname:
                recursive.add(fname)
                break

    return recursive


# ---------------------------------------------------------------------------
# Graph building with signal weighting
# ---------------------------------------------------------------------------

def build_graph(
    fnames: list[str],
    entry_points: set[str] | None = None,
    signal_mul: dict[str, float] | None = None,
    mentioned_fnames: set[str] | None = None,
    mentioned_idents: set[str] | None = None,
    confirmed_idents: set[str] | None = None,
    suppressed_files: set[str] | None = None,
) -> tuple[Any, dict[str, float], dict, dict[str, set[Tag]]]:
    """Build a risk-weighted PageRank graph from source files.

    Steps:
      1. Extract tags (def/ref/signal) from every file.
      2. Compute per-ident ``signal_score`` from signal tags.
      3. Build a ``nx.MultiDiGraph`` where edges = referencer → definer.
         Edge weights are multiplied by the referencer's signal score.
      4. Run PageRank with entry-point personalization.
      5. Distribute rank across edges → ``ranked_definitions``.

    Returns
    -------
    G : nx.MultiDiGraph
        The call-adjacency graph with weighted edges.
    pagerank_scores : dict[str, float]
        Raw PageRank score per node (rel_fname).
    ranked_tags : list[Tag]
        Tags sorted by rank (descending).
    file_tags : dict[str, set[Tag]]
        All tags grouped by rel_fname.
    """
    import networkx as nx

    entry_points = entry_points or set()
    signal_mul = signal_mul or {}
    mentioned_fnames = mentioned_fnames or set()
    mentioned_idents = mentioned_idents or set()

    defines: dict[str, set[str]] = defaultdict(set)
    references: dict[str, list[str]] = defaultdict(list)
    definitions: dict[tuple[str, str], set[Tag]] = defaultdict(set)
    file_tags: dict[str, set[Tag]] = defaultdict(set)
    signal_scores: dict[str, float] = defaultdict(lambda: 1.0)

    personalization: dict[str, float] = {}
    personalize = 100 / max(len(fnames), 1)

    for fname in fnames:
        rel_fname = os.path.relpath(fname, os.path.commonpath(fnames)) if len(fnames) > 1 else fname
        # Actually use the root-relative path — try to get relpath from a common root.
        # For now, just use the fname as-is and compute rel_fname later.
        pass

    # First pass: collect all tags and compute base rel_fnames
    rel_map: dict[str, str] = {}
    for fname in fnames:
        # Derive rel_fname: if all paths share a common prefix, use it
        rel_map[fname] = fname  # fallback; refined below

    # Build a common-root relative path for each file
    if fnames:
        try:
            common = os.path.commonpath(fnames)
        except ValueError:
            common = ""
        for fname in fnames:
            if common and fname.startswith(common):
                rel_map[fname] = os.path.relpath(fname, common)
            else:
                rel_map[fname] = os.path.basename(fname)

    # Check if root was explicitly provided (RepoMap instance)
    # The RepoMap class below handles this properly.
    # This standalone function receives pre-computed fnames from RepoMap which
    # has self.root set.

    for fname in fnames:
        rel_fname = rel_map[fname]

        # Personalization for entry points
        current_pers = 0.0
        if fname in entry_points:
            current_pers += personalize * 10  # entry points get 10x boost
        if rel_fname in mentioned_fnames:
            current_pers += personalize

        # Path-component matching for mentioned_idents
        path_obj = Path(rel_fname)
        base_name = path_obj.name
        base_stem = path_obj.stem
        components = set(path_obj.parts) | {base_name, base_stem}
        if components & mentioned_idents:
            current_pers += personalize

        if current_pers > 0:
            personalization[rel_fname] = current_pers

        tags = list(get_tags_raw(fname, rel_fname))
        if not tags:
            continue

        file_tags[rel_fname].update(tags)

        for tag in tags:
            if tag.kind == "def":
                defines[tag.name].add(rel_fname)
                definitions[(rel_fname, tag.name)].add(tag)
            elif tag.kind == "ref":
                references[tag.name].append(rel_fname)
            elif tag.kind == "signal":
                # Accumulate signal score per identifier name
                mul = signal_mul.get(tag.signal_type, 1.0)
                # If a function name is the *target* of a signal call
                # (e.g. `execute` is the callee), boost edges involving it
                signal_scores[tag.name] *= mul

    # Fallback: if no refs, treat all defs as self-refs so graph isn't empty
    if not references:
        references = {k: list(v) for k, v in defines.items()}

    idents = set(defines.keys()) & set(references.keys())
    G = nx.MultiDiGraph()

    # Self-edges for ident with definitions but no references
    for ident in defines:
        if ident not in references:
            for definer in defines[ident]:
                G.add_edge(definer, definer, weight=0.1, ident=ident)

    # Build weighted edges
    for ident in idents:
        definers = defines[ident]

        # Base mul from Aider heuristics
        mul = 1.0
        is_snake = "_" in ident and any(c.isalpha() for c in ident)
        is_kebab = "-" in ident and any(c.isalpha() for c in ident)
        is_camel = any(c.isupper() for c in ident) and any(c.islower() for c in ident)
        if ident in mentioned_idents:
            mul *= 10
        if (is_snake or is_kebab or is_camel) and len(ident) >= 8:
            mul *= 10
        if ident.startswith("_"):
            mul *= 0.1
        if len(defines[ident]) > 5:
            mul *= 0.1

        # *** Signal weighting ***
        sig_score = signal_scores.get(ident, 1.0)
        mul *= sig_score

        for referencer, num_refs in Counter(references[ident]).items():
            for definer in definers:
                use_mul = mul
                num_refs_sqrt = math.sqrt(num_refs)
                G.add_edge(
                    referencer, definer,
                    weight=use_mul * num_refs_sqrt,
                    ident=ident,
                )

    # PageRank
    pers_args = {}
    if personalization:
        pers_args = dict(personalization=personalization, dangling=personalization)

    try:
        pr_scores = nx.pagerank(G, weight="weight", **pers_args)
    except (ZeroDivisionError, ImportError):
        try:
            pr_scores = nx.pagerank(G, weight="weight")
        except (ZeroDivisionError, ImportError):
            pr_scores = _pagerank_pure(G, weight=weight, personalization=personalization)

    if not pr_scores:
        return G, {}, [], file_tags

    # Distribute rank from source to out-edges
    ranked_defs: defaultdict[tuple[str, str], float] = defaultdict(float)
    for src in G.nodes:
        src_rank = pr_scores.get(src, 0)
        total_weight = sum(
            data["weight"] for _, _, data in G.out_edges(src, data=True)
        )
        if total_weight <= 0:
            continue
        for _, dst, data in G.out_edges(src, data=True):
            edge_rank = src_rank * data["weight"] / total_weight
            ident = data.get("ident", "")
            ranked_defs[(dst, ident)] += edge_rank

    # Sort ranked definitions
    ranked_items = sorted(ranked_defs.items(), reverse=True, key=lambda x: (x[1], x[0]))

    ranked_tags: list[Tag] = []
    for (fname, ident), rank in ranked_items:
        ranked_tags.extend(definitions.get((fname, ident), []))

    # Add files without tags at the end
    tagged_fnames = set(rt[0] for rt in ranked_tags)
    top_rank = sorted(
        [(rank, node) for node, rank in pr_scores.items()], reverse=True
    )
    for rank, fname in top_rank:
        if fname not in tagged_fnames:
            ranked_tags.append(Tag(fname, "", 0, "", "def", ""))

    return G, pr_scores, ranked_tags, file_tags


# ---------------------------------------------------------------------------
# RepoMap class (simplified — no diskcache, no pygments, no grep_ast)
# ---------------------------------------------------------------------------

class RepoMap:
    """Tag cache + PageRank orchestrator.

    Usage::

        rm = RepoMap(root="/path/to/project")
        G, pr_scores, ranked_tags, file_tags = rm.build_graph(
            fnames=[...],
            entry_points={"app.py", "cli.py"},
            signal_mul=SIGNAL_MUL,
        )
    """

    def __init__(self, root: str | None = None) -> None:
        self.root = root or os.getcwd()
        self._tags_cache: dict[str, tuple[float, list[Tag]]] = {}

    def __repr__(self) -> str:
        return f"<RepoMap root={self.root!r}>"

    # ------------------------------------------------------------------
    # File helpers
    # ------------------------------------------------------------------

    def rel_fname(self, fname: str) -> str:
        try:
            return os.path.relpath(fname, self.root)
        except ValueError:
            return fname

    def mtime(self, fname: str) -> float | None:
        try:
            return os.path.getmtime(fname)
        except OSError:
            return None

    # ------------------------------------------------------------------
    # Tag extraction (cached)
    # ------------------------------------------------------------------

    def get_tags_raw(self, fname: str) -> list[Tag]:
        """Extract tags from a file (no cache)."""
        rel = self.rel_fname(fname)
        return list(get_tags_raw(fname, rel))

    def get_tags(self, fname: str) -> list[Tag]:
        """Cached tag extraction — re-parses only if mtime changed."""
        mtime = self.mtime(fname)
        if mtime is None:
            return []

        cache_key = fname
        cached = self._tags_cache.get(cache_key)
        if cached is not None and cached[0] == mtime:
            return cached[1]

        rel = self.rel_fname(fname)
        tags = list(get_tags_raw(fname, rel))
        self._tags_cache[cache_key] = (mtime, tags)
        return tags

    def clear_cache(self) -> None:
        self._tags_cache.clear()

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def build_graph(
        self,
        fnames: list[str],
        entry_points: set[str] | None = None,
        signal_mul: dict[str, float] | None = None,
        mentioned_fnames: set[str] | None = None,
        mentioned_idents: set[str] | None = None,
        confirmed_idents: set[str] | None = None,
        suppressed_files: set[str] | None = None,
        prescan_sinks: set[str] | None = None,
    ) -> tuple[Any, dict[str, float], list[Tag], dict[str, set[Tag]]]:
        """Build risk-weighted PageRank graph.

        Returns
        -------
        G : nx.MultiDiGraph
        pagerank_scores : dict[rel_fname, float]
        ranked_tags : list[Tag] sorted by rank
        file_tags : dict[rel_fname, set[Tag]]
        """
        import networkx as nx

        entry_points = entry_points or set()
        signal_mul = signal_mul or {}
        mentioned_fnames = mentioned_fnames or set()
        mentioned_idents = mentioned_idents or set()
        confirmed_idents = confirmed_idents or set()
        suppressed_files = suppressed_files or set()
        prescan_sinks = prescan_sinks or set()

        defines: dict[str, set[str]] = defaultdict(set)
        references: dict[str, list[str]] = defaultdict(list)
        definitions: dict[tuple[str, str], set[Tag]] = defaultdict(set)
        file_tags: dict[str, set[Tag]] = defaultdict(set)
        signal_scores: dict[str, float] = defaultdict(lambda: 1.0)

        personalize = 100 / max(len(fnames), 1)
        personalization: dict[str, float] = {}

        for fname in fnames:
            rel = self.rel_fname(fname)

            # Personalization
            pers = 0.0
            if fname in entry_points or rel in entry_points:
                pers += personalize * 10  # entry points get 10x boost
            if rel in mentioned_fnames:
                pers += personalize
            if rel in prescan_sinks:
                pers += personalize * 100  # 100x boost for critical sinks
            # Path-component matching for mentioned_idents
            path_obj = Path(rel)
            components = set(path_obj.parts) | {path_obj.name, path_obj.stem}
            if components & mentioned_idents:
                pers += personalize
            if pers > 0:
                personalization[rel] = pers

            tags = self.get_tags(fname)
            if not tags:
                continue

            file_tags[rel].update(tags)

            for tag in tags:
                if tag.kind == "def":
                    defines[tag.name].add(rel)
                    definitions[(rel, tag.name)].add(tag)
                elif tag.kind == "ref":
                    references[tag.name].append(rel)
                elif tag.kind == "signal":
                    # Accumulate signal score per ident name
                    mul = signal_mul.get(tag.signal_type, 1.0)
                    # P5: suppress signals in FP-heavy files
                    if tag.rel_fname in suppressed_files:
                        mul *= FP_SUPPRESS_MUL
                    signal_scores[tag.name] *= mul

        # Fallback: if no refs found, treat defs as self-refs
        if not references:
            references = {k: list(v) for k, v in defines.items()}

        idents = set(defines.keys()) & set(references.keys())
        G = nx.MultiDiGraph()

        # Self-edges for ident with defs but no refs
        for ident in defines:
            if ident not in references:
                for definer in defines[ident]:
                    G.add_edge(definer, definer, weight=0.1, ident=ident)

        # Build weighted edges
        for ident in idents:
            definers = defines[ident]

            mul = 1.0
            is_snake = "_" in ident and any(c.isalpha() for c in ident)
            is_kebab = "-" in ident and any(c.isalpha() for c in ident)
            is_camel = any(c.isupper() for c in ident) and any(c.islower() for c in ident)
            if ident in mentioned_idents:
                mul *= 10
            if (is_snake or is_kebab or is_camel) and len(ident) >= 8:
                mul *= 10
            if ident.startswith("_"):
                mul *= 0.1
            if len(defines[ident]) > 5:
                mul *= 0.1

            # *** Signal weighting ***
            sig_score = signal_scores.get(ident, 1.0)
            mul *= sig_score

            # P5: confirmed vuln boost
            if ident in confirmed_idents:
                mul *= CONFIRMED_BOOST

            for referencer, num_refs in Counter(references[ident]).items():
                for definer in definers:
                    use_mul = mul
                    num_refs_sqrt = math.sqrt(num_refs)
                    G.add_edge(
                        referencer, definer,
                        weight=use_mul * num_refs_sqrt,
                        ident=ident,
                    )

        # PageRank (pure-Python implementation — no scipy dependency)
        pr_scores = _pagerank_pure(G, weight="weight", personalization=personalization)
        if not pr_scores:
            return G, {}, [], file_tags

        # Distribute rank to definitions
        ranked_defs: defaultdict[tuple[str, str], float] = defaultdict(float)
        for src in G.nodes:
            src_rank = pr_scores.get(src, 0)
            total_wt = sum(
                data["weight"] for _, _, data in G.out_edges(src, data=True)
            )
            if total_wt <= 0:
                continue
            for _, dst, data in G.out_edges(src, data=True):
                edge_rank = src_rank * data["weight"] / total_wt
                ranked_defs[(dst, data.get("ident", ""))] += edge_rank

        ranked_items = sorted(ranked_defs.items(), reverse=True, key=lambda x: (x[1], x[0]))
        ranked_tags: list[Tag] = []
        for (fname, ident), _rank in ranked_items:
            ranked_tags.extend(definitions.get((fname, ident), []))

        return G, pr_scores, ranked_tags, file_tags

    # ------------------------------------------------------------------
    # Convenience: get neighbors for recursive expansion
    # ------------------------------------------------------------------

    def get_neighbors(
        self,
        symbol: str,
        file_tags: dict[str, set[Tag]],
    ) -> list[Tag]:
        """Return tags related to *symbol* — its callers and callees.

        Scans all file_tags for defs/refs of *symbol* and neighbors that
        share a file with it.
        """
        related: list[Tag] = []
        for rel_fname, tags in file_tags.items():
            for tag in tags:
                if tag.name == symbol:
                    related.append(tag)
                # Also include other tags in the same file that reference
                # or define this symbol
        # Deduplicate
        seen: set[tuple[str, str, int]] = set()
        result: list[Tag] = []
        for tag in related:
            key = (tag.rel_fname, tag.name, tag.line)
            if key not in seen:
                seen.add(key)
                result.append(tag)
        return result
