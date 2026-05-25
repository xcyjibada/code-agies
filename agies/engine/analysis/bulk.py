"""Phase 1 bulk analysis — parallel LLM calls over all functions.

Two modes (from REFACTOR.md):
- **Single-function**: one LLM call per function (high concurrency)
- **Multi-function (chunked)**: one LLM call per chunk of related files

Uses ThreadPoolExecutor for parallel sync LLM calls (the LLM provider
layer is synchronous).
"""

from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agies.engine.analysis.prompts import (
    MULTI_FUNCTION_SYSTEM,
    MULTI_FUNCTION_USER,
    SINGLE_FUNCTION_SYSTEM,
    SINGLE_FUNCTION_USER,
)
from agies.engine.sourcer.models import (
    BulkAnalysisOutput,
    CandidateFinding,
    FunctionIndex,
    SourceFunction,
)

logger = logging.getLogger(__name__)


_SINK_TYPE_MAP: dict[str, str] = {
    # Deserialization sinks
    "shelve.open": "deserialization",
    "shelve.DbfilenameShelf": "deserialization",
    "pickle.load": "deserialization",
    "pickle.loads": "deserialization",
    "pickle.Unpickler": "deserialization",
    "yaml.load": "deserialization",
    "jsonpickle": "deserialization",
    "marshal.load": "deserialization",
    "marshal.loads": "deserialization",
    # Command injection / RCE
    "eval": "rce",
    "exec": "rce",
    "compile": "rce",
    "os.system": "command_injection",
    "os.popen": "command_injection",
    "subprocess.Popen": "command_injection",
    "subprocess.run": "command_injection",
    "subprocess.call": "command_injection",
    "subprocess.check_output": "command_injection",
    # Path traversal
    "zipfile.extractall": "path_traversal",
    "zipfile.extract": "path_traversal",
    "tarfile.extractall": "path_traversal",
    "tarfile.extract": "path_traversal",
}


# Deterministic body-scan patterns — function bodies containing these
# substrings get a candidate injected regardless of LLM behavior.
# The LLM sometimes misses obvious sinks (shelve.open, subprocess.run)
# in trivial wrapper functions.  This over-zealous pre-scan catches them.
_BODY_SINK_PATTERNS: list[tuple[str, str, str]] = [
    # (substring, sink_name, vuln_type)
    ("shelve.open(", "shelve.open", "deserialization"),
    ("pickle.load(", "pickle.load", "deserialization"),
    ("pickle.loads(", "pickle.loads", "deserialization"),
    ("yaml.load(", "yaml.load", "deserialization"),
    ("subprocess.run(", "subprocess.run", "command_injection"),
    ("subprocess.Popen(", "subprocess.Popen", "command_injection"),
    ("os.system(", "os.system", "command_injection"),
    ("os.popen(", "os.popen", "command_injection"),
    ("eval(", "eval", "rce"),
    ("exec(", "exec", "rce"),
    ("zipfile.extractall(", "zipfile.extractall", "path_traversal"),
    ("tarfile.extractall(", "tarfile.extractall", "path_traversal"),
]


def _pre_scan_body(fn: SourceFunction) -> list[CandidateFinding]:
    """Deterministic body pre-scan — inject candidates for known sink calls
    without waiting for the LLM.  This is NOT a SAST rule (no tree-sitter,
    no YAML config), just a simple substring scan that catches obvious sinks
    the LLM might miss in trivial wrappers or when data flow is invisible."""
    findings: list[CandidateFinding] = []
    body = fn.body
    for substr, sink_name, vuln_type in _BODY_SINK_PATTERNS:
        if substr in body:
            # Find the line number containing this pattern
            line_num = fn.line_start
            for i, line in enumerate(body.split("\n")):
                if substr in line:
                    line_num = fn.line_start + i
                    break
            # High-risk sink types use "high" severity so they compete with
            # LLM-reported path_traversal findings during pruning.
            _sev = "high" if vuln_type in ("deserialization", "rce", "command_injection") else "medium"
            findings.append(CandidateFinding(
                type=vuln_type,
                severity=_sev,
                file_path=fn.file_path,
                function_name=fn.fullname,
                line_number=line_num,
                source_line=fn.signature,
                reason=f"Body pattern '{substr}' found in function — potential {vuln_type} sink.",
                sink_type=sink_name,
                confidence="medium",
            ))
    return findings


def _sink_type(name: str) -> str:
    """Map a sink name to a vulnerability type for scoring."""
    exact = _SINK_TYPE_MAP.get(name)
    if exact:
        return exact
    # Prefix-based fallback
    name_lower = name.lower()
    if "pickle" in name_lower or "shelve" in name_lower:
        return "deserialization"
    if "eval" in name_lower or "exec" in name_lower:
        return "rce"
    if "subprocess" in name_lower or "os.system" in name_lower or "os.popen" in name_lower:
        return "command_injection"
    if "zipfile" in name_lower or "tarfile" in name_lower:
        return "path_traversal"
    return "sink"


def _sink_to_finding(
    s: dict, fn: SourceFunction
) -> CandidateFinding:
    """Convert a sink dict to a candidate with proper type/severity/confidence."""
    sink_name = s.get("name", "")
    return CandidateFinding(
        type=_sink_type(sink_name),
        severity="medium",
        file_path=fn.file_path,
        function_name=fn.fullname,
        line_number=s.get("line", fn.line_start),
        source_line=fn.signature,
        reason=s.get("reason", ""),
        sink_type=sink_name,
        confidence="medium",
    )


def _call_llm_single(
    fn: SourceFunction, llm: Any, context: str = ""
) -> list[CandidateFinding]:
    """Synchronous LLM call for one function."""
    # Deterministic pre-scan catches obvious sinks the LLM might miss
    # in trivial wrappers or when data flow crosses file boundaries.
    deterministic = _pre_scan_body(fn)

    user_msg = SINGLE_FUNCTION_USER.format(
        context=context or "",
        name=fn.fullname,
        file_path=fn.file_path,
        line_start=fn.line_start,
        line_end=fn.line_end,
        signature=fn.signature,
        body=fn.body,
    )
    try:
        response = llm.chat_completion(
            messages=[
                {"role": "system", "content": SINGLE_FUNCTION_SYSTEM},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=512,
        )
    except Exception as exc:
        logger.warning("Bulk analysis LLM call failed for %s: %s", fn.fullname, exc)
        return deterministic

    llm_findings = _parse_single_response(response, fn)
    # Merge LLM findings + deterministic pre-scan, dedup by sink_name
    seen_sinks = set()
    merged: list[CandidateFinding] = []
    for f in deterministic + llm_findings:
        key = (f.function_name, f.sink_type)
        if key not in seen_sinks:
            seen_sinks.add(key)
            merged.append(f)
    return merged


def _parse_single_response(
    response: Any, fn: SourceFunction
) -> list[CandidateFinding]:
    """Parse the LLM response for a single-function analysis."""
    content = (response.content or "").strip()
    if not content:
        return []

    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if not json_match:
        json_match = re.search(r"\{.*\}", content, re.DOTALL)

    if not json_match:
        return []

    try:
        data = json.loads(json_match.group(1))
    except (json.JSONDecodeError, IndexError):
        return []

    findings: list[CandidateFinding] = []
    for v in data.get("vulnerabilities", []):
        if not isinstance(v, dict):
            continue
        findings.append(
            CandidateFinding(
                type=v.get("type", ""),
                severity=v.get("severity", "medium"),
                file_path=fn.file_path,
                function_name=fn.fullname,
                line_number=fn.line_start,
                source_line=fn.signature,
                reason=v.get("reason", ""),
                sink_type=v.get("sink", ""),
                invariant=v.get("invariant", ""),
                confidence=v.get("confidence", "medium"),
            )
        )

    # Surface sinks as candidates — the LLM may not report them as
    # vulnerabilities when data flow crosses file boundaries.
    for s in data.get("sinks", []):
        if not isinstance(s, dict):
            continue
        findings.append(_sink_to_finding(s, fn))
    return findings


def _call_llm_multi(
    fns: list[SourceFunction], llm: Any, context: str = "", max_chunk: int = 12
) -> list[CandidateFinding]:
    """One LLM call for a chunk of related functions (same file).

    Uses the interprocedural MULTI_FUNCTION_PROMPT so the LLM can track
    data flow across function boundaries within the same file.
    """
    # Build function description blocks
    fn_blocks: list[str] = []
    for fn in fns:
        fn_blocks.append(
            f"### Function: {fn.fullname}\n"
            f"File: {fn.file_path}\n"
            f"Lines: {fn.line_start}-{fn.line_end}\n"
            f"Signature:\n```\n{fn.signature}\n```\n"
            f"Body:\n```\n{fn.body}\n```"
        )

    user_msg = MULTI_FUNCTION_USER.format(
        context=context or "",
        chunk_id=f"{fns[0].file_path} ({len(fns)} functions)",
        count=len(fns),
        functions="\n\n---\n\n".join(fn_blocks),
    )
    try:
        response = llm.chat_completion(
            messages=[
                {"role": "system", "content": MULTI_FUNCTION_SYSTEM},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=1024,
        )
    except Exception as exc:
        logger.warning("Multi-function LLM call failed for %s: %s", fns[0].file_path, exc)
        # Return deterministic pre-scan results even when LLM fails
        deterministic: list[CandidateFinding] = []
        for fn in fns:
            deterministic.extend(_pre_scan_body(fn))
        return deterministic

    llm_findings = _parse_multi_response(response, fns)

    # Merge deterministic pre-scan + LLM results, dedup by sink_name
    deterministic: list[CandidateFinding] = []
    for fn in fns:
        deterministic.extend(_pre_scan_body(fn))
    seen_sinks = set()
    merged: list[CandidateFinding] = []
    for f in deterministic + llm_findings:
        key = (f.function_name, f.sink_type)
        if key not in seen_sinks:
            seen_sinks.add(key)
            merged.append(f)
    return merged


def _parse_multi_response(
    response: Any, fns: list[SourceFunction]
) -> list[CandidateFinding]:
    """Parse interprocedural multi-function LLM response."""
    content = (response.content or "").strip()
    if not content:
        return []

    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if not json_match:
        json_match = re.search(r"\{.*\}", content, re.DOTALL)
    if not json_match:
        return []

    try:
        json_str = json_match.group(1)
        data = json.loads(json_str)
    except (json.JSONDecodeError, IndexError) as exc:
        json_str = json_match.group(1) if json_match else "NO MATCH"
        logger.warning("Multi-function JSON decode failed (len=%d): %s | match=%s",
                       len(content), content[:200], json_str[:200])
        return []

    # Build name -> SourceFunction map (fullname and short name)
    fn_map: dict[str, SourceFunction] = {}
    for fn in fns:
        fn_map[fn.fullname] = fn
        fn_map[fn.name] = fn

    findings: list[CandidateFinding] = []
    for v in data.get("vulnerabilities", []):
        if not isinstance(v, dict):
            continue
        fn_name = v.get("function", "")
        fn = fn_map.get(fn_name)
        if not fn:
            continue

        findings.append(
            CandidateFinding(
                type=v.get("type", ""),
                severity=v.get("severity", "medium"),
                file_path=fn.file_path,
                function_name=fn.fullname,
                line_number=fn.line_start,
                source_line=fn.signature,
                reason=v.get("reason", ""),
                sink_type=v.get("sink", ""),
                invariant=v.get("invariant", ""),
                confidence=v.get("confidence", "medium"),
            )
        )

    # Also promote sinks as candidates — the LLM may not see the full
    # data flow (cross-file taint), but sinks are always worth verifying.
    for s in data.get("sinks", []):
        if not isinstance(s, dict):
            continue
        fn_name = s.get("function", "")
        fn = fn_map.get(fn_name)
        if not fn:
            continue
        findings.append(_sink_to_finding(s, fn))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_single_functions(
    index: FunctionIndex,
    llm: Any,
    max_workers: int = 20,
    priority_map: dict[str, float] | None = None,
    max_functions: int = 0,
    function_context: dict[str, str] | None = None,
) -> BulkAnalysisOutput:
    """Run Phase 1 single-function analysis over all functions in *index*.

    Each function gets one parallel LLM call via ThreadPoolExecutor.

    Parameters
    ----------
    index : FunctionIndex
        The function index to analyze.
    llm : Any
        LLM provider instance.
    max_workers : int
        Max thread pool workers for parallel LLM calls.
    priority_map : dict[str, float] | None
        Maps function name to risk score (from Director cards).
        When provided, functions are sorted by score descending so
        high-risk functions are analysed first.
    max_functions : int
        If > 0, limit analysis to this many functions (highest priority
        first).  Useful when token budget is tight.
    """
    candidates: list[CandidateFinding] = []
    call_count = 0

    # Sort by priority when a map is available
    if priority_map:
        def _priority(fn: SourceFunction) -> float:
            # Try fullname first, then short name
            return priority_map.get(
                fn.fullname,
                priority_map.get(fn.name, 0.0),
            )

        funcs = sorted(index.funcs, key=_priority, reverse=True)
    else:
        funcs = list(index.funcs)

    # Apply optional function limit (keep highest-priority ones)
    if max_functions > 0 and len(funcs) > max_functions:
        cutoff_idx = max_functions
        retained = set(funcs[:cutoff_idx])
        # But always keep functions from files with dangerous imports:
        # shelve, pickle, marshal, yaml, subprocess, eval, exec.
        # Without this, low-PageRank deserialization wrappers (e.g.
        # shelvestore.py) get dropped and never flagged by Phase 1.
        _DANGEROUS_IMPORTS = frozenset({
            "import shelve", "from shelve",
            "import pickle", "from pickle",
            "import marshal", "from marshal",
            "import yaml", "from yaml",
            "import subprocess", "from subprocess",
            "import tarfile", "from tarfile",
            "import zipfile", "from zipfile",
        })
        for fn in funcs[cutoff_idx:]:
            if any(di in fn.body for di in _DANGEROUS_IMPORTS):
                retained.add(fn)
            # Also check the file header for the import
            elif index and fn.file_path in index.sources:
                src = index.sources[fn.file_path].source
                if any(di in src for di in _DANGEROUS_IMPORTS):
                    retained.add(fn)
        funcs = sorted(retained, key=lambda f: (priority_map.get(f.fullname, priority_map.get(f.name, 0.0)) if priority_map else 0, f.fullname), reverse=True)

    # --- Group by file for multi-function chunking ---
    # Files with 2+ functions use interprocedural analysis (one LLM call per file).
    # Files with 1 function use the existing per-function analysis.
    by_file: dict[str, list[SourceFunction]] = {}
    for fn in funcs:
        # Preserve priority order within each file
        by_file.setdefault(fn.file_path, []).append(fn)

    def _chunked(
        file_funcs: list[SourceFunction],
    ) -> list[list[SourceFunction]]:
        """Split a large file function list into chunks of *max_chunk*."""
        max_chunk = 10
        return [
            file_funcs[i : i + max_chunk]
            for i in range(0, len(file_funcs), max_chunk)
        ]

    # Build dispatch list: (fns_list, is_multi)
    dispatch: list[tuple[list[SourceFunction], bool]] = []
    for file_funcs in by_file.values():
        if len(file_funcs) >= 2:
            for chunk in _chunked(file_funcs):
                dispatch.append((chunk, True))
        else:
            dispatch.append((file_funcs, False))

    def _lookup_context(fn: SourceFunction) -> str:
        ctx_parts: list[str] = []
        if function_context is not None:
            ctx = function_context.get(
                fn.fullname,
                function_context.get(fn.name, ""),
            )
            if ctx:
                ctx_parts.append(ctx)
        # Always append file header (imports + module docstring) so the LLM
        # sees what the module imports.  Without this, simple wrappers around
        # shelve/pickle/yaml/etc. are analyzed with zero dependency context,
        # even when the Director provides generic call-chain metadata.
        if index:
            sf = index.sources.get(fn.file_path)
            if sf:
                lines = sf.source.split("\n")[:20]
                header = [l for l in lines if l.strip()
                          and not l.strip().startswith("#")]
                if header:
                    ctx_parts.append("File header:\n" + "\n".join(header))
        return "\n\n".join(ctx_parts)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {}
        for fns_list, is_multi in dispatch:
            if is_multi:
                chunk_ctx = ""
                for fn in fns_list:
                    chunk_ctx = _lookup_context(fn)
                    if chunk_ctx:
                        break
                future = pool.submit(_call_llm_multi, fns_list, llm, context=chunk_ctx)
            else:
                fn = fns_list[0]
                ctx = _lookup_context(fn)
                future = pool.submit(_call_llm_single, fn, llm, context=ctx)
            future_map[future] = fns_list

        for future in as_completed(future_map):
            call_count += 1
            try:
                result = future.result()
                candidates.extend(result)
            except Exception as exc:
                logger.warning("Bulk analysis worker failed: %s", exc)

    # Count deserialization candidates for debugging
    deserial_count = sum(1 for c in candidates if c.type == "deserialization")
    if deserial_count:
        logger.warning("BULK output: %d candidates, %d deserialization (sample: %s)",
                       len(candidates), deserial_count,
                       [c.function_name for c in candidates if c.type == "deserialization"][:3])
    return BulkAnalysisOutput(
        candidates=candidates,
        total_functions_analyzed=len(funcs),
        total_llm_calls=call_count,
    )
