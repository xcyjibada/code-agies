"""Phase 1 bulk analysis — parallel LLM calls over all functions.

Two modes (from REFACTOR.md):
- **Single-function**: one LLM call per function (high concurrency)
- **Multi-function (chunked)**: one LLM call per chunk of related files

Uses asyncio.create_task() + asyncio.Semaphore for robust parallel execution
with retry and dynamic concurrency control.  Each batch runs in its own
event loop (via asyncio.run()) so httpx's internal async TaskGroup never
sees a stale/no-loop context, eliminating the "no such group" crash.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
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

# Max retries per LLM call before giving up.
_MAX_RETRIES = 2


def _dynamic_max_workers(total_functions: int) -> int:
    """Pick a sensible concurrency cap based on project size.

    | Functions | Cap | Rationale                              |
    |-----------|-----|----------------------------------------|
    | < 200     |  8  | Small project, no need for aggression  |
    | 200–2000  | 12  | Medium project                         |
    | > 2000    | 16  | Django-sized — wider pipe, not insane  |
    """
    base = (os.cpu_count() or 4) * 2
    if total_functions > 2000:
        return min(base, 16)
    if total_functions > 500:
        return min(base, 12)
    return min(base, 8)


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


def _sink_to_finding(s: dict, fn: SourceFunction) -> CandidateFinding:
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


def _call_llm_single(fn: SourceFunction, llm: Any, context: str = "") -> list[CandidateFinding]:
    """Synchronous LLM call for one function."""
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
    seen_sinks = set()
    merged: list[CandidateFinding] = []
    for f in deterministic + llm_findings:
        key = (f.function_name, f.sink_type)
        if key not in seen_sinks:
            seen_sinks.add(key)
            merged.append(f)
    return merged


def _parse_single_response(response: Any, fn: SourceFunction) -> list[CandidateFinding]:
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
        findings.append(CandidateFinding(
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
        ))

    for s in data.get("sinks", []):
        if not isinstance(s, dict):
            continue
        findings.append(_sink_to_finding(s, fn))
    return findings


def _call_llm_multi(
    fns: list[SourceFunction], llm: Any, context: str = "", max_chunk: int = 12
) -> list[CandidateFinding]:
    """One LLM call for a chunk of related functions (same file)."""
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
        deterministic: list[CandidateFinding] = []
        for fn in fns:
            deterministic.extend(_pre_scan_body(fn))
        return deterministic

    llm_findings = _parse_multi_response(response, fns)

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


def _parse_multi_response(response: Any, fns: list[SourceFunction]) -> list[CandidateFinding]:
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
        logger.warning("Multi-function JSON decode failed: %s | content=%.200s", exc, content[:200])
        return []

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
        findings.append(CandidateFinding(
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
        ))

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

    Uses asyncio.create_task() + asyncio.Semaphore for robust parallel
    execution with retry and dynamic concurrency control.  Each invocation
    runs in a fresh event loop so httpx's internal TaskGroup never crashes
    with "no such group" (the root cause was cross-thread event-loop staleness).

    Parameters
    ----------
    index : FunctionIndex
        The function index to analyze.
    llm : Any
        LLM provider instance.
    max_workers : int
        Ignored when > 0 (overridden by _dynamic_max_workers).  Kept for
        backward-compat — callers that pass this directly (tests) still work.
    priority_map : dict[str, float] | None
        Maps function name to risk score (from Director cards).
        When provided, functions are sorted by score descending so
        high-risk functions are analysed first.
    max_functions : int
        If > 0, limit analysis to this many functions (highest priority
        first).  Useful when token budget is tight.
    function_context : dict[str, str] | None
        Maps function name to human-readable context string (from Director).
    """
    candidates: list[CandidateFinding] = []
    call_count = 0

    # Sort by priority when a map is available
    if priority_map:
        def _priority(fn: SourceFunction) -> float:
            return priority_map.get(
                fn.fullname,
                priority_map.get(fn.name, 0.0),
            )
        funcs = sorted(index.funcs, key=_priority, reverse=True)
    else:
        funcs = list(index.funcs)

    # Apply optional function limit
    if max_functions > 0 and len(funcs) > max_functions:
        cutoff_idx = max_functions
        retained = set(funcs[:cutoff_idx])
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
            elif index and fn.file_path in index.sources:
                src = index.sources[fn.file_path].source
                if any(di in src for di in _DANGEROUS_IMPORTS):
                    retained.add(fn)
        funcs = sorted(retained, key=lambda f: (
            priority_map.get(f.fullname, priority_map.get(f.name, 0.0)) if priority_map else 0,
            f.fullname,
        ), reverse=True)

    # --- Group by file for multi-function chunking ---
    by_file: dict[str, list[SourceFunction]] = {}
    for fn in funcs:
        by_file.setdefault(fn.file_path, []).append(fn)

    def _chunked(file_funcs: list[SourceFunction]) -> list[list[SourceFunction]]:
        max_chunk = 10
        return [file_funcs[i: i + max_chunk] for i in range(0, len(file_funcs), max_chunk)]

    # Build dispatch list
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
        if index:
            sf = index.sources.get(fn.file_path)
            if sf:
                lines = sf.source.split("\n")[:20]
                header = [l for l in lines if l.strip() and not l.strip().startswith("#")]
                if header:
                    ctx_parts.append("File header:\n" + "\n".join(header))
        return "\n\n".join(ctx_parts)

    # Pre-compute context for each dispatch item (avoids recomputation inside tasks)
    dispatch_items: list[tuple[list[SourceFunction], bool, str]] = []
    for fns_list, is_multi in dispatch:
        if is_multi:
            chunk_ctx = ""
            for fn in fns_list:
                chunk_ctx = _lookup_context(fn)
                if chunk_ctx:
                    break
            dispatch_items.append((fns_list, True, chunk_ctx))
        else:
            fn = fns_list[0]
            dispatch_items.append((fns_list, False, _lookup_context(fn)))

    # --- asyncio parallel execution with semaphore + retry ---
    max_concurrent = _dynamic_max_workers(len(funcs))

    async def _run_analysis() -> list[CandidateFinding]:
        sem = asyncio.Semaphore(max_concurrent)
        loop = asyncio.get_running_loop()
        results: list[CandidateFinding] = []
        results_lock = asyncio.Lock()
        completed = 0
        total = len(dispatch_items)

        async def _process(fns_list: list[SourceFunction],
                           is_multi: bool,
                           ctx: str) -> None:
            nonlocal completed, call_count
            async with sem:
                last_exc: Exception | None = None
                for attempt in range(1, _MAX_RETRIES + 2):  # 1 initial + N retries
                    try:
                        if is_multi:
                            chunk = await loop.run_in_executor(
                                None, _call_llm_multi, fns_list, llm, ctx,
                            )
                        else:
                            chunk = await loop.run_in_executor(
                                None, _call_llm_single, fns_list[0], llm, ctx,
                            )
                        async with results_lock:
                            results.extend(chunk)
                        return  # success
                    except Exception as exc:
                        last_exc = exc
                        if attempt <= _MAX_RETRIES:
                            logger.warning(
                                "Bulk worker failed (attempt %d/%d): %s",
                                attempt, _MAX_RETRIES + 1, exc,
                            )
                            await asyncio.sleep(1.0 * attempt)
                        # else: final attempt failed — log and drop
                logger.error(
                    "Bulk worker failed after %d attempts: %s | fns=%s",
                    _MAX_RETRIES + 1, last_exc,
                    [f.fullname for f in fns_list[:3]],
                )
            # still report progress after failure
            nonlocal completed, call_count

        # Fire all tasks
        tasks = [
            asyncio.create_task(_process(fns, multi, ctx))
            for fns, multi, ctx in dispatch_items
        ]

        # Wait for all to complete
        await asyncio.gather(*tasks, return_exceptions=True)

        # Count actual LLM calls (one per dispatch item that didn't fail outright)
        actual_calls = sum(
            1 for t in tasks if not t.cancelled() and not t.exception()
        )
        nonlocal call_count
        call_count = actual_calls
        return results

    candidates = asyncio.run(_run_analysis())

    # Log summary
    deserial_count = sum(1 for c in candidates if c.type == "deserialization")
    if deserial_count:
        logger.warning(
            "BULK output: %d candidates, %d deserialization (sample: %s)",
            len(candidates), deserial_count,
            [c.function_name for c in candidates if c.type == "deserialization"][:3],
        )
    return BulkAnalysisOutput(
        candidates=candidates,
        total_functions_analyzed=len(funcs),
        total_llm_calls=call_count,
    )
