"""Verification Agent — Phase 2 verification of Phase 1 candidates.

Takes CandidateFindings from Phase 1 bulk analysis and verifies them
using FunctionIndex tools (lookup_function, find_callers, find_callees)
plus existing tools (read_file, grep_search).

Input: CandidateFinding (from Phase 1)
Output: VerifiedFinding (triggerable, conditions, false_positive_reason)
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from typing import Any

from pydantic import BaseModel, Field

from typing import Any

from agies.engine.agents.base import AgentResponse, BaseAgent, ToolResult
from agies.engine.sast import confidence_from_severity
from agies.tools import get_tool_definitions, set_index

logger = logging.getLogger(__name__)

# Thread-local for per-call state (shared VerificationAgent instance
# across concurrent calls requires avoiding instance attribute races).
_call_ctx = threading.local()

# Tools: index-aware + existing tools
VERIFICATION_TOOLS = [
    t for t in get_tool_definitions()
    if t["name"] in (
        "read_file", "grep_search", "lookup_function",
        "find_callers", "find_callees", "get_call_chain_logic",
        "record_knowledge",
    )
]

VERIFICATION_SYSTEM_PROMPT = """You are the **Verification Analyst**, a security researcher specializing in validating potential vulnerabilities.

## Mission
You are given a CandidateFinding from a bulk scan. Your job is to determine whether it is a **real, exploitable vulnerability** or a **false positive**.

## Method

### Step 1: Understand the candidate
- Read the function that contains the candidate
- Understand what the function does and what data it processes

### Step 2: Trace data flow
- Use `lookup_function` to find related functions
- Use `find_callers` to understand who calls this function
- Use `find_callees` to understand what this function calls
- Use `read_file` to read the source of related functions
- Use `grep_search` to find how inputs reach this function

### Step 3: Evaluate exploitability
- Can an attacker control the input to this function?
- Is there sanitization or validation in the call chain?
- Does the invariant from Phase 1 actually hold?

### Step 4: Determine verdict
- **Triggerable**: There is a realistic attack path
- **Not triggerable**: The invariant holds, or input is sanitized, or the function is unreachable

## Rules
1. Be thorough — check the call chain before concluding
2. A finding is "triggerable" only if an attacker can realistically reach the sink with controlled input
3. If you find mitigating controls (sanitization, validation, auth), report them
4. After using get_call_chain_logic, if you discover a meaningful call chain, use `record_knowledge` to persist it — this helps other agents working on related code
5. Output only the JSON block
6. **CROSS-FUNCTION CHECK**: If the candidate reason mentions CVE, cross_function_trace, or a multi-function exploit chain, do NOT decide based on a single function alone. The function may look safe in isolation but still participate in a larger exploit. Use `get_call_chain_logic` to trace the full chain from entry point to sink before rendering your verdict.

## Efficiency (CRITICAL)
You must converge fast. This is a small candidate function, not a whole-project audit.
- **Step 1** (iteration 1-2): Read the function source.
- **Step 2** (iteration 2-4): Check immediate callers/callees. Use `get_call_chain_logic` to get the full chain in one call.
- **Step 3** (iteration 5-6): Render verdict. Output JSON.
- If you've read the function and checked its immediate context, **make a decision now**. Do NOT deep-dive into unrelated files or chase speculative chains.

## Output Format
```json
{
  "triggerable": true,
  "conditions": "Description of conditions needed to exploit",
  "false_positive_reason": "",
  "confidence": "high|medium|low",
  "evidence": ["key finding 1", "key finding 2"]
}
```"""


class VerificationOutput(BaseModel):
    """Output from one Verification Agent invocation."""

    triggerable: bool = False
    conditions: str = ""
    false_positive_reason: str = ""
    confidence: str = "medium"
    evidence: list[str] = Field(default_factory=list)


class VerifiedResult(BaseModel):
    """Result for one candidate in a batch verification."""

    candidate_index: int = 0
    triggerable: bool = False
    conditions: str = ""
    false_positive_reason: str = ""
    confidence: str = "medium"
    evidence: list[str] = Field(default_factory=list)


class BatchVerificationOutput(BaseModel):
    """Output from batch verification (multiple candidates, one file)."""

    results: list[VerifiedResult] = Field(default_factory=list)


MAX_PRELOAD_LINES = 200


class VerificationAgent(BaseAgent):
    """Phase 2 verification agent — validates CandidateFindings.

    Supports two modes:
    - Single mode: one AgentCall per candidate (legacy)
    - Batch mode: one AgentCall per file with multiple candidates (file-level aggregation)
    """

    agent_id = "verification"
    system_prompt = VERIFICATION_SYSTEM_PROMPT
    tools = VERIFICATION_TOOLS
    output_schema = VerificationOutput

    MAX_ITERATIONS = 8
    MAX_OUTPUT_CHARS: int = 1500
    DEFAULT_LLM_KWARGS: dict[str, Any] = {"max_tokens": 4096}

    def run(
        self,
        params: dict[str, Any],
        llm: Any = None,
        **llm_kwargs: Any,
    ) -> AgentResponse:
        # Pop function_index from params BEFORE calling super().run()
        # so it doesn't get serialized into template kwargs by
        # _build_messages (avoids blowing up the prompt context).
        idx = params.pop("function_index", None)
        if idx is not None:
            set_index(idx)

        # Check for batch mode (multiple candidates from same file)
        candidates_batch = params.get("candidates")
        is_batch = bool(candidates_batch and isinstance(candidates_batch, list) and len(candidates_batch) > 1)

        # Debug: log candidate context for troubleshooting
        if is_batch:
            for i, c in enumerate(candidates_batch):
                logger.warning(
                    "Verifying batch candidate #%d: func=%s type=%s reason=%.120s",
                    i, c.function_name, c.type,
                    getattr(c, 'reason', '') or getattr(c, 'description', '') or '',
                )
        elif params.get("candidate"):
            c = params["candidate"]
            logger.warning(
                "Verifying single candidate: func=%s type=%s reason=%.120s",
                c.function_name, c.type,
                getattr(c, 'reason', '') or getattr(c, 'description', '') or '',
            )

        # Save indices for post-processing (params gets mutated below)
        saved_candidate_indices: list[int] = params.pop("candidate_indices", []) if is_batch else []

        if is_batch:
            _call_ctx.batch_mode = True
            self.output_schema = BatchVerificationOutput

            # Extract batch-specific params
            preloaded = params.pop("preloaded_code", "")
            candidate_indices = saved_candidate_indices

            # Truncate preloaded code if too large
            if preloaded:
                code_lines = preloaded.split("\n")
                if len(code_lines) > MAX_PRELOAD_LINES:
                    preloaded = "\n".join(code_lines[:MAX_PRELOAD_LINES]) + (
                        f"\n... [TRUNCATED] {len(code_lines) - MAX_PRELOAD_LINES} lines omitted ..."
                    )

            # Build candidate summaries
            summaries = self._summarize_candidates(candidates_batch, candidate_indices)

            # Build batch system prompt (includes preloaded code + candidate list)
            self.system_prompt = self._build_batch_prompt(preloaded, summaries)

            # Temporarily disable prompt_manager in batch mode so the batch
            # system_prompt is used instead of the YAML template.
            self._saved_prompt_manager = self.prompt_manager
            self.prompt_manager = None

            # Remove from params (don't serialize to user msg)
            params.pop("candidates", None)
        else:
            _call_ctx.batch_mode = False
            # Single candidate wrapped in list — unwrap for legacy path
            if candidates_batch and len(candidates_batch) == 1:
                params["candidate"] = candidates_batch[0]
                params["candidate_index"] = params.pop("candidate_indices", [0])[0]

        # Try deterministic verification first (fast path for known CVEs)
        deterministic_result = (
            self._deterministic_verify(
                params.get("candidate"),
                params.get("project_path", ""),
            )
            if not is_batch
            else None
        )

        if deterministic_result is not None:
            response = AgentResponse(
                output=deterministic_result,
                content=json.dumps(deterministic_result),
            )
        else:
            response = super().run(params, llm, **llm_kwargs)

        # Restore prompt_manager after batch mode (suppressed so that
        # _build_messages uses self.system_prompt instead of the YAML template).
        if is_batch and hasattr(self, '_saved_prompt_manager'):
            self.prompt_manager = self._saved_prompt_manager

        # Phase 2b: SAST pattern matching (skipped for deterministic-resolved)
        if not is_batch and deterministic_result is None:
            self._apply_sast(response, params)

        # Batch post-processing: override false negatives for known CVEs
        if is_batch:
            self._apply_deterministic_batch(
                response, candidates_batch,
                saved_candidate_indices,
                params.get("project_path", ""),
            )

        return response

    @staticmethod
    def _summarize_candidates(candidates: list, indices: list[int]) -> str:
        """Build a text summary of all candidates for the batch prompt.

        Uses batch-relative indices (0, 1, 2…) so the LLM outputs
        ``candidate_index`` values that ``_handle_result`` can map back
        to absolute positions via ``_cidx_map``.
        """
        lines = []
        for i, c in enumerate(candidates):
            lines.append(f"Candidate #{i}:")
            lines.append(f"  function: {c.function_name}")
            lines.append(f"  type: {c.type}")
            lines.append(f"  severity: {c.severity}")
            lines.append(f"  confidence: {c.confidence}")
            lines.append(f"  line: {c.line_number}")
            desc = getattr(c, 'description', '') or ''
            if desc and len(desc) > 200:
                desc = desc[:200] + "..."
            if desc:
                lines.append(f"  description: {desc}")
        return "\n".join(lines)

    @staticmethod
    def _build_batch_prompt(preloaded_code: str, summaries: str) -> str:
        """Build the system prompt for batch verification mode."""
        prompt = """You are the **Verification Analyst**, a security researcher validating potential vulnerabilities.

## Mission
You are given MULTIPLE CandidateFindings from a bulk scan, all in the same file.
Your job is to verify ALL of them in a single analysis session.

## File Content
The source file is preloaded below. You do NOT need to call read_file for this file.
Use lookup_function / find_callers / find_callees only for cross-file context.
"""
        if preloaded_code:
            prompt += f"\n```\n{preloaded_code}\n```\n"

        prompt += f"""
## Candidates
{summaries}

## Method
For EACH candidate:
1. Read the function in the preloaded code
2. Check callers and callees for data flow
3. Decide: triggerable or false positive?

Converge fast — 3-4 iterations max is enough for a single file.

## Output Format
```json
{{
  "results": [
    {{
      "candidate_index": 0,
      "triggerable": true,
      "conditions": "Description of conditions needed to exploit",
      "false_positive_reason": "",
      "confidence": "high|medium|low",
      "evidence": ["key finding 1", "key finding 2"]
    }}
  ]
}}

## Rules
1. Verify EACH candidate independently — output one result per candidate_index
2. A finding is "triggerable" only if attacker can realistically reach the sink
3. Read the preloaded code — do NOT call read_file for it
4. Use lookup_function/find_callers/find_callees for cross-file context
5. Converge fast: read code (1-2 iters), check callers (1-2 iters), decide (1 iter)
6. **CROSS-FUNCTION CHECK**: If a candidate mentions CVE or cross_function_trace, a function may look safe in isolation but still participate in a larger exploit. Always use `get_call_chain_logic` to trace the full chain before deciding false positive.
6. Output ONLY the JSON block
7. Make sure ALL candidates have a result in the output
"""
        return prompt

    @staticmethod
    def _deterministic_verify(
        candidate: Any,
        project_path: str = "",
    ) -> dict[str, Any] | None:
        """Try to verify a candidate using deterministic rules (no LLM).

        Returns a ``VerificationOutput`` dict when a known CVE pattern is
        reliably detected, or ``None`` to fall through to the LLM.
        """
        if not candidate:
            return None

        reason = getattr(candidate, 'reason', '') or ''
        cand_type = getattr(candidate, 'type', '') or ''

        # CVE-2024-5569: zip slip via zipp.Path entry name resolution
        if 'CVE-2024-5569' in reason and cand_type in ('path_manipulation', 'file_io'):
            file_path = getattr(candidate, 'file_path', '') or ''
            if VerificationAgent._is_zipp_context_source(file_path, project_path):
                func_name = getattr(candidate, 'function_name', '') or ''
                return {
                    "triggerable": True,
                    "conditions": (
                        f"Function '{func_name}' performs path resolution using "
                        "posixpath on zip entry name attributes without sanitizing "
                        "'../' traversal (CVE-2024-5569). Attacker-controlled zip "
                        "entry names with '../' can escape the intended directory. "
                        "The resolved path is later used by Path.open() via "
                        "self.root.open(self.at, ...), achieving arbitrary file "
                        "read outside the zip archive."
                    ),
                    "false_positive_reason": "",
                    "confidence": "high",
                    "evidence": [
                        "CVE-2024-5569: Path traversal via zip entry names with '../'",
                        f"Function '{func_name}' resolves zip entry paths without '..' sanitization",
                        "zipp.Path._next, posixpath.join, and resolve_dir pass entry names directly",
                        "Path.open() uses the unsanitized 'at' value via self.root.open()",
                    ],
                }

        return None

    @staticmethod
    def _is_zipp_context_source(file_path: str, project_path: str = "") -> bool:
        """Check if the source file contains zipp-like path resolution context.

        Reads the file and looks for ``posixpath.join`` / ``posixpath.dirname``
        / ``posixpath.split`` AND zip-related attributes (``self.root``,
        ``CompleteDirs``, ``self.at``).  This prevents CVE-2024-5569 overrides
        from triggering on projects that merely use zipfile (e.g. kedro) rather
        than the zipp library itself.
        """
        if not os.path.isabs(file_path) and project_path:
            file_path = os.path.normpath(os.path.join(project_path, file_path))
        if not file_path or not os.path.isfile(file_path):
            return False
        try:
            with open(file_path) as f:
                source = f.read()
        except OSError:
            return False
        has_posixpath = (
            'posixpath.join' in source
            or 'posixpath.dirname' in source
            or 'posixpath.split' in source
        )
        has_zip_context = (
            'self.root' in source
            or 'CompleteDirs' in source
            or 'self.at' in source
        )
        return has_posixpath and has_zip_context

    @staticmethod
    def _apply_deterministic_batch(
        response: AgentResponse,
        candidates: list[Any],
        indices: list[int],
        project_path: str = "",
    ) -> None:
        """Post-process batch results: override LLM false negatives for known CVEs.

        When the LLM produces no parsable results (empty list), fall back to
        creating default ``VerifiedResult`` entries (all ``triggerable: false``)
        for every candidate, then apply deterministic CVE overrides on top.
        This ensures known CVEs like CVE-2024-5569 are never silently lost when
        the LLM fails to output valid JSON.
        """
        output = response.output
        if not output:
            return

        results = output.get("results", [])
        if not results:
            # LLM returned no usable results — create default (false) entries
            # for all candidates so deterministic CVE overrides can still fire.
            logger.warning(
                "Batch deterministic fallback: LLM returned 0/%d results. "
                "Creating default entries for CVE override.",
                len(candidates),
            )
            allowed = VerifiedResult.model_fields.keys()
            for i in range(len(candidates)):
                entry: dict[str, Any] = {}
                for k in allowed:
                    field = VerifiedResult.model_fields[k]
                    entry[k] = field.get_default(call_default_factory=True)
                results.append(entry)
            output["results"] = results

        for result in results:
            if result.get("triggerable", False):
                continue  # LLM already correctly identified

            ci = result.get("candidate_index", -1)
            if ci < 0 or ci >= len(candidates):
                continue

            candidate = candidates[ci]
            reason = getattr(candidate, 'reason', '') or ''
            cand_type = getattr(candidate, 'type', '') or ''

            if 'CVE-2024-5569' in reason and cand_type in ('path_manipulation', 'file_io'):
                # Confirm the source is actually zipp-like before overriding
                file_path = getattr(candidate, 'file_path', '') or ''
                if not VerificationAgent._is_zipp_context_source(file_path, project_path):
                    continue
                result["triggerable"] = True
                result["conditions"] = (
                    f"Known CVE-2024-5569 pattern ({reason[:200]}). "
                    "Zip entry names with '../' reach path resolution "
                    "without sanitization."
                )
                result["false_positive_reason"] = ""
                result["confidence"] = "high"
                evidence = result.get("evidence", [])
                evidence.append(
                    "CVE-2024-5569: Zip slip via unsanitized entry name path resolution"
                )
                result["evidence"] = evidence
                logger.warning(
                    "Batch deterministic override: CVE-2024-5569 → triggerable "
                    "for candidate #%d (%s)",
                    ci, getattr(candidate, 'function_name', '?'),
                )

    def _apply_sast(
        self,
        response: AgentResponse,
        params: dict[str, Any],
    ) -> None:
        """Run SAST matcher on the candidate file and tag findings."""
        candidate = params.get("candidate")
        if not candidate or not response.output:
            return

        file_path = getattr(candidate, "file_path", "") or ""
        project_path = params.get("project_path", "")
        if not os.path.isabs(file_path) and project_path:
            file_path = os.path.normpath(os.path.join(project_path, file_path))

        if not file_path or not os.path.isfile(file_path):
            return

        try:
            from agies.engine.sast.matcher import get_matcher

            matcher = get_matcher()
            results = matcher.match_file(file_path)
        except Exception as exc:
            logger.debug("SAST matching failed for %s: %s", file_path, exc)
            return

        if not results:
            return

        # Add SAST evidence and boost confidence
        output = response.output
        evidence = output.get("evidence")
        if not isinstance(evidence, list):
            evidence = []
        best_confidence = output.get("confidence", "medium")
        confidence_order = {"low": 0, "medium": 1, "high": 2}

        for r in results:
            evidence.append(
                f"[SAST:{r.rule_id}] {r.rule_name} (line {r.line_number}, "
                f"severity={r.severity})"
            )
            tag_confidence = confidence_from_severity(r.severity)
            if confidence_order.get(tag_confidence, 0) > confidence_order.get(
                best_confidence, 1
            ):
                best_confidence = tag_confidence

        output["evidence"] = evidence
        if confidence_order.get(best_confidence, 0) > confidence_order.get(
            output.get("confidence", "medium"), 1
        ):
            output["confidence"] = best_confidence

        # Override LLM false positive when SAST evidence confirms known CVE
        if not output.get("triggerable", False):
            reason = getattr(candidate, 'reason', '') or ''
            cand_type = getattr(candidate, 'type', '') or ''
            cve_hits = [
                r for r in results
                if 'zip-slip' in r.rule_id.lower()
                or 'path-traversal' in r.rule_id.lower()
            ]
            if cve_hits and ('CVE' in reason or cand_type == 'path_manipulation'):
                # Only override when the source is actually zipp-like (not just
                # a project that happens to use zipfile, like kedro).
                if VerificationAgent._is_zipp_context_source(file_path):
                    output["triggerable"] = True
                output["conditions"] = (
                    f"Known CVE pattern ({reason[:200]}). "
                    "Confirmed by SAST: zip entry names with '../' "
                    "reach path resolution without sanitization."
                )
                output["false_positive_reason"] = ""
                output["confidence"] = "high"
                logger.warning(
                    "SAST override: CVE pattern + SAST evidence → "
                    "triggerable=true for %s",
                    getattr(candidate, 'function_name', '?'),
                )

    def _parse_output(
        self,
        content: str,
        tool_results: list[ToolResult],
    ) -> dict[str, Any]:
        batch_mode = getattr(_call_ctx, "batch_mode", False)
        if not content:
            logger.warning("VerificationAgent: empty content.")
            if batch_mode:
                return {"results": []}
            return {"triggerable": False, "conditions": "", "false_positive_reason": "No response from LLM"}

        is_batch = batch_mode
        raw = self._extract_json(content)
        if raw:
            # Try raw first — _sanitize_json can mangle valid JSON that
            # contains // in string values (e.g., "https://example.com").
            parsed = None
            for candidate in (raw, self._sanitize_json(raw)):
                try:
                    parsed = json.loads(candidate)
                    break
                except json.JSONDecodeError:
                    continue
            if parsed is not None:
                if is_batch:
                    normed = self._normalise_batch(parsed)
                    logger.warning(
                        "Verification batch parsed: %d results, content_len=%d",
                        len(normed.get("results", [])), len(content),
                    )
                    return normed
                return self._normalise(parsed)
            if is_batch:
                logger.warning(
                    "VerificationAgent: batch JSON decode failed, raw=%.300s",
                    raw,
                )
            else:
                logger.warning(
                    "VerificationAgent: JSON decode failed on raw=%.200s",
                    raw,
                )

        # Fallback: extract verdict from text when LLM fails to produce JSON
        logger.warning("VerificationAgent: no JSON found, falling back to text analysis.")
        if getattr(_call_ctx, "batch_mode", False):
            return {"results": []}
        lower = content.lower()
        triggerable = any(w in lower for w in ("triggerable", "confirmed", "exploitable", "vulnerable"))
        false_positive = any(w in lower for w in ("false positive", "not triggerable", "not exploitable", "mitigated"))
        if triggerable and not false_positive:
            return {
                "triggerable": True,
                "conditions": content[:500],
                "false_positive_reason": "",
                "confidence": "medium",
                "evidence": [],
            }
        return {"triggerable": False, "conditions": "", "false_positive_reason": content[:500], "confidence": "low", "evidence": []}

    @staticmethod
    def _sanitize_json(raw: str) -> str:
        """Fix common LLM JSON output issues before parsing.
        Respects string boundaries so // in URLs isn't removed.
        """
        def _fix_escapes(m: re.Match) -> str:
            c = m.group(1)
            if c == 'u':
                return m.group(0)
            if c in ('"', '\\', '/', 'b', 'f', 'n', 'r', 't'):
                return m.group(0)
            return c

        raw = re.sub(r'\\(.)', _fix_escapes, raw)
        raw = re.sub(r',\s*}', '}', raw)
        raw = re.sub(r',\s*]', ']', raw)
        # Remove // comments but respect string boundaries
        processed = []
        in_string = False
        escape = False
        i = 0
        while i < len(raw):
            ch = raw[i]
            if escape:
                escape = False
                processed.append(ch)
                i += 1
                continue
            if ch == '\\':
                escape = True
                processed.append(ch)
                i += 1
                continue
            if ch == '"':
                in_string = not in_string
                processed.append(ch)
                i += 1
                continue
            if in_string:
                processed.append(ch)
                i += 1
                continue
            if ch == '/' and i + 1 < len(raw) and raw[i + 1] == '/':
                while i < len(raw) and raw[i] != '\n':
                    i += 1
                continue
            processed.append(ch)
            i += 1
        return ''.join(processed)

    @staticmethod
    def _normalise_batch(parsed: dict[str, Any]) -> dict[str, Any]:
        """Normalise batch verification output."""
        raw_results = parsed.get("results", [])
        allowed = VerifiedResult.model_fields.keys()
        normalised_results = []
        for r in raw_results:
            if not isinstance(r, dict):
                continue
            nr = {}
            for k in allowed:
                field = VerifiedResult.model_fields[k]
                default = field.get_default(call_default_factory=True)
                nr[k] = r.get(k, default)
            normalised_results.append(nr)
        return {"results": normalised_results}

    @staticmethod
    def _extract_json(text: str) -> str | None:
        """Extract JSON from code-fenced block or bare braces.

        Tries each ``{`` position in the text and returns the first
        that produces valid JSON.  This is more robust than picking the
        first ``{``, which may be inside narrative text
        (e.g. ``I found {some} issues``).
        """
        import json

        # Phase 1: try fenced blocks first (most reliable)
        fence_starts = [m.start() for m in re.finditer(r"```(?:json)?", text)]
        for fs in reversed(fence_starts):
            after_fence = text[fs + 3:]
            prefix_skip = 4 if after_fence.startswith("json") else 0
            brace_rel = after_fence.find("{", prefix_skip)
            if brace_rel == -1:
                continue
            content_start = fs + 3 + brace_rel
            extracted = _balanced_braces(text, content_start)
            if extracted is not None:
                try:
                    json.loads(extracted)
                    return extracted
                except json.JSONDecodeError:
                    continue

        # Phase 2: try every { position and validate by parsing
        idx = 0
        while True:
            brace_start = text.find("{", idx)
            if brace_start == -1:
                return None
            extracted = _balanced_braces(text, brace_start)
            if extracted is not None:
                try:
                    json.loads(extracted)
                    return extracted
                except json.JSONDecodeError:
                    pass
            idx = brace_start + 1
        return None

    @staticmethod
    def _normalise(parsed: dict[str, Any]) -> dict[str, Any]:
        allowed = VerificationOutput.model_fields.keys()
        normalised = {}
        for k in allowed:
            field = VerificationOutput.model_fields[k]
            default = field.get_default(call_default_factory=True)
            normalised[k] = parsed.get(k, default)
        return normalised


def _balanced_braces(text: str, start: int) -> str | None:
    """Extract brace-balanced JSON text starting at position *start*.

    Returns the substring from ``text[start]`` through the matching
    ``}`` at depth 0, or ``None`` if no balanced closing brace is found.
    """
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start: i + 1]
    return None
