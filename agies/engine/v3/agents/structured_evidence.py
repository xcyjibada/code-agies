"""Structured evidence extraction and formatting for inter-agent communication.

Implements the JSON-wrapped CoT Protocol described in ``docs/op.md``:

1. Logic Agent embeds a `` ```json [STRUCTURED_EVIDENCE] `` block in its
   ``analysis`` string containing ``taint_path``, ``reasoning_steps``,
   ``exploitability_verdict``, and ``guards_detected``.
2. Downstream agents (Adversary, PoC) parse the block programmatically
   using ``extract_structured_evidence()`` with ``json_repair`` fallback.
3. If the block is missing or unparseable, the agent falls back to reading
   the free-text ``analysis`` — zero compatibility risk.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Regex: ```json [STRUCTURED_EVIDENCE]
#         { ... }
#         ```
STRUCTURED_EVIDENCE_RE = re.compile(
    r"```json\s*\[STRUCTURED_EVIDENCE\]\s*\n(.*?)\n```",
    re.DOTALL,
)


def extract_structured_evidence(analysis: str) -> dict[str, Any] | None:
    """Extract the ``[STRUCTURED_EVIDENCE]`` JSON block from analysis text.

    Returns ``None`` if no block is found or if all parsing attempts fail.
    The ``json_repair`` library is used as a fallback when the built-in
    ``json.loads`` fails — this handles common LLM output issues such as
    trailing commas, unescaped quotes, and missing brackets.

    **Behaviour**:
    1. Search for `` ```json [STRUCTURED_EVIDENCE] `` fence
    2. Try ``json.loads``
    3. On failure, try ``json_repair.repair_json``
    4. On complete failure, return ``None`` (caller falls back to free text)
    """
    match = STRUCTURED_EVIDENCE_RE.search(analysis)
    if not match:
        return None

    raw = match.group(1).strip()
    if not raw:
        return None

    # Attempt 1: standard json.loads
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # Attempt 2: json_repair (optional dependency)
    try:
        from json_repair import repair_json  # type: ignore[import-untyped]

        repaired = repair_json(raw)
        data = json.loads(repaired) if isinstance(repaired, str) else repaired
        if isinstance(data, dict):
            logger.debug("structured_evidence: repaired malformed JSON")
            return data
    except Exception:
        pass

    return None


def format_structured_evidence_block(
    taint_path: list[dict[str, str]] | None = None,
    reasoning_steps: list[str] | None = None,
    exploitability_verdict: str = "",
    guards_detected: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Format structured evidence as a fenced JSON block with tag.

    Returns an empty string when *all* data fields are empty (caller can
    skip the block entirely).

    The tag ``[STRUCTURED_EVIDENCE]`` lets ``extract_structured_evidence()``
    distinguish this block from ordinary JSON code fences in the same text.
    """
    evidence: dict[str, Any] = {}

    if taint_path:
        evidence["taint_path"] = taint_path
    if reasoning_steps:
        evidence["reasoning_steps"] = reasoning_steps
    if exploitability_verdict:
        evidence["exploitability_verdict"] = exploitability_verdict
    if guards_detected:
        evidence["guards_detected"] = guards_detected
    if extra:
        # Allow prompt authors to add custom fields without changing this API
        for k, v in extra.items():
            if v is not None and v != "" and v != []:
                evidence[k] = v

    if not evidence:
        return ""

    json_str = json.dumps(evidence, indent=2, ensure_ascii=False)
    return f"```json [STRUCTURED_EVIDENCE]\n{json_str}\n```"
