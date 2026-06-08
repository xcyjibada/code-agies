"""Suspicious code path analysis prompt.

Unlike other vulnerability-specific prompts (LFI, RCE, SSRF, …), this
prompt does NOT pre-judge the vulnerability type.  It is used when the
pathfinder detected a sensitive operation (e.g. path construction, archive
handling) but the vulnerability class is not clear from the sink alone.

The LLM is asked to freely analyze what kind of vulnerability could exist.
"""

SUSPICIOUS_PROMPT_TEMPLATE = """You are analyzing a code path for **potential security vulnerabilities**.

The code below involves sensitive operations (path construction, archive
handling, or internal logic) that COULD be vulnerable — but the specific
vulnerability type is not predetermined.  You must determine what kind of
vulnerability (if any) exists.

Project Context
{readme_summary}

Code Path (analysis chain)
Format: [summary] = intent pseudocode, [DANGEROUS: pass_through] = raw source code.
```
{code_block}
```

Analysis Focus
----
The code performs operations on paths, archives, or internal data structures
that could be exploitable in several ways.  Consider ALL of the following
vulnerability classes:

1. **DoS / Infinite Loop** — Does the code iterate over archive entries or
   path components in a way that could hang or loop infinitely on crafted
   input? (``__truediv__``, ``joinpath``, ``iterdir``, zip entry iteration)
2. **Path Traversal (LFI)** — If constructed paths reach file read/write
   operations, can ``../`` escape the intended directory?
3. **Zip/Tar Slip (AFO)** — Does archive extraction write files outside the
   target directory via entry names containing ``../``?
4. **Logic Error** — Is there a mismatch between what the developer intended
   and what the code actually does? (missing validation, incorrect bounds check)
5. **Resource Exhaustion** — Could the code consume excessive memory, disk,
   or file descriptors on crafted input (zip bomb, symlink loop)?

Checklist:
- [ ] What operations does this function perform? (path construction, archive iteration, file I/O?)
- [ ] Does it accept external/untrusted input? (function parameters, class constructor args)
- [ ] Does it validate or sanitize that input? (path component check, archive entry name check)
- [ ] Could a crafted input cause unexpected behavior? (infinite loop, path escape, crash)
- [ ] If this is a **library utility** (``__truediv__``, ``joinpath``, ``PurePosixPath``):
  - What happens when external/untrusted data reaches this function via callers?
  - Does it have any validation at all, or does it assume caller provides safe input?
  - Can the constructed path be used by downstream callers to read/write outside intended base?
- [ ] If this involves archive iteration: can a malicious archive trigger an infinite loop?
- [ ] If this constructs paths: is ``../`` blocked, or could it traverse directories?
- [ ] Are there any missing validation steps that a caller could bypass?

CRITICAL: Be specific about which vulnerability class applies (or state "none").
Do NOT default to "path traversal" just because path operations are involved.
The real vulnerability could be something unexpected like a DoS/infinite loop.

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "rce/lfi/ssrf/sqli/xss/afo/idor/redos/dos/logic/none",
  "sink_function": "function name",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "What kind of vulnerability is this (if any)? Be specific about the vulnerability class and why it applies.",
  "bypass_poc": "If vulnerable, describe a concrete exploit scenario. Be precise about what input triggers it."
}}
```
"""


def build_suspicious_prompt(
    code_block: str = "",
    readme_summary: str = "",
    **kwargs,
) -> str:
    return SUSPICIOUS_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
    )
