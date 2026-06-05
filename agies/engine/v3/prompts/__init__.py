"""Vulnerability-specific analysis prompts (adapted from VulnHuntr style).

Each module provides a ``build_prompt()`` function that returns the analysis
prompt for a specific vulnerability type, including bypass examples and
sink-specific guidance.

See ``docs/v3/plan.md`` Phase C for design rationale.
"""

from agies.engine.v3.prompts.rce import build_rce_prompt
from agies.engine.v3.prompts.lfi import build_lfi_prompt
from agies.engine.v3.prompts.ssrf import build_ssrf_prompt
from agies.engine.v3.prompts.sqli import build_sqli_prompt
from agies.engine.v3.prompts.xss import build_xss_prompt
from agies.engine.v3.prompts.afo import build_afo_prompt
from agies.engine.v3.prompts.idor import build_idor_prompt
from agies.engine.v3.prompts.redos import build_redos_prompt
from agies.engine.v3.prompts.readme_summary import build_readme_prompt

PROMPT_BUILDERS = {
    "rce": build_rce_prompt,
    "lfi": build_lfi_prompt,
    "ssrf": build_ssrf_prompt,
    "sqli": build_sqli_prompt,
    "xss": build_xss_prompt,
    "afo": build_afo_prompt,
    "idor": build_idor_prompt,
    "redos": build_redos_prompt,
}


def get_prompt(vuln_type: str, **kwargs) -> str:
    """Get the analysis prompt for a vulnerability type.

    Parameters
    ----------
    vuln_type : str
        One of ``"rce"``, ``"lfi"``, ``"ssrf"``, ``"sqli"``,
        ``"xss"``, ``"afo"``, ``"idor"``.
    **kwargs
        Passed through to the builder function (e.g. ``code_block``,
        ``readme_summary``, ``bypasses``).

    Returns
    -------
    str
        The analysis prompt text.
    """
    builder = PROMPT_BUILDERS.get(vuln_type)
    if builder is None:
        return _build_generic_prompt(**kwargs)
    return builder(**kwargs)


def _build_generic_prompt(
    code_block: str = "",
    readme_summary: str = "",
    **kwargs,
) -> str:
    """Generic prompt for unknown/unclassified vulnerability types."""
    return f"""You are analyzing a source-to-sink code path for potential security vulnerabilities.

Project Context
{readme_summary or "Not available."}

Code Path (analysis chain)
Format: [summary] = intent pseudocode, [DANGEROUS: pass_through] = raw source code.
```
{code_block or "(code not loaded)"}
```

Your task: Analyze this code path carefully. Consider:
1. Does user input reach the sink function without proper validation?
2. Are there any security controls (authentication, sanitization, authorization)?
3. Can any controls be bypassed?

Output your analysis as JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "unknown",
  "sink_function": "...",
  "confidence": 0-10,
  "analysis": "Brief explanation...",
  "bypass_poc": "If vulnerable, describe how to exploit..."
}}
```
"""
