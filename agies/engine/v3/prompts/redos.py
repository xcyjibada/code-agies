"""ReDoS (Regular Expression Denial of Service) analysis prompt.

Detects: user-supplied regex patterns, glob patterns that yield catastrophic
backtracking, and computationally expensive string matching.
"""

REDOS_PROMPT_TEMPLATE = """You are analyzing a code path for **ReDoS (Regular Expression Denial of Service)** vulnerabilities.

Project Context
{readme_summary}

Code Path (analysis chain)
Format: [summary] = intent pseudocode, [DANGEROUS: pass_through] = raw source code.
```
{code_block}
```

{bypass_section}
Analysis Focus
----
The sink function on this path performs string pattern matching.
Determine if a user can supply a regex or a pattern that triggers
catastrophic backtracking (exponential or polynomial time).

Checklist:
- [ ] Is the regex pattern user-controllable (request param, uploaded file name, config value)?
- [ ] Does the regex contain nested/unbounded quantifiers like ``(a+)+``, ``(a|)*``, ``(a*)*``?
- [ ] Does the regex have overlapping alternations like ``(a|a)+``, ``(ab|ab)*``?
- [ ] Are there user-supplied inputs to ``re.match``, ``re.search``, ``re.findall``, ``re.fullmatch``?
- [ ] Is ``fnmatch.translate()`` converting a glob pattern to regex? Can user supply the glob?
- [ ] Is ``re.compile()`` called with user data? Is the compiled regex reused across requests?
- [ ] Are there any limits on input length or match timeout?
- [ ] Is ``glob.glob()`` or ``Path.glob()`` called with user-controlled pattern?
- [ ] Does the match run on every request (amplification factor)?
- [ ] Are string methods like ``.replace()`` or ``.split()`` used on attacker-controlled data in hot paths?

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "redos",
  "sink_function": "re.match/re.search/re.compile/fnmatch.translate/glob/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain whether a ReDoS attack is feasible and what pattern causes it.",
  "bypass_poc": "If vulnerable, describe the payload pattern (e.g. 'a'*20 + '!' triggers backtracking on regex (a+)+b)."
}}
```
"""


def build_redos_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    bypass_section = bypasses if bypasses else (
        "Common ReDoS Attack Vectors\n"
        "- EvilRegex: ``(a+)+b`` with input ``aaaaaaaaac`` → exponential backtrack\n"
        "- Nested quantifiers: ``(.*)*``, ``(a*)*``, ``(a|b)*``\n"
        "- Overlapping alternations: ``(a|a)*``, ``(ab|ab)*``\n"
        "- Polynomial ReDoS: ``(a|b)+(a|b)+`` → quadratic time\n"
        "- Glob patterns: ``fnmatch.translate(\"***\")`` generates catastrophic regex\n"
        "- ``glob.glob(\"//...///...///...///...\")`` platform-dependent backtrack\n"
        "- ``re.sub()`` with callback: regex DoS still blocks the event loop\n"
        "- Empty-string matching: ``(a|)*`` matches any input with exponential states\n\n"
    )
    return REDOS_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )
