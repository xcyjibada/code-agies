"""RCE analysis prompt — adapted from VulnHuntr.

Detects: exec/eval/subprocess/os.system calls with user-controllable input.
"""

RCE_PROMPT_TEMPLATE = """You are analyzing a Python code path for **Remote Code Execution (RCE)** vulnerabilities.

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
The sink function on this path executes system commands or evaluates code.
Determine if user-controlled data reaches the sink without proper validation.

Checklist:
- [ ] Does user input (HTTP params, file upload, headers, body) reach exec/eval/subprocess/os.system?
- [ ] Is shell=True used with subprocess? (dramatically increases risk)
- [ ] Are there any input filters or sanitizers? Can they be bypassed?
- [ ] Is the input concatenated into a command string vs passed as arguments array?
- [ ] Could path traversal allow loading arbitrary modules/scripts?
- [ ] Is there a chokepoint that limits exploitation?

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "rce",
  "sink_function": "exec/eval/subprocess.call/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain whether the path is exploitable and why.",
  "bypass_poc": "If vulnerable, describe the exploit payload briefly."
}}
```
"""


def build_rce_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    """Build the RCE analysis prompt."""
    bypass_section = _build_bypass_section(bypasses)
    return RCE_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )


def _build_bypass_section(bypasses: str) -> str:
    if bypasses:
        return f"Known Bypass Techniques (for reference)\n{bypasses}\n\n"
    return (
        "Common RCE Bypass Techniques (for reference)\n"
        "- Reverse shell: python -c 'import socket...' \n"
        "- Blind RCE: time-based exfiltration\n"
        "- Filter bypass: ${IFS} instead of spaces, base64 encoding\n"
        "- Chained commands: ; && || | \\n"
        "- Newline injection in exec/eval\n\n"
    )
