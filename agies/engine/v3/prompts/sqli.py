"""SQLI (SQL Injection) analysis prompt.

Detects: execute/executemany/query calls with user-controllable input.
"""

SQLI_PROMPT_TEMPLATE = """You are analyzing a code path for **SQL Injection (SQLI)** vulnerabilities.

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
The sink function on this path executes SQL queries.
Determine if user-controlled data reaches the query parameter.

Checklist:
- [ ] Is user input concatenated directly into SQL strings?
- [ ] Are parameterized queries / prepared statements used?
- [ ] If ORM methods are used, are they safe by default?
- [ ] Is there any escaping? Can it be bypassed?
- [ ] Could second-order injection apply (data read from DB later used unsafely)?
- [ ] Is the error message exposed (helps crafting exploits)?
- [ ] What database is in use? (MySQL, PostgreSQL, SQLite — syntax varies)

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "sqli",
  "sink_function": "execute/executemany/cursor.execute/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain briefly whether the path is exploitable and why.",
  "bypass_poc": "If vulnerable, describe the injection point briefly."
}}
```
"""


def build_sqli_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    bypass_section = bypasses if bypasses else (
        "Common SQLI Bypass Techniques\n"
        "- Comments: --, /*, #\n"
        "- UNION-based extraction\n"
        "- Blind SQLI: AND 1=1 / OR 1=1, time-based (SLEEP, BENCHMARK)\n"
        "- String escaping: ' OR '1'='1\n"
        "- Second-order: stored XSS/false data that triggers on later query\n"
        "- WAF bypass: mixed case, comments inside keywords (SEL/**/ECT)\n\n"
    )
    return SQLI_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )
