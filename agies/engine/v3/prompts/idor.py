"""IDOR (Insecure Direct Object Reference) analysis prompt.

Detects: direct object lookup/filter/get with user-controllable identifiers.
"""

IDOR_PROMPT_TEMPLATE = """You are analyzing a code path for **Insecure Direct Object Reference (IDOR)** vulnerabilities.

Project Context
{readme_summary}

Source Code (call chain)
```
{code_block}
```

{bypass_section}
Analysis Focus
----
The sink function on this path retrieves or manipulates objects by identifier.
Determine if a user can access/modify objects they should not have access to.

Checklist:
- [ ] Is the object identifier (ID, PK, key) user-controllable?
- [ ] Is there authorization/ownership checking before access?
- [ ] Are object IDs predictable? (incrementing integers vs UUIDs)
- [ ] Is the access control check complete? (checked in middleware but not in handler?)
- [ ] Can the identifier be changed in a follow-up request?
- [ ] Are there rate limits or brute-force protections?
- [ ] Could mass assignment / parameter tampering bypass access controls?

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "idor",
  "sink_function": "get_object_or_404/queryset.filter/Model.objects/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain briefly whether the path is exploitable and why.",
  "bypass_poc": "If vulnerable, describe the IDOR scenario briefly."
}}
```
"""


def build_idor_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    bypass_section = bypasses if bypasses else (
        "Common IDOR Bypass Techniques\n"
        "- Increment ID: /api/user/1 → /api/user/2\n"
        "- UUID enumeration if predictable generation\n"
        "- Mass assignment: extra fields in POST body\n"
        "- Role/scope confusion: user can access admin endpoints\n"
        "- Missing ownership check in nested resources\n"
        "- Insecure direct function reference → IDOR bypass\n\n"
    )
    return IDOR_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )
