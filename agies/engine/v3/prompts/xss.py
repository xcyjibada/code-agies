"""XSS (Cross-Site Scripting) analysis prompt.

Detects: render_template_string/format/Response with unsanitized data.
"""

XSS_PROMPT_TEMPLATE = """You are analyzing a code path for **Cross-Site Scripting (XSS)** vulnerabilities.

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
The sink function on this path renders user-controlled data into HTML/templates.
Determine if user input reaches the render/output without proper escaping.

Checklist:
- [ ] Is user input rendered directly in HTML/templates without escaping?
- [ ] Are auto-escaping templates used (Jinja2 autoescape, React JSX)?
- [ ] Is ``|safe``, ``Markup()``, ``__html__``, ``dangerouslySetInnerHTML`` used?
- [ ] Could the input context matter (HTML body vs attribute vs script tag vs CSS)?
- [ ] Can the user control the template itself (SSTI)?
- [ ] Is Content-Type properly set? (text/html vs application/json)
- [ ] Are CSP headers set? Can they be bypassed?

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "xss",
  "sink_function": "render_template_string/format/Response/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain briefly whether the path is exploitable and why.",
  "bypass_poc": "If vulnerable, provide a short XSS payload."
}}
```
"""


def build_xss_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    bypass_section = bypasses if bypasses else (
        "Common XSS Bypass Techniques\n"
        "- Event handlers: <img src=x onerror=alert(1)>\n"
        "- SVG: <svg onload=alert(1)>\n"
        "- Script without tags: <script>alert(1)</script>\n"
        "- UTF-7: +ADw-script+AD4-alert(1)+ADw-/script+AD4-\n"
        "- Filter bypass: <img src=x onerror=alert(1)>\n"
        "- DOM clobbering: <a id=defaultAvatar><a id=defaultAvatar name=avatar href=\"x:alert(1)\">\n\n")
    return XSS_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )
