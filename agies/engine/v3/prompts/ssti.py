"""SSTI (Server-Side Template Injection) analysis prompt.

Detects: user input flowing into template engines without sanitization.
"""

SSTI_PROMPT_TEMPLATE = """You are analyzing a code path for **Server-Side Template Injection (SSTI)** vulnerabilities.

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
The sink function on this path renders a template with user-controllable input. Determine whether template injection is possible.

Checklist:
- [ ] Is user input used as the **template string** itself (``render_template_string(user_input)``)?
- [ ] Is user input passed as **template variable** content (e.g. ``render_template_string(\"...\", name=user_input)``)?
- [ ] If user input is a template variable (not the template itself): is the template context controlled? (``| safe`` filter, ``autoescape=False``)?
- [ ] For Jinja2: is ``Environment(autoescape=False)`` or ``SandboxedEnvironment`` used?
- [ ] For Mako: can arbitrary Python code be injected via ``${{...}}`` expressions?
- [ ] For Django templates: can ``{{% include ... %}}`` or ``{{% extends ... %}}`` be controlled?
- [ ] Can the template engine be forced to **include** other templates (local file inclusion via SSTI)?
- [ ] Is there a **sandbox escape** path (Jinja2: accessing ``__class__.__mro__`` chain to ``subprocess.Popen``)?
- [ ] Can user input reach ``Template()`` constructor directly?
- [ ] Is user input used in ``Environment.from_string()``?
- [ ] Could the developer have intentionally allowed template rendering in user-facing features (e.g. email templates, notification templates) with insufficient sandboxing?

**Common patterns**:
- Flask ``render_template_string(user_input)`` — **RCE if user input contains template directives**
- ``jinja2.Template(user_input).render()`` — direct template from user string
- ``Environment().from_string(user_input).render(**data)`` — same as above
- Mako ``Template(user_input).render()`` — supports arbitrary Python expressions
- ``template.render(user_input=payload)`` — variable injection, context-dependent
- Django ``Template(user_input)`` — limited but can leak variables

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "ssti",
  "sink_function": "render_template_string/Template.render/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain whether SSTI is possible, which engine, and exploitability.",
  "bypass_poc": "If vulnerable, provide example template injection payload."
}}
```
"""


def build_ssti_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    bypass_section = bypasses if bypasses else (
        "Common SSTI Bypass / Escalation Techniques\n"
        "- Jinja2 sandbox escape: ``{{ ''.__class__.__mro__[1].__subclasses__() }}`` → find Popen\n"
        "- Jinja2 filter bypass: ``{{ config.__class__.__init__.__globals__ }}``\n"
        "- Mako RCE: ``${import('os').popen('id').read()}``\n"
        "- Jinja2 hex/octal encoding: ``{{\"\\x5f\\x5fclass\\x5f\\x5f\"}}``\n"
        "- Jinja2 ``| attr()`` filter: ``{{ obj|attr(\"__subclasses__\") }}``\n"
        "- Django template: ``{% include \"/etc/passwd\" %}`` (file read, not RCE)\n"
        "- Jinja2 access to ``lipsum``: ``{{ lipsum.__globals__[\"os\"].popen(\"id\").read() }}``\n"
        "- Jinja2 access to ``cycler``: ``{{ cycler.__init__.__globals__.os.popen(\"id\").read() }}``\n"
        "- Bypass ``| safe`` if chained with user input in render context\n"
        "- ``{% print ... %}`` Jinja2 extension for output\n\n"
    )
    return SSTI_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )
