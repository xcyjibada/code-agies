"""AFO (Arbitrary File Overwrite) analysis prompt.

Detects: write/save/upload/put with user-controllable path/content.
"""

AFO_PROMPT_TEMPLATE = """You are analyzing a code path for **Arbitrary File Overwrite (AFO)** vulnerabilities.

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
The sink function on this path writes files to the filesystem.
Determine if user-controlled data reaches the write path or content.

Checklist:
- [ ] Is the destination file path user-controllable?
- [ ] Is there path traversal protection? Can it be bypassed?
- [ ] Is the file being written via **archive extraction** (zipfile/tarfile)?
- [ ] If archive extraction: are entry names with ``../`` checked and rejected?
- [ ] Can critical files be overwritten? (configs, modules, startup scripts)
- [ ] Is the file content user-controllable? (script injection)
- [ ] Is there a race condition (TOCTOU)?
- [ ] Could symlink attacks apply?
- [ ] Are permissions/filesystem boundaries restrictive enough?

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "afo",
  "sink_function": "write/save/upload/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain briefly whether the path is exploitable and why.",
  "bypass_poc": "If vulnerable, describe what file could be overwritten and impact."
}}
```
"""


def build_afo_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    bypass_section = bypasses if bypasses else (
        "Common AFO Attack Vectors\n"
        "- Overwrite config files → escalate to RCE\n"
        "- Symlink race: create symlink to /etc/passwd before write\n"
        "- Overwrite Python __init__.py → code execution on import\n"
        "- Overwrite shell startup files (.bashrc, .profile)\n"
        "- Overwrite SSH authorized_keys\n"
        "- Write to web root → webshell\n"
        "- **Zip/Tar slip**: archive entry with ``../../../etc/cron.d/evil`` name\n"
        "- Zip symlink extraction: archive entry as symlink to /etc/passwd\n\n"
    )
    return AFO_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )
