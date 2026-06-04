"""LFI (Local File Inclusion) analysis prompt.

Detects: open/file/read operations with user-controllable paths.
"""

LFI_PROMPT_TEMPLATE = """You are analyzing a code path for **Local File Inclusion / Path Traversal** vulnerabilities.

Project Context
{readme_summary}

Source Code (call chain)
```
{code_block}
```

{bypass_section}
Analysis Focus
----
The sink function on this path reads files or accesses the filesystem.
Determine if user-controlled data reaches the sink without proper validation.

Checklist:
- [ ] Is user input used in file path construction?
- [ ] Is there path traversal protection (os.path.realpath, abspath, normpath)?
- [ ] If path validation exists, is it complete? (single replace vs recursive)
- [ ] Does the function use ``posixpath.join`` or string concatenation for paths?
- [ ] If ``posixpath.join`` is used: does it sanitize ``../`` from each component?
- [ ] Is this a **library utility** (``__truediv__``, ``joinpath``, ``PurePosixPath``) that other code calls with user input?
- [ ] **Archive path traversal**: does this function operate on zip/tar entries? Are entry names with ``../`` rejected?
- [ ] Can encoding tricks bypass filters? (URL encoding, Unicode, double encoding)
- [ ] Does the application join paths safely (os.path.join) or concatenate strings?
- [ ] Is the file read exposed to other users (auth bypass)?
- [ ] Could this be used to read config files, source code, /etc/passwd, etc.?

**Note on path-construction utilities**: If the sink is a ``posixpath.join``, ``PurePosixPath``, or similar utility that only *constructs* a path (no file I/O), consider that:
1. This path will be used by callers for file read/write operations
2. If ``../`` is not sanitized here, callers will operate on paths outside the intended base
3. The question is: does this function validate/sanitize path components, or does it assume the caller provides safe input?
4. Even if this function doesn't do I/O itself, if it constructs a traversed path without sanitization, it enables path traversal when the result reaches a downstream I/O operation.

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "lfi",
  "sink_function": "open/read/Path.read_text/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain briefly whether the path is exploitable and why.",
  "bypass_poc": "If vulnerable, describe exploit path, e.g. ../../etc/passwd"
}}
```
"""


def build_lfi_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    bypass_section = bypasses if bypasses else (
        "Common Path Traversal Bypass Techniques\n"
        "- Single replace bypass: ....// or ....\\/\\\n"
        "- Double encoding: %252e%252e%252f\n"
        "- Unicode: ..%c0%af (overlong UTF-8)\n"
        "- Null byte injection: file.txt%00.txt\n"
        "- Wrapper protocols: php://filter, file://\n"
        "- Absolute path bypass: /etc/passwd instead of ../../\n"
        "- Library alias bypass: ``__truediv__`` → ``joinpath`` if only one is sanitized\n"
        "- Archive entry traversal: zip entry with ``../../../etc/passwd`` name\n\n"
    )
    return LFI_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )
