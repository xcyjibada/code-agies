"""SSRF (Server-Side Request Forgery) analysis prompt.

Detects: urlopen/requests.get/httpx calls with user-controllable URLs.
"""

SSRF_PROMPT_TEMPLATE = """You are analyzing a code path for **Server-Side Request Forgery (SSRF)** vulnerabilities.

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
The sink function on this path makes outbound HTTP requests.
Determine if user-controlled data reaches the URL/endpoint parameter.

Checklist:
- [ ] Is the full URL user-controllable (host, path, scheme)?
- [ ] Is there URL validation? Can it be bypassed with redirects or DNS rebinding?
- [ ] Is there an allowlist of allowed hosts/domains? How is it implemented?
- [ ] Can internal services be accessed (127.0.0.1, 10.x, 172.x, 192.168.x)?
- [ ] Is the response returned to the user (reflective SSRF)?
- [ ] Could SSRF be chained with cloud metadata (169.254.169.254)?
- [ ] Are redirects followed automatically?

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "ssrf",
  "sink_function": "requests.get/urlopen/httpx.get/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain briefly whether the path is exploitable and why.",
  "bypass_poc": "If vulnerable, describe exploit target, e.g. http://169.254.169.254/latest/meta-data/"
}}
```
"""


def build_ssrf_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    bypass_section = bypasses if bypasses else (
        "Common SSRF Bypass Techniques\n"
        "- Redirect bypass: attacker.com → 127.0.0.1\n"
        "- DNS rebinding: short TTL to bypass allowlist\n"
        "- URL parser confusion: http://allowed-host@attacker\n"
        "- IPv6 loopback: [::1], [0:0:0:0:0:ffff:127.0.0.1]\n"
        "- Short URLs: 0/1/2130706433 (IP decimal)\n"
        "- Cloud metadata: 169.254.169.254\n\n"
    )
    return SSRF_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )
