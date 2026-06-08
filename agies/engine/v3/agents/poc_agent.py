"""PoC Agent — write executable PoC scripts for un-rebutted findings.

Generates a self-contained Python script that reproduces the vulnerability.
Saved to ``pocs/{target}-{path_id}-poc.py`` for manual execution by the user.
"""

from __future__ import annotations

import json
import logging
import os
import re

logger = logging.getLogger(__name__)

POC_PROMPT = """You are writing a Proof-of-Concept exploit script for **{project_desc}**. The finding below has survived adversarial review — write a working, self-contained Python script.

Finding
-------
- Vulnerability Type: {vuln_type}
- Project: {project_desc}
- Analysis: {analysis}
- Contradiction: {contradiction}
- Finding Strength: {weakness}

Source Code
```
{code_block}
```

Requirements for the PoC:
1. **Self-contained** — include all imports, no external dependencies beyond requests/stdlib
2. **Error handling** — catch connection errors, timeouts, print clear error messages
3. **Comments** — explain what each step does and what to expect
4. **Configurable** — target URL/host as a variable at the top or argparse
5. **Safe by default** — use a benign payload (e.g., ``touch /tmp/poc_success.txt`` or read a harmless file)

Output ONLY the Python script inside a code fence:

```python
#!/usr/bin/env python3
...
```
"""


def parse_poc_response(response: str) -> str:
    """Extract PoC script from the LLM response."""
    py_match = re.search(
        r"```python\s*\n(.*?)\n```",
        response,
        re.DOTALL,
    )
    if py_match:
        return py_match.group(1).strip()
    # Fallback: try any code fence
    code_match = re.search(
        r"```\s*\n(.*?)\n```",
        response,
        re.DOTALL,
    )
    if code_match:
        return code_match.group(1).strip()
    return response.strip()


class PoCAgent:
    """Generate PoC scripts for un-rebutted findings."""

    def __init__(self, output_dir: str = "", target: str = "") -> None:
        self._output_dir = output_dir or os.path.join(
            os.getcwd(), "pocs",
        )
        self._project_name = os.path.splitext(os.path.basename(os.path.normpath(target)))[0] if target else "unknown"
        self._project_desc = f"{self._project_name} ({target})" if target else "unknown project"

    def prepare_prompt(
        self,
        vuln_type: str,
        analysis: str,
        contradiction: str,
        code_block: str,
        weakness: str = "",
    ) -> str:
        """Build the PoC generation prompt."""
        return POC_PROMPT.format(
            vuln_type=vuln_type.upper(),
            project_desc=self._project_desc,
            analysis=analysis or "(no analysis)",
            contradiction=contradiction or "(no contradiction)",
            weakness=weakness or "(strong finding)",
            code_block=code_block or "(code not loaded)",
        )

    def write_script(self, path_id: str, script_content: str) -> str:
        """Write PoC script to disk, return the file path."""
        os.makedirs(self._output_dir, exist_ok=True)
        safe_project = re.sub(r"[^a-zA-Z0-9_-]", "_", self._project_name)
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", path_id)
        file_path = os.path.join(self._output_dir, f"{safe_project}-{safe_id}-poc.py")

        if not script_content.strip():
            logger.warning("PoCAgent: empty script content for %s", path_id)
            return ""

        # Prepend header comment with project context
        header = (
            f"#!/usr/bin/env python3\n"
            f"# PoC for {self._project_desc}\n"
            f"# Path: {path_id}\n"
            f"# Auto-generated — run with: python3 {os.path.basename(file_path)}\n"
            f"#\n"
        )
        content = header + script_content.strip()
        if not content.endswith("\n"):
            content += "\n"

        with open(file_path, "w") as f:
            f.write(content)
        os.chmod(file_path, 0o755)

        logger.info("PoCAgent: wrote %s", file_path)
        return file_path

    def run(
        self,
        path_id: str,
        vuln_type: str,
        analysis: str,
        contradiction: str,
        code_block: str,
        weakness: str = "",
        llm_response: str | None = None,
        llm_call=None,
    ) -> str:
        """Run PoC generation.

        Returns the file path to the written PoC script, or empty string if
        generation failed.
        """
        if llm_response is not None:
            script = parse_poc_response(llm_response)
        elif llm_call:
            prompt = self.prepare_prompt(
                vuln_type, analysis, contradiction, code_block, weakness,
            )
            response = llm_call(prompt)
            script = parse_poc_response(response) if response else ""
        else:
            return ""

        if not script:
            logger.warning("PoCAgent: no script generated for %s", path_id)
            return ""

        return self.write_script(path_id, script)
