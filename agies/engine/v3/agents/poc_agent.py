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
    """Generate PoC scripts for un-rebutted findings.

    Writes scripts to ``{output_dir}/{project_name}/{descriptive_name}.py``
    so each project's PoCs live in their own subfolder with human-readable
    filenames.
    """

    def __init__(self, output_dir: str = "", target: str = "") -> None:
        self._base_dir = output_dir or os.path.join(os.getcwd(), "pocs")
        raw = os.path.basename(os.path.normpath(target)) if target else "unknown"
        # Use the full directory name so versioned tarballs keep their label
        self._project_name = raw
        self._project_desc = f"{raw} ({target})" if target else "unknown project"
        # Output to ``pocs/{project_name}/``
        self._output_dir = os.path.join(self._base_dir, self._project_name)

    # ── helper: extract a short human-readable label from analysis text ──
    @staticmethod
    def _describe(analysis: str, sink_name: str, vuln_type: str) -> str:
        """Return a short kebab-case label like ``path_traversal_convert_generic``.

        Priority:
        1. First sentence of *analysis* (up to ~6 words) + sink name
        2. Fallback: vuln_type + sink_name
        """
        # Grab the first meaningful sentence
        m = re.search(r"([A-Z][^.]{10,60}\.)", analysis)
        desc = m.group(1).rstrip(".") if m else vuln_type.lower()
        # Shrink to a handful of keywords
        words = re.findall(r"[a-zA-Z][a-zA-Z0-9]+", desc)
        keywords = [w for w in words if w.lower() not in
                    {"the", "a", "an", "is", "are", "was", "were",
                     "can", "will", "would", "could", "should",
                     "this", "that", "these", "those", "it", "its",
                     "in", "on", "at", "to", "for", "of", "by", "with",
                     "via", "and", "or", "not", "no", "be", "has", "have",
                     "from", "an", "attacker", "user", "provides",
                     "parameter", "value", "file", "path"}][:4]
        label = "_".join(keywords).lower() if keywords else vuln_type.lower()
        # Prepend vuln type as prefix so filenames are always identifiable
        vuln_prefix = vuln_type.lower()
        if vuln_prefix and not label.startswith(vuln_prefix):
            label = f"{vuln_prefix}_{label}"
        if sink_name:
            # Append the sink function name for disambiguation
            short = sink_name.split(".")[-1].split("(")[0].strip()
            if short:
                label = f"{label}_{short}"
        # Strip any leading/trailing underscores
        label = label.strip("_")
        return label

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

    def write_script(
        self,
        path_id: str,
        script_content: str,
        sink_name: str = "",
        analysis: str = "",
        vuln_type: str = "",
    ) -> str:
        """Write PoC script to ``pocs/{project}/{label}.py``, return the path."""
        os.makedirs(self._output_dir, exist_ok=True)

        if not script_content.strip():
            logger.warning("PoCAgent: empty script content for %s", path_id)
            return ""

        # Build descriptive filename from analysis text + sink name
        label = self._describe(analysis or vuln_type, sink_name, vuln_type)

        # Write ``pocs/safetensors-0.8.0/path_traversal_convert_generic.py``
        file_path = os.path.join(self._output_dir, f"{label}.py")

        # Deduplicate: if a file already exists with same label, append -N
        counter = 1
        while os.path.exists(file_path):
            counter += 1
            file_path = os.path.join(self._output_dir, f"{label}_{counter}.py")

        # Prepend header comment with project context
        header = (
            f"#!/usr/bin/env python3\n"
            f"# PoC for {self._project_desc}\n"
            f"# Path: {path_id}\n"
            f"# Sink: {sink_name}\n"
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
        sink_name: str = "",
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

        return self.write_script(
            path_id, script,
            sink_name=sink_name,
            analysis=analysis,
            vuln_type=vuln_type,
        )
