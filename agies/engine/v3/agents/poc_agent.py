"""PoC Agent — write executable PoC scripts for un-rebutted findings.

Generates a self-contained Python script that reproduces the vulnerability.
Saved to ``pocs/{target}-{path_id}-poc.py`` for manual execution by the user.
"""

from __future__ import annotations

import json
import logging
import os
import re

from agies.engine.v3.agents.structured_evidence import extract_structured_evidence

logger = logging.getLogger(__name__)

POC_PROMPT = """You are writing a Proof-of-Concept exploit script for **{project_desc}**. The finding below has survived adversarial review — write a working, self-contained Python script.

Finding
-------
- Vulnerability Type: {vuln_type}
- Project: {project_desc}
- Analysis: {analysis}
- Contradiction: {contradiction}
- Finding Strength: {weakness}
{structured_evidence}

Source Code (with data flow annotations)
```
{code_block}
```
The ``[DATA FLOW]`` section in the source shows which parameters at the entry function are attacker-controlled (UNTRUSTED) and traces how they propagate through the call chain to the sink. The ``[INTENT EVIDENCE]`` section shows each function's purpose, data flow (inputs/outputs), and suspicious observations — this is per-function evidence from the Intent Agent. The ``[STRUCTURED EVIDENCE]`` above (when present) is the Logic Agent's structured analysis.

**IMPORTANT — Confidence guidance**: All annotations are HELPFUL HINTS, not ground truth. Static data flow analysis is approximate (~60-70% accuracy for Python). Use them as clues to understand the code, but base your final PoC on your OWN reading of the source code. If you determine the sink argument IS reachable from untrusted input (even if annotations miss it), generate the PoC. If it is NOT reachable, do NOT generate a PoC.

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

    @staticmethod
    def _format_structured_evidence(analysis: str) -> str:
        """Extract and format ``[STRUCTURED_EVIDENCE]`` for prompt injection.

        Same format as AdversaryAgent._format_structured_evidence — keeps
        the structured data presentation consistent across all downstream agents.
        """
        ev = extract_structured_evidence(analysis)
        if not ev:
            return ""

        lines: list[str] = []

        tp = ev.get("taint_path", [])
        if tp and isinstance(tp, list):
            lines.append("[STRUCTURED EVIDENCE — Data Flow Trace]")
            for step in tp:
                lines.append(
                    f"  [{step.get('action', '?')}] {step.get('function', '?')} "
                    f"→ param: {step.get('param', '?')}"
                )

        rs = ev.get("reasoning_steps", [])
        if rs and isinstance(rs, list):
            lines.append("[STRUCTURED EVIDENCE — Logic Agent Reasoning]")
            for i, s in enumerate(rs, 1):
                lines.append(f"  {i}. {s}")

        verdict = ev.get("exploitability_verdict", "")
        if verdict:
            lines.append(f"[STRUCTURED EVIDENCE — Verdict] {verdict}")

        gd = ev.get("guards_detected", [])
        if gd and isinstance(gd, list):
            lines.append("[STRUCTURED EVIDENCE — Guards Detected]")
            for g in gd:
                lines.append(f"  - {g}")

        return "\n".join(lines)

    def prepare_prompt(
        self,
        vuln_type: str,
        analysis: str,
        contradiction: str,
        code_block: str,
        weakness: str = "",
    ) -> str:
        """Build the PoC generation prompt."""
        structured_section = self._format_structured_evidence(analysis)
        return POC_PROMPT.format(
            vuln_type=vuln_type.upper(),
            project_desc=self._project_desc,
            analysis=analysis or "(no analysis)",
            contradiction=contradiction or "(no contradiction)",
            weakness=weakness or "(strong finding)",
            code_block=code_block or "(code not loaded)",
            structured_evidence=(
                "\n" + structured_section if structured_section else ""
            ),
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
