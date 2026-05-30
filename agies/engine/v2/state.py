"""Project analysis state — tracks what's been done and what's available."""

from __future__ import annotations

import difflib
import json
import os
from dataclasses import dataclass, field
from typing import Any, ClassVar

from agies.engine.v2.sourcer.models import CandidateFinding, FunctionIndex


@dataclass
class ProjectState:
    """Full analysis state for a single code audit project.

    The Brain reads this to decide what to do next.
    Agents write results into this after completion.
    """

    # Project info
    project_path: str = ""
    language: str = ""
    framework: str = ""
    file_count: int = 0

    # Mapping (set by Mapping Agent)
    project_summary: str = ""
    modules: list[dict] = field(default_factory=list)
    key_files: list[dict] = field(default_factory=list)
    trust_assumptions: list[dict] = field(default_factory=list)

    # Attack surface (set by AttackSurface Agent)
    entry_points: list[dict] = field(default_factory=list)

    # Dataflow paths (set by DataFlow Agents)
    dataflow_paths: list[dict] = field(default_factory=list)

    # Function index (set by Sourcer — deterministic, no LLM)
    function_index: FunctionIndex | None = None

    # Phase 1 candidates (set by bulk_analysis)
    candidates: list[CandidateFinding] = field(default_factory=list)

    # Candidate vulnerabilities (set by Vulnerability Agents)
    candidate_vulnerabilities: list[dict] = field(default_factory=list)

    # Verified findings (set by Verify Agents)
    verified_findings: list[dict] = field(default_factory=list)

    # Blackboard — cross-agent derived knowledge (set by record_knowledge tool)
    discovered_logic: dict[str, str] = field(default_factory=dict)
    """Cross-agent knowledge sharing.

    Key = function name or file path.
    Value = free-text summary of what was discovered about that symbol.

    Populated by agents calling ``record_knowledge(key, value)`` during
    analysis.  Consumed by Brain when dispatching the next agent — any
    agent working on a function/file that appears in this dict gets the
    relevant knowledge injected as ``[PRIOR_KNOWLEDGE]`` in its system
    prompt.
    """

    # Agent tracking
    completed_agents: list[str] = field(default_factory=list)
    last_batch_reason: str = ""

    # Two-round verification: Round 1 = high-confidence (bulk + pre-scan),
    # Round 2 = low-confidence (Director/Boundary injected).
    # After Round 1 completes, Brain logs progress and decides Round 2.
    verification_round: int = 1

    # Pipeline mode: False = legacy (mapping → attack_surface → dataflow → vuln → verify)
    # True = new Xint-inspired pipeline (mapping → sourcer → bulk → verification)
    use_new_pipeline: bool = False

    # Raw agent outputs (for context building)
    agent_outputs: list[dict] = field(default_factory=list)

    # Dedup stats
    dedup_stats: dict[str, int] = field(default_factory=dict)
    """Tracks ``{"total_raw": N, "after_dedup": M}`` across all runs."""

    # Per-agent token usage
    agent_tokens: dict[str, int] = field(default_factory=dict)
    """Maps ``agent_name → total_tokens`` across all runs."""

    # ProgramGraph (populated by Director / GraphGenerator)
    # Unified function-level call graph with signals and scores.
    program_graph: Any = None

    # Director analysis cards (populated by Director.Phase 0)
    analysis_cards: list = field(default_factory=list)
    """Ranked EntryAnalysisCard list from the Director layer."""

    # Director entry points (includes SAST-prescan-promoted critical files).
    # Stored separately from analysis_cards so the Sourcer can always do full
    # AST extraction for critical files even when their cards fall outside the
    # top-15 limit.
    director_entry_points: list[str] = field(default_factory=list)
    """All entry point paths from the Director (including SAST-promoted sinks)."""

    # Classified cards (populated after analysis_cards by Brain)
    hot_cards: list = field(default_factory=list)
    """Cards with final_score >= 80th percentile — full deep analysis."""
    warm_cards: list = field(default_factory=list)
    """Cards with 40th <= final_score < 80th percentile — quick scan."""
    cold_cards: list = field(default_factory=list)
    """Cards with final_score < 40th percentile — SAST signal only, no LLM."""

    # Token budget tracking
    total_tokens_consumed: int = 0
    token_budget: int = 0
    """Max tokens this run may consume (0 = unlimited)."""

    # SAST-only signals (cold cards, no LLM dispatch)
    silent_signals: list[dict] = field(default_factory=list)

    # Summary for the Brain (compressed version of everything above)
    brain_summary: str = ""

    def is_complete(self) -> bool:
        """Check if analysis should stop."""
        return "report" in self.completed_agents

    def get_available_agents(self) -> list[str]:
        """Return agent names that make sense to run right now.

        New pipeline (REFACTOR.md):

          1. ``mapping`` — project understanding (always first)
          2. ``sourcer`` — build FunctionIndex (deterministic, no LLM)
          3. ``bulk_analysis`` — Phase 1: parallel per-function/chunk scan
          4. ``verification`` — Phase 2: tool-using agent per candidate

        Legacy vulnerability modes are kept for backward compatibility.
        """
        agents = []

        if "mapping" not in self.completed_agents:
            agents.append("mapping")

        # --- New pipeline (Xint-inspired) — opt-in via use_new_pipeline flag ---
        if self.use_new_pipeline and "mapping" in self.completed_agents:
            if self.function_index is None:
                agents.append("sourcer")

        if self.use_new_pipeline and self.function_index is not None:
            if "bulk_analysis" not in self.completed_agents:
                agents.append("bulk_analysis")

        if self.use_new_pipeline and "bulk_analysis" in self.completed_agents:
            unverified = [c for c in self.candidates if not getattr(c, "verified", False)]
            if "verification" not in self.completed_agents and unverified:
                agents.append("verification")
            elif self.verification_round == 2 and unverified:
                # Round 2: low-confidence candidates (Director/Boundary injected)
                agents.append("verification")

        # --- Legacy vulnerability modes (backward compat) ---
        if "mapping" in self.completed_agents:
            if not self.entry_points:
                if "attack_surface" not in self.completed_agents:
                    agents.append("attack_surface")
                unanalyzed = [kf for kf in self.key_files if not kf.get("vuln_analyzed")]
                if unanalyzed and "vulnerability" not in agents:
                    agents.append("vulnerability")

            if self.entry_points:
                if "attack_surface" not in self.completed_agents:
                    agents.append("attack_surface")

                if "attack_surface" in self.completed_agents:
                    unanalyzed_entries = [
                        ep for ep in self.entry_points if not ep.get("dataflow_done")
                    ]
                    if unanalyzed_entries:
                        agents.append("dataflow")

                if self.dataflow_paths:
                    unanalyzed_paths = [
                        p for p in self.dataflow_paths if not p.get("vuln_analyzed")
                    ]
                    if unanalyzed_paths:
                        agents.append("vulnerability")

        # --- verify / report (shared across both modes) ---
        if self.candidate_vulnerabilities:
            unverified = [v for v in self.candidate_vulnerabilities if not v.get("verified")]
            if unverified:
                agents.append("verify")

        if self.candidate_vulnerabilities and "report" not in self.completed_agents:
            all_verified = all(v.get("verified") for v in self.candidate_vulnerabilities)
            if all_verified:
                agents.append("report")

        return agents

    def register_result(self, agent_name: str, params: dict, output: dict, tokens: int = 0) -> None:
        """Register an agent's completion result into state.

        Args:
            agent_name: Which agent produced this result.
            params: The params dict it was called with.
            output: Structured output (e.g. vulnerability list).
            tokens: Approximate token count for this agent run.
        """
        self.completed_agents.append(agent_name)
        self.agent_outputs.append({
            "agent": agent_name,
            "params": params,
            "output_summary": _truncate_for_summary(output),
        })
        self.agent_tokens[agent_name] = self.agent_tokens.get(agent_name, 0) + tokens
        self.total_tokens_consumed += tokens

        # Route output to the appropriate field
        if agent_name == "mapping":
            self.project_summary = output.get("summary", "")
            self.modules = output.get("modules", [])
            self.key_files = output.get("key_files", [])
            self.language = output.get("language", "")
            self.framework = output.get("framework", "")
            self.file_count = output.get("file_count", 0)
            self.trust_assumptions = output.get("trust_assumptions", [])

        elif agent_name == "attack_surface":
            self.entry_points = output.get("entry_points", [])

        elif agent_name == "dataflow":
            for path in output.get("paths", []):
                path["dataflow_done"] = True
            self.dataflow_paths.extend(output.get("paths", []))
            # Always mark the originating entry point as done.
            # Handles both empty-success (no exploitable paths found) and
            # final-failure (all retries exhausted) without stalling the
            # pipeline for other entry points.
            for ep in self.entry_points:
                if ep.get("id") == params.get("entry_point_id"):
                    ep["dataflow_done"] = True

        elif agent_name == "sourcer":
            self.function_index = output.get("function_index")

        elif agent_name == "bulk_analysis":
            self.candidates.extend(output.get("candidates", []))

        elif agent_name == "verification":
            for c in self.candidates:
                vid = params.get("candidate_index")
                if vid is not None and self.candidates.index(c) == vid:
                    c.verified = True
                    c.verification_result = output
                    if output:
                        self.verified_findings.append({
                            "function_name": c.function_name,
                            "file_path": c.file_path,
                            "type": c.type,
                            "triggerable": output.get("triggerable", False),
                            "conditions": output.get("conditions", ""),
                            "false_positive_reason": output.get("false_positive_reason", ""),
                            "confidence": output.get("confidence", "medium"),
                            "evidence": output.get("evidence", []),
                        })

        elif agent_name == "vulnerability":
            raw_vulns = output.get("vulnerabilities", [])
            deduped = self._deduplicate_vulnerabilities(raw_vulns)

            for vuln in deduped:
                vuln["vuln_analyzed"] = True

            # Track dedup stats
            self.dedup_stats["total_raw"] = (
                self.dedup_stats.get("total_raw", 0) + len(raw_vulns)
            )
            self.dedup_stats["after_dedup"] = (
                self.dedup_stats.get("after_dedup", 0) + len(deduped)
            )

            # Mark key_file / dataflow path as analyzed
            key_file_path = params.get("key_file_path")
            if key_file_path:
                for kf in self.key_files:
                    kf_path = kf.get("path", "")
                    if kf_path == key_file_path or os.path.join(self.project_path, kf_path) == key_file_path:
                        kf["vuln_analyzed"] = True

            path_id = params.get("path_id")
            if path_id:
                for path in self.dataflow_paths:
                    if path.get("id") == path_id:
                        path["vuln_analyzed"] = True

            self.candidate_vulnerabilities.extend(deduped)

        elif agent_name == "verify":
            for finding in output.get("findings", []):
                finding["verified"] = True
            self.verified_findings.extend(output.get("findings", []))
            # Always mark the candidate vulnerability as processed.
            # Handles both empty-output (no findings after verification) and
            # final-failure (all retries exhausted) without stalling.
            vid = params.get("vulnerability_id")
            for v in self.candidate_vulnerabilities:
                if v.get("id") == vid:
                    v["verified"] = True

        # Always rebuild brain summary after state change
        self._rebuild_brain_summary()

    # ------------------------------------------------------------------
    # Blackboard: cross-agent knowledge
    # ------------------------------------------------------------------

    def record_knowledge(self, key: str, value: str) -> None:
        """Record a discovered fact for cross-agent knowledge sharing.

        *key* is a function name or file path.
        *value* is a free-text summary of what was discovered.

        If the same *key* receives multiple recordings, values are
        appended so earlier knowledge is never lost.
        """
        if not key or not value:
            return
        existing = self.discovered_logic.get(key, "")
        if existing:
            self.discovered_logic[key] = existing + "\n\n" + value
        else:
            self.discovered_logic[key] = value

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    # Type normalisation map: alias → canonical name.
    # Keeps the type field consistent across different agent invocations.
    VULN_TYPE_ALIASES: ClassVar[dict[str, str]] = {
        # SQL injection
        "sqli": "sql_injection",
        # XSS
        "xss": "cross_site_scripting",
        "stored_xss": "cross_site_scripting",
        "reflected_xss": "cross_site_scripting",
        # Session
        "session_tampering": "session_forgery",
        "session_fixation": "session_forgery",
        "integrity_forgery": "session_forgery",
        "insufficient_encryption": "session_forgery",
        # Auth
        "auth_bypass": "authentication_bypass",
        "auth": "authentication_bypass",
        # CSRF
        "csrf": "cross_site_request_forgery",
        # IDOR
        "idor": "idor",
        # Path traversal
        "path_traversal": "path_traversal",
        # Race condition
        "race_condition": "race_condition",
        # Info disclosure
        "information_disclosure": "information_disclosure",
        # Missing protection
        "missing_protection": "missing_protection",
        # Hardcoded secret
        "hardcoded_secret": "hardcoded_secret",
        # Weak security control
        "weak_security_control": "weak_security_control",
        # Missing auth
        "missing_authentication": "missing_authentication",
        # Business logic
        "business_logic_flaw": "business_logic_flaw",
        # Input tampering
        "input_tampering": "input_tampering",
        # Denial of service
        "denial_of_service": "denial_of_service",
        # Broken auth
        "broken_authentication": "broken_authentication",
    }

    @staticmethod
    def _normalise_vuln_type(raw_type: str) -> str:
        """Map a raw LLM type label to a canonical name."""
        lower = raw_type.lower().strip()
        return ProjectState.VULN_TYPE_ALIASES.get(lower, lower)

    @staticmethod
    def _title_similarity(a: str, b: str) -> float:
        """Return a 0-1 similarity score between two finding titles."""
        return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()

    def _deduplicate_vulnerabilities(
        self,
        new_vulns: list[dict],
    ) -> list[dict]:
        """Deduplicate *new* findings against *candidate_vulnerabilities*.

        Strategy (three-tier, strict→fuzzy):

        1. **Exact location match** — same ``(file_path, line_number, type)``.
           If a vuln already exists at the same file+line+type, the new one is
           dropped regardless of wording.

        2. **Proximity match** — same ``(file_path, type)`` and line numbers
           within 3 lines of each other.  Keeps the existing one.

        3. **Title-similarity match** — when location is unavailable or the
           above rules don't apply, compare titles with a 0.70+ threshold.
        """
        if not new_vulns:
            return []

        # Normalise types of existing vulns so comparison works correctly
        existing_normalised: list[dict] = []
        for v in self.candidate_vulnerabilities:
            entry = dict(v)
            entry["_norm_type"] = self._normalise_vuln_type(entry.get("type", ""))
            existing_normalised.append(entry)

        deduped: list[dict] = []
        for nv in new_vulns:
            nv_type = self._normalise_vuln_type(nv.get("type", ""))
            nv_file = nv.get("file_path", "")
            nv_line = nv.get("line_number", 0) or 0
            nv_title = nv.get("title", "")

            is_dup = False

            for ev in existing_normalised:
                ev_type = ev["_norm_type"]
                ev_file = ev.get("file_path", "")
                ev_line = ev.get("line_number", 0) or 0

                # Tier 1: exact location match
                if (
                    nv_file == ev_file
                    and nv_line == ev_line
                    and nv_line > 0
                    and nv_type == ev_type
                ):
                    is_dup = True
                    break

                # Tier 2: proximity match (same file+type, lines within 3)
                if (
                    nv_file == ev_file
                    and nv_type == ev_type
                    and nv_line > 0
                    and ev_line > 0
                    and abs(nv_line - ev_line) <= 3
                ):
                    is_dup = True
                    break

            if not is_dup:
                # Tier 3: title similarity against all existing + already-deduped
                for ev in existing_normalised:
                    ev_title = ev.get("title", "")
                    if nv_title and ev_title:
                        if self._title_similarity(nv_title, ev_title) >= 0.70:
                            # Also check same file+type for title-match
                            if nv_file == ev.get("file_path", "") and nv_type == ev["_norm_type"]:
                                is_dup = True
                                break

            if not is_dup:
                # Also check against the current deduped batch
                for dv in deduped:
                    dv_file = dv.get("file_path", "")
                    dv_line = dv.get("line_number", 0) or 0
                    dv_type = self._normalise_vuln_type(dv.get("type", ""))

                    if (
                        nv_file == dv_file
                        and nv_line == dv_line
                        and nv_line > 0
                        and nv_type == dv_type
                    ):
                        is_dup = True
                        break

                    if (
                        nv_file == dv_file
                        and nv_type == dv_type
                        and nv_line > 0
                        and dv_line > 0
                        and abs(nv_line - dv_line) <= 3
                    ):
                        is_dup = True
                        break

            if not is_dup:
                # Store normalised type for consistency
                nv["_norm_type"] = nv_type
                deduped.append(nv)

        return deduped

    def _rebuild_brain_summary(self) -> None:
        """Build a compressed summary string for the Brain."""
        parts = [
            f"Project: {self.project_path}",
            f"Language: {self.language or 'unknown'}, Framework: {self.framework or 'unknown'}",
            f"Files: {self.file_count}",
            f"Modules: {len(self.modules)}",
            f"Completed agents: {', '.join(self.completed_agents) or 'none'}",
        ]
        if self.project_summary:
            parts.append(f"Summary: {self.project_summary[:500]}")
        if self.trust_assumptions:
            assumptions = [a.get("assumption", "")[:120] for a in self.trust_assumptions[:5]]
            parts.append("Trust assumptions: " + " | ".join(assumptions))

        ep_counts = {
            "unanalyzed": sum(1 for ep in self.entry_points if not ep.get("dataflow_done")),
            "done": sum(1 for ep in self.entry_points if ep.get("dataflow_done")),
        }
        parts.append(f"Entry points: {ep_counts['done']} done, {ep_counts['unanalyzed']} remaining")

        path_counts = {
            "unanalyzed": sum(1 for p in self.dataflow_paths if not p.get("vuln_analyzed")),
            "done": sum(1 for p in self.dataflow_paths if p.get("vuln_analyzed")),
        }
        parts.append(f"Dataflow paths: {len(self.dataflow_paths)} total, {path_counts['done']} analyzed")

        vuln_counts = {
            "unverified": sum(1 for v in self.candidate_vulnerabilities if not v.get("verified")),
            "verified": sum(1 for v in self.candidate_vulnerabilities if v.get("verified")),
        }
        parts.append(f"Candidate vulnerabilities: {len(self.candidate_vulnerabilities)} total, "
                     f"{vuln_counts['verified']} verified, {vuln_counts['unverified']} unverified")

        if self.dedup_stats.get("total_raw", 0) > 0:
            dedup_pct = (
                1 - self.dedup_stats["after_dedup"] / self.dedup_stats["total_raw"]
            ) * 100
            parts.append(
                f"Dedup: {self.dedup_stats['total_raw']} raw → "
                f"{self.dedup_stats['after_dedup']} unique "
                f"({dedup_pct:.0f}% compression)"
            )

        if self.verified_findings:
            by_severity = {}
            for f in self.verified_findings:
                sev = f.get("severity", "unknown")
                by_severity[sev] = by_severity.get(sev, 0) + 1
            parts.append(f"Findings: {dict(by_severity)}")

        self.brain_summary = "\n".join(parts)

    # ------------------------------------------------------------------
    # Card classification
    # ------------------------------------------------------------------

    def load_analysis_cards(self, cards: list) -> None:
        """Classify Director cards into hot/warm/cold tiers.

        Called by Brain after Director Phase 0 completes.
        ``cards`` must be ``EntryAnalysisCard`` objects (from director/aggregator.py).
        """
        self.analysis_cards = cards
        from agies.engine.v2.router import classify_cards, classify_card

        scores = [c.final_score for c in cards]
        p80, p40 = classify_cards(scores)

        self.hot_cards = []
        self.warm_cards = []
        self.cold_cards = []

        for card in cards:
            cls = classify_card(card.final_score, p80, p40)
            if cls == "hot":
                self.hot_cards.append(card)
            elif cls == "warm":
                self.warm_cards.append(card)
            else:
                self.cold_cards.append(card)
                self.silent_signals.append({
                    "entry": card.entry,
                    "final_score": card.final_score,
                    "signals": [s.tag for s in card.aggregated_signals],
                })

    def to_dict(self) -> dict:
        return {
            "project_path": self.project_path,
            "language": self.language,
            "framework": self.framework,
            "file_count": self.file_count,
            "project_summary": self.project_summary[:200] if self.project_summary else "",
            "modules": len(self.modules),
            "entry_points": len(self.entry_points),
            "dataflow_paths": len(self.dataflow_paths),
            "candidate_vulnerabilities": len(self.candidate_vulnerabilities),
            "verified_findings": len(self.verified_findings),
            "completed_agents": self.completed_agents,
            "brain_summary": self.brain_summary,
        }

    def save_checkpoint(self, path: str) -> None:
        """Save state to JSON for resume support."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_checkpoint(cls, path: str) -> ProjectState:
        with open(path) as f:
            data = json.load(f)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def _truncate_for_summary(output: dict, max_len: int = 300) -> str:
    """Build a short text summary of an agent output dict."""
    as_str = json.dumps(output, ensure_ascii=False, default=str)
    if len(as_str) > max_len:
        return as_str[:max_len] + "..."
    return as_str
