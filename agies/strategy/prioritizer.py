"""File prioritizer — identify high-value audit targets.

Uses a hybrid approach:
- Heuristic scoring (safe default, zero LLM cost)
- AI-driven prioritization via LLM stratified sampling (when available)

Graceful degradation: AI failure → fallback to heuristic.
"""

import os
import fnmatch
from dataclasses import dataclass
from typing import Optional


@dataclass
class ScoredFile:
    path: str
    score: int
    reason: str


# Security-sensitive path patterns (heuristic)
HIGH_VALUE_PATTERNS = [
    # Authentication & authorization
    "*security*", "*auth*", "*login*", "*oauth*", "*jwt*", "*token*",
    "*permission*", "*rbac*", "*session*", "*certificate*",
    # Configuration & secrets
    "*application*.yml", "*application*.yaml", "*application*.properties",
    "*.env*", "*credential*", "*secret*", "*key*",
    # Controllers & entry points
    "*controller*", "*RestController*", "*endpoint*", "*route*",
    "*handler*", "*service*", "*api*",
    # Data access
    "*mapper*", "*repository*", "*dao*", "*sql*", "*query*",
    # Input handling
    "*input*", "*upload*", "*import*", "*parse*", "*deserialize*",
    "*validator*", "*filter*", "*interceptor*",
    # Build & dependency
    "pom.xml", "build.gradle", "package.json", "requirements.txt",
    # Dangerous patterns
    "*eval*", "*exec*", "*command*", "*shell*",
    # ORM / XML mapping
    "*.xml", "*.sql",
]

# Files to deprioritize
LOW_VALUE_PATTERNS = [
    "*.md", "*.txt", "*.png", "*.jpg", "*.svg", "*.ico",
    "*.css", "*.scss", "*.less",
    "node_modules/*", ".git/*", "__pycache__/*", ".venv/*",
    "*.test.*", "*.spec.*", "*_test.go", "*test_*",
    "LICENSE", "README*", "CHANGELOG*",
]


class FilePrioritizer:
    """Score files by audit priority — heuristic + optional AI."""

    def __init__(self, target_root: str, llm_model=None):
        self.target_root = os.path.abspath(target_root)
        self.llm_model = llm_model

    def prioritize(self, files: list[str]) -> list[ScoredFile]:
        """Score and sort files by audit priority.

        For projects under 50K files, uses AI-driven prioritization
        if an LLM model is available. Falls back to heuristic otherwise.
        """
        if self.llm_model and len(files) < 50000:
            return self._ai_prioritize(files)
        return self._heuristic_prioritize(files)

    def _heuristic_prioritize(self, files: list[str]) -> list[ScoredFile]:
        """Pure heuristic scoring — fast, deterministic, no LLM cost."""
        scored = []
        for path in files:
            score = 0
            reasons = []

            # Positive signals
            for pattern in HIGH_VALUE_PATTERNS:
                if fnmatch.fnmatch(path, pattern):
                    if score < 80:
                        score += 20
                    reasons.append(f"matches {pattern}")

            # Negative signals (deprioritize)
            for pattern in LOW_VALUE_PATTERNS:
                if fnmatch.fnmatch(path, pattern):
                    score = max(0, score - 30)
                    break

            # File depth bonus (deeper nesting may indicate more complex logic)
            rel_path = os.path.relpath(path, self.target_root)
            depth = rel_path.count(os.sep)
            if depth >= 3:
                score += 5

            # Bump if it's a source code file in a key language
            if path.endswith((".py", ".java", ".js", ".ts", ".go", ".rs", ".php", ".rb", ".kt")):
                score += 10

            if score > 0:
                scored.append(ScoredFile(
                    path=path,
                    score=min(score, 100),
                    reason="; ".join(reasons[:3]) if reasons else "heuristic match",
                ))

        scored.sort(key=lambda x: -x.score)
        return scored

    def _ai_prioritize(self, files: list[str]) -> list[ScoredFile]:
        """AI-driven prioritization with heuristic fallback."""
        # First, get heuristic scores as baseline
        heuristic = self._heuristic_prioritize(files)

        if not self.llm_model:
            return heuristic

        # Stratified sampling: pick up to 200 files covering all directories
        sampled = self._stratified_sample(files, sample_size=min(200, len(files)))

        # Build project metadata
        metadata = self._build_metadata(files)

        # Ask LLM to score
        prompt = (
            f"Analyze this codebase sample and identify the highest-value "
            f"files for a security audit.\n\n"
            f"## Project Structure\n"
            f"{metadata}\n\n"
            f"## Sampled Files ({len(sampled)} files)\n"
            + "\n".join(f"- {f}" for f in sampled[:50])  # Limit prompt size
            + "\n\n"
            f"Return a JSON array of {{'path': str, 'priority': int (1-10), "
            f"'reason': str}} for the top 10 files most likely to contain "
            f"security vulnerabilities."
        )

        try:
            from agies.llm import get_model
            model = get_model("claude-haiku-3-5") if not self.llm_model else self.llm_model
            response = model.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
            )

            import json
            content = response.content or "[]"
            # Try to extract JSON from code blocks
            import re
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', content)
            if json_match:
                content = json_match.group(1).strip()

            ai_results = json.loads(content)
            if isinstance(ai_results, dict) and "priority_files" in ai_results:
                ai_results = ai_results["priority_files"]

            # Merge AI results with heuristic: AI sets score, heuristic adds bonus
            ai_map = {r["path"]: r for r in ai_results if isinstance(r, dict)}
            merged = []
            seen = set()

            # AI-ranked files first
            for r in ai_results:
                path = r.get("path", "")
                if path in seen:
                    continue
                seen.add(path)
                merged.append(ScoredFile(
                    path=path,
                    score=r.get("priority", 5) * 10,
                    reason=r.get("reason", "AI-selected"),
                ))

            # Then heuristic-scored files not already in AI list
            for hf in heuristic:
                if hf.path not in seen:
                    merged.append(hf)

            return merged

        except Exception:
            # Graceful degradation
            pass

        return heuristic

    def _stratified_sample(self, files: list[str], sample_size: int) -> list[str]:
        """Stratified sampling: pick files proportionally from each directory."""
        from collections import defaultdict
        import random

        dirs = defaultdict(list)
        for f in files:
            d = os.path.dirname(f)
            dirs[d].append(f)

        # Proportional allocation
        total = len(files)
        sampled = []
        for directory, dir_files in sorted(dirs.items()):
            count = max(1, int(len(dir_files) / total * sample_size))
            sampled.extend(random.sample(dir_files, min(count, len(dir_files))))

        # Fill remaining slots
        remaining = sample_size - len(sampled)
        if remaining > 0:
            other = [f for f in files if f not in sampled]
            sampled.extend(random.sample(other, min(remaining, len(other))))

        return sampled[:sample_size]

    def _build_metadata(self, files: list[str]) -> str:
        """Build a concise project metadata summary."""
        from collections import Counter

        exts = Counter(os.path.splitext(f)[1] for f in files)
        dirs = Counter(os.path.dirname(f) for f in files)

        lines = [f"Total files: {len(files)}"]
        lines.append(f"File types: {dict(exts.most_common(10))}")
        lines.append(f"Top directories: {list(dirs.most_common(15))}")

        # Security-sensitive paths
        sensitive = [
            f for p in ["security", "auth", "login", "controller", "mapper", "config"]
            for f in files if p in f.lower()
        ]
        if sensitive:
            lines.append(f"Security-sensitive paths ({len(sensitive)}):")
            lines.extend(f"  {f}" for f in sensitive[:20])

        return "\n".join(lines)
