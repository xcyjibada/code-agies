"""Extensible audit rule definitions."""

from abc import ABC, abstractmethod


class AuditRule(ABC):
    """Base class for an audit rule."""

    name: str
    description: str
    language: str | None = None  # None = language-agnostic

    @abstractmethod
    def get_prompt_instructions(self) -> str:
        """Return the prompt instructions for this rule."""
        ...


class RuleSet:
    """A collection of audit rules for a specific language/category."""

    def __init__(self, name: str, rules: list[AuditRule] | None = None):
        self.name = name
        self._rules = rules or []

    def add(self, rule: AuditRule):
        self._rules.append(rule)

    def get_instructions(self) -> str:
        parts = [f"## Audit Rules: {self.name}", ""]
        for r in self._rules:
            parts.append(f"### {r.name}")
            parts.append(r.description)
            parts.append(r.get_prompt_instructions())
            parts.append("")
        return "\n".join(parts)

    def __iter__(self):
        return iter(self._rules)


def get_enabled_rulesets(languages: list[str]) -> list[RuleSet]:
    """Return rule sets applicable to the detected languages."""
    from agies.rules.python_rules import python_ruleset
    from agies.rules.js_rules import js_ruleset
    from agies.rules.generic_rules import generic_ruleset

    rulesets = [generic_ruleset()]
    lang_map = {
        "Python": python_ruleset,
        "JavaScript": js_ruleset,
        "TypeScript": js_ruleset,
        "JavaScript React": js_ruleset,
        "TypeScript React": js_ruleset,
    }

    for lang in languages:
        builder = lang_map.get(lang)
        if builder:
            rulesets.append(builder())

    return rulesets
