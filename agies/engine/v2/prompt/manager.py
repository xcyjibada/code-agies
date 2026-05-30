"""PromptManager — load YAML prompt files, compile Jinja2, manage model-level overrides.

Usage::

    from agies.engine.v2.prompt.manager import PromptManager

    pm = PromptManager.from_path("agies/engine/prompts")
    bound = pm.model("deepseek-chat").bind(
        "MappingAgent",
        kwargs={"agent": mapping_instance},
    )
    system_text = bound.system
    user_text = bound.user

Reference: Xint ``crs/common/prompts.py`` — same Jinja2 + YAML + per-model overlay
strategy.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Self

import yaml

from agies.engine.v2.prompt.models import (
    AgentPrompts,
    BoundAgent,
    BoundCustom,
    PromptMapping,
    TemplateMapping,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _merge_tools(
    base: dict[str, dict[str, Any]],  # ToolPrompt dicts
    override: dict[str, dict[str, Any]],
) -> None:
    """Merge tool descriptions from *override* into *base*.

    For each tool name: summary, params, returns all get overwritten
    (not deep merged) — same rule as Xint.
    """
    for name, tool in override.items():
        existing = base.get(name)
        if existing is None:
            base[name] = tool
            continue
        # Overwrite fields
        if tool.get("summary"):
            existing.summary = tool.summary
        if tool.get("params"):
            existing.params.update(tool.params)
        if tool.get("returns") is not None:
            existing.returns = tool.returns


# ---------------------------------------------------------------------------
# PromptManager
# ---------------------------------------------------------------------------


class PromptManager:
    """Loads YAML prompt files, compiles Jinja2, manages model-level overrides.

    Files in the prompts directory::

        prompts/
        ├── default.yaml              ← base prompts for all agents
        ├── deepseek-chat.yaml        ← per-model overrides (optional)
        └── claude-sonnet-4.yaml      ← per-model overrides (optional)

    The ``default.yaml`` provides the baseline.  Model-specific YAMLs
    deep-copy the default and then overlay only the sections they define.
    """

    def __init__(self, models: dict[str, PromptMapping]) -> None:
        default = models.pop("default")

        # Copy default tools into every default agent (GLOBAL-TOOL MERGE)
        for agent_prompt in default.agents.values():
            _merge_tools(agent_prompt.tools, default.tools)
            # Merge global custom into agent custom (agent wins on conflict)
            merged = {**default.custom, **agent_prompt.custom}
            agent_prompt.custom = merged

        # For every non-default model: deepcopy default, merge overrides
        compiled: dict[str, TemplateMapping] = {}
        for model_name, model_pm in models.items():
            fork = copy.deepcopy(default)
            # Merge agents (tools + custom at agent level)
            for agent_name, agent_override in model_pm.agents.items():
                base = fork.agents.get(agent_name)
                if base is None:
                    # New agent in override — merge global tools+custom
                    _merge_tools(agent_override.tools, fork.tools)
                    merged_custom = {**fork.custom, **agent_override.custom}
                    agent_override.custom = merged_custom
                    fork.agents[agent_name] = agent_override
                    continue
                _merge_tools(base.tools, fork.tools)  # ensure base has globals
                _merge_tools(base.tools, agent_override.tools)
                base.custom = {**fork.custom, **base.custom, **agent_override.custom}

            # Top-level tool+custom overrides
            _merge_tools(fork.tools, model_pm.tools)
            fork.custom.update(model_pm.custom)

            # Push merged custom back into agents
            for ap in fork.agents.values():
                ap.custom = {**fork.custom, **ap.custom}

            compiled[model_name] = fork.compile()

        self.default = default.compile()
        self.models: dict[str, TemplateMapping] = compiled

    @classmethod
    def from_path(cls, path: str | Path) -> Self:
        """Load all ``*.yaml`` files from *path* and build the manager."""
        models: dict[str, PromptMapping] = {}
        p = Path(path)
        if not p.is_dir():
            raise NotADirectoryError(f"Prompt directory not found: {path}")
        for yaml_file in sorted(p.iterdir()):
            if not yaml_file.name.endswith(".yaml"):
                continue
            name = yaml_file.name.removesuffix(".yaml")
            with open(yaml_file) as f:
                raw = yaml.safe_load(f)
            models[name] = PromptMapping.model_validate(raw)
        if "default" not in models:
            raise FileNotFoundError(
                f"No default.yaml found in {path}. "
                f"Available: {list(models)}"
            )
        return cls(models)

    @classmethod
    def from_dict(cls, name: str, data: dict) -> Self:
        """Build a single-model manager from a dict (useful for tests)."""
        pm = PromptMapping.model_validate(data)
        return cls({"default": pm})

    def model(self, name: str) -> TemplateMapping:
        """Return the compiled mapping for *name*, falling back to default."""
        return self.models.get(name, self.default)


# ---------------------------------------------------------------------------
# Global singleton (lazy init)
# ---------------------------------------------------------------------------

_PROMPT_MANAGER: PromptManager | None = None
_PROMPT_DIR: str = ""


def init_prompts(path: str = "") -> PromptManager:
    """Initialise (or re-initialise) the global PromptManager singleton."""
    global _PROMPT_MANAGER, _PROMPT_DIR
    target = path or _PROMPT_DIR
    if not target:
        # Default: look next to this file under prompts/
        target = str(Path(__file__).resolve().parent.parent / "prompts")
    _PROMPT_DIR = target
    _PROMPT_MANAGER = PromptManager.from_path(target)
    return _PROMPT_MANAGER


def get_prompts() -> PromptManager:
    """Return the global PromptManager singleton (init on first call)."""
    global _PROMPT_MANAGER
    if _PROMPT_MANAGER is None:
        _PROMPT_MANAGER = init_prompts()
    return _PROMPT_MANAGER
