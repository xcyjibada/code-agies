"""Pydantic models for the YAML prompt file schema.

Maps directly to Xint's ``PromptMapping`` / ``AgentPrompts`` / ``ToolPrompt``.

Two layers:
1. **Raw models** (``PromptMapping``, ``AgentPrompts``, ``ToolPrompt``) — deserialized
   from YAML.
2. **Template models** (``TemplateMapping``, ``TemplateAgent``) — after ``.compile()``,
   all renderable fields become ``jinja2.Template`` objects.
"""

from __future__ import annotations

from typing import Any

import jinja2
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Raw models — deserialised 1:1 from YAML
# ---------------------------------------------------------------------------


class ToolPrompt(BaseModel):
    """Description of one tool for prompt construction."""

    summary: str = ""
    params: dict[str, str] = Field(default_factory=dict)
    returns: str | None = None


class AgentPrompts(BaseModel):
    """Raw Agent prompt definition from YAML."""

    system: str = ""
    user: str = ""
    tools: dict[str, ToolPrompt] = Field(default_factory=dict)
    custom: dict[str, str] = Field(default_factory=dict)

    def compile(self) -> TemplateAgent:
        """Compile all Jinja2 fields into ``TemplateAgent``."""
        return TemplateAgent(
            system=jinja2.Template(self.system),
            user=jinja2.Template(self.user),
            tools=self.tools,
            custom={k: jinja2.Template(v) for k, v in self.custom.items()},
        )


class PromptMapping(BaseModel):
    """Represents one YAML prompt file."""

    agents: dict[str, AgentPrompts] = Field(default_factory=dict)
    tools: dict[str, ToolPrompt] = Field(default_factory=dict)
    custom: dict[str, str] = Field(default_factory=dict)

    def compile(self) -> TemplateMapping:
        """Compile all agents + custom into Jinja2 templates."""
        return TemplateMapping(
            agents={name: a.compile() for name, a in self.agents.items()},
            tools=self.tools,
            custom={k: jinja2.Template(v) for k, v in self.custom.items()},
        )


# ---------------------------------------------------------------------------
# Compiled models — after compile(), Jinja2 templates ready to render
# ---------------------------------------------------------------------------


class TemplateAgent(BaseModel):
    """Compiled Agent prompt (fields are ``jinja2.Template``)."""

    model_config = {"arbitrary_types_allowed": True}

    system: jinja2.Template
    user: jinja2.Template
    tools: dict[str, ToolPrompt]
    custom: dict[str, jinja2.Template]


class TemplateMapping(BaseModel):
    """Compiled mapping (agents + tools + custom, all Jinja2-ready)."""

    model_config = {"arbitrary_types_allowed": True}

    agents: dict[str, TemplateAgent]
    tools: dict[str, ToolPrompt]
    custom: dict[str, jinja2.Template]

    def bind(self, *agent_names: str, kwargs: dict[str, Any]) -> BoundAgent:
        """Bind this mapping to an Agent instance.

        Tries each *agent_names* in order, using the first match.
        The *kwargs* dict must contain ``agent`` (the agent instance).
        """
        agent: TemplateAgent | None = None
        for name in agent_names:
            if (a := self.agents.get(name)) is not None:
                agent = a
                break
        if agent is None:
            raise RuntimeError(
                f"Agent prompt not found: tried {agent_names}, "
                f"available: {list(self.agents)}"
            )

        custom = BoundCustom(custom=agent.custom, kwargs=kwargs)
        kwargs["custom"] = custom
        return BoundAgent(
            name=agent_names[0],
            kwargs=kwargs,
            agent=agent,
            custom=custom,
        )


# ---------------------------------------------------------------------------
# Bound models — attached to a live agent instance, rendering ready
# ---------------------------------------------------------------------------


class BoundAgent(BaseModel):
    """A prompt that has been bound to an Agent instance.

    Access ``.system`` and ``.user`` to get rendered strings.
    """

    model_config = {"arbitrary_types_allowed": True}

    name: str
    kwargs: dict[str, Any]
    agent: TemplateAgent
    custom: BoundCustom

    @property
    def system(self) -> str:
        try:
            return self.agent.system.render(self.kwargs)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to render system prompt for agent '{self.name}': {exc}"
            ) from exc

    @property
    def user(self) -> str:
        try:
            return self.agent.user.render(self.kwargs)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to render user prompt for agent '{self.name}': {exc}"
            ) from exc

    @property
    def tools_prompts(self) -> dict[str, ToolPrompt]:
        """Unrendered tool descriptions (no Jinja2 in tool fields)."""
        return self.agent.tools


class BoundCustom(BaseModel):
    """Enables ``{{ custom.xxx }}`` references in Jinja2 templates."""

    model_config = {"arbitrary_types_allowed": True}

    custom: dict[str, jinja2.Template]
    kwargs: dict[str, Any]

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            template = self.custom[name]
        except KeyError:
            raise AttributeError(name) from None
        try:
            return template.render(custom=self, **self.kwargs)
        except Exception as exc:
            raise RuntimeError(
                f"Template error in custom.{name}: {exc}"
            ) from exc
