"""Anthropic/Claude provider.

Handles message format conversion between OpenAI-compatible format
and Anthropic's native message format (content blocks, tool_use/tool_result).
"""

import json

from anthropic import Anthropic

from .base import LLMProvider, LLMResponse, ToolCall


class AnthropicProvider(LLMProvider):
    """Provider for Anthropic Claude models."""

    # Stores raw content blocks from last API response to preserve
    # extended thinking blocks across conversation turns.
    _last_raw_assistant_blocks: list[dict] | None = None

    @property
    def default_model(self) -> str:
        return "claude-sonnet-4-20250514"

    @property
    def env_key_name(self) -> str:
        return "ANTHROPIC_API_KEY"

    def _init_client(self, **kwargs):
        self._client = Anthropic(
            api_key=self.api_key,
            timeout=120.0,
        )
        self._last_raw_assistant_blocks = None

    def _convert_messages(self, messages: list[dict]):
        """Convert OpenAI-format messages to Anthropic format.

        Returns (system_prompt, anthropic_messages).
        """
        system = None
        anthropic_messages = []

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            if role == "system":
                # Pass through list format (cache_control annotations);
                # fall back to plain string.
                system = content if isinstance(content, (str, list)) else str(content)

            elif role == "user":
                # tool_result content blocks or plain text
                if isinstance(content, str):
                    entry = {"role": "user", "content": content}
                else:
                    entry = {"role": "user", "content": content}
                anthropic_messages.append(entry)

            elif role == "assistant":
                # Preserve raw blocks from cache (includes thinking blocks).
                # Strip tool_use from raw_blocks — the message's own tool_calls
                # are the authoritative source for tool_use IDs, ensuring they
                # match the tool_result blocks that follow after message
                # stripping (e.g. iteration limit handling).
                raw = msg.get("_raw_blocks")
                if raw is not None:
                    blocks = [
                        b for b in raw if b.get("type") != "tool_use"
                    ]
                else:
                    blocks = []
                    if content:
                        blocks.append({"type": "text", "text": content})

                for tc in msg.get("tool_calls", []):
                    try:
                        tc_input = json.loads(tc["function"]["arguments"])
                    except (json.JSONDecodeError, KeyError):
                        tc_input = {}
                    blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["function"]["name"],
                        "input": tc_input,
                    })

                anthropic_messages.append({"role": "assistant", "content": blocks})

            elif role == "tool":
                result_content = content if isinstance(content, str) else json.dumps(content)
                # Batch consecutive tool results into a single user message,
                # since Anthropic requires all tool results from one assistant
                # turn to be in one message with multiple content blocks.
                if anthropic_messages and anthropic_messages[-1]["role"] == "user":
                    # Check if the last user message already has tool_result blocks
                    last = anthropic_messages[-1]
                    if isinstance(last.get("content"), list) and any(
                        b.get("type") == "tool_result" for b in last["content"]
                    ):
                        last["content"].append({
                            "type": "tool_result",
                            "tool_use_id": msg["tool_call_id"],
                            "content": result_content,
                        })
                    else:
                        anthropic_messages.append({
                            "role": "user",
                            "content": [{
                                "type": "tool_result",
                                "tool_use_id": msg["tool_call_id"],
                                "content": result_content,
                            }],
                        })
                else:
                    anthropic_messages.append({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": msg["tool_call_id"],
                            "content": result_content,
                        }],
                    })

        return system, anthropic_messages

    @staticmethod
    def _convert_tools(openai_tools):
        """Convert OpenAI tool format to Anthropic tool format."""
        if not openai_tools:
            return None

        converted = []
        for t in openai_tools:
            func = t.get("function", {})
            converted.append({
                "name": func.get("name", ""),
                "description": func.get("description", ""),
                "input_schema": func.get("parameters", {"type": "object", "properties": {}}),
            })
        return converted

    def _convert_response(self, response) -> LLMResponse:
        """Convert an Anthropic Message to LLMResponse."""
        content_parts = []
        tool_calls = []
        raw_blocks = []

        for block in response.content:
            # Serialise block to a dict for round-trip preservation
            if block.type == "text" and block.text:
                content_parts.append(block.text)
                raw_blocks.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=json.dumps(block.input),
                ))
                raw_blocks.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
            elif block.type == "thinking":
                raw_blocks.append({"type": "thinking", "thinking": block.thinking})
            elif block.type == "redacted_thinking":
                raw_blocks.append({"type": "redacted_thinking", "data": block.data})

        content = "".join(content_parts) if content_parts else None

        # Store raw blocks so _convert_messages can re-inject them
        self._last_raw_assistant_blocks = raw_blocks if raw_blocks else None

        return LLMResponse(
            content=content,
            tool_calls=tool_calls if tool_calls else None,
        )

    def _chat_completion_impl(
        self, messages, tools=None, **kwargs
    ) -> LLMResponse:
        # Apply prompt cache annotations (system + last user/tool messages)
        # to reduce costs on repeated system prompts and tool results.
        from agies.engine.v2.context import apply_cache_annotations

        apply_cache_annotations(messages)

        # Inject raw blocks from the previous response into the last
        # assistant message so that extended-thinking blocks are preserved
        # across conversation turns.
        if self._last_raw_assistant_blocks is not None:
            for msg in reversed(messages):
                if msg.get("role") == "assistant":
                    msg["_raw_blocks"] = self._last_raw_assistant_blocks
                    break

        system, anthropic_messages = self._convert_messages(messages)
        anthropic_tools = self._convert_tools(tools)

        max_tokens = kwargs.pop("max_tokens", 8192)

        response = self._client.messages.create(
            model=self.model,
            system=system,
            messages=anthropic_messages,
            tools=anthropic_tools,
            max_tokens=max_tokens,
            **kwargs,
        )

        usage = None
        if hasattr(response, "usage") and response.usage:
            in_t = getattr(response.usage, "input_tokens", 0) or 0
            out_t = getattr(response.usage, "output_tokens", 0) or 0
            usage = {
                "prompt_tokens": in_t,
                "completion_tokens": out_t,
                "total_tokens": in_t + out_t,
            }

        result = self._convert_response(response)
        result.usage = usage
        return result
