"""DeepSeek provider via OpenAI-compatible API."""

import os

from openai import OpenAI, Timeout

from .base import LLMProvider, LLMResponse, ToolCall


class DeepSeekProvider(LLMProvider):
    """Provider for DeepSeek models via OpenAI-compatible endpoint."""

    @property
    def default_model(self) -> str:
        return "deepseek-chat"

    @property
    def env_key_name(self) -> str:
        return "DEEPSEEK_API_KEY"

    def _init_client(self, **kwargs):
        if not self.api_key:
            self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        base_url = "https://api.deepseek.com"
        if not self.api_key:
            self._client = None
        else:
            self._client = OpenAI(
                api_key=self.api_key,
                base_url=base_url,
                timeout=Timeout(120.0),
            )

    def _chat_completion_impl(
        self, messages, tools=None, **kwargs
    ) -> LLMResponse:
        if self._client is None:
            raise ValueError(
                f"{self.env_key_name} is not set. "
                "Set it via environment variable or pass api_key to get_model()."
            )
        response = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,
            **kwargs,
        )
        choice = response.choices[0]
        msg = choice.message

        tool_calls = None
        if msg.tool_calls:
            tool_calls = [
                ToolCall(id=tc.id, name=tc.function.name, arguments=tc.function.arguments)
                for tc in msg.tool_calls
            ]

        usage = None
        if hasattr(response, "usage") and response.usage:
            usage = {
                "prompt_tokens": response.usage.prompt_tokens or 0,
                "completion_tokens": response.usage.completion_tokens or 0,
                "total_tokens": response.usage.total_tokens or 0,
            }

        return LLMResponse(content=msg.content, tool_calls=tool_calls, usage=usage)
