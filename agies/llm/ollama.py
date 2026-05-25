"""Ollama provider for local models via OpenAI-compatible endpoint."""

from openai import OpenAI

from .base import LLMProvider, LLMResponse, ToolCall


class OllamaProvider(LLMProvider):
    """Provider for locally-hosted models via Ollama."""

    @property
    def default_model(self) -> str:
        return "deepseek-coder"

    @property
    def env_key_name(self) -> str:
        return "OLLAMA_API_KEY"

    def _init_client(self, **kwargs):
        base_url = kwargs.get("base_url", "http://localhost:11434/v1")
        self._client = OpenAI(
            api_key=self.api_key or "ollama",
            base_url=base_url,
        )

    def _chat_completion_impl(
        self, messages, tools=None, **kwargs
    ) -> LLMResponse:
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
