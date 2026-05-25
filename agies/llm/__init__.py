"""LLM provider abstraction layer.

Usage:
    from agies.llm import get_model

    model = get_model("deepseek-chat")
    response = model.chat_completion(
        messages=[{"role": "user", "content": "Hello"}],
    )
"""

from .base import LLMProvider, LLMResponse, ToolCall
from .registry import ModelRegistry, get_model, register_provider
from .deepseek import DeepSeekProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .ollama import OllamaProvider

__all__ = [
    "LLMProvider",
    "LLMResponse",
    "ToolCall",
    "ModelRegistry",
    "get_model",
    "register_provider",
    "DeepSeekProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
]
