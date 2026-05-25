"""Model registry — resolve model names to provider instances."""

from .base import LLMProvider
from .deepseek import DeepSeekProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .ollama import OllamaProvider

# Ordered prefix → provider class mapping.
# First match wins, so be specific with prefixes.
PROVIDER_MAP: list[tuple[str, type[LLMProvider]]] = [
    ("deepseek", DeepSeekProvider),
    ("gpt", OpenAIProvider),
    ("claude", AnthropicProvider),
    ("ollama", OllamaProvider),
]


class ModelRegistry:
    """Resolve model name strings to LLMProvider instances."""

    def __init__(self):
        self._cache: dict[str, LLMProvider] = {}

    def get_model(self, model_name: str, **kwargs) -> LLMProvider:
        """Return a provider instance for the given model name.

        Uses prefix matching:
            "deepseek-chat"         → DeepSeekProvider
            "gpt-4o"               → OpenAIProvider
            "claude-sonnet-4-6"    → AnthropicProvider
            "ollama/deepseek-coder" → OllamaProvider

        Falls back to DeepSeekProvider if no prefix matches.
        """
        if model_name in self._cache:
            provider_cls = type(self._cache[model_name])
            return provider_cls(model=model_name, **kwargs)

        for prefix, provider_cls in PROVIDER_MAP:
            if model_name.startswith(prefix):
                instance = provider_cls(model=model_name, **kwargs)
                self._cache[model_name] = instance
                return instance

        # Default fallback
        instance = DeepSeekProvider(model=model_name, **kwargs)
        self._cache[model_name] = instance
        return instance

    def register_provider(self, prefix: str, provider_cls: type[LLMProvider]):
        """Register a custom provider with priority over built-ins."""
        PROVIDER_MAP.insert(0, (prefix, provider_cls))


# Global singleton
_registry = ModelRegistry()


def get_model(model_name: str, **kwargs) -> LLMProvider:
    """Convenience — resolve model name via the global registry."""
    return _registry.get_model(model_name, **kwargs)


def register_provider(prefix: str, provider_cls: type[LLMProvider]):
    """Convenience — register a custom provider globally."""
    _registry.register_provider(prefix, provider_cls)
