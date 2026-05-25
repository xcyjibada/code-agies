"""Abstract base for all LLM providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class ToolCall:
    id: str
    name: str = ""
    arguments: str = ""  # JSON string
    type: str = "function"


@dataclass
class LLMResponse:
    content: Optional[str] = None
    tool_calls: Optional[list[ToolCall]] = None
    usage: Optional[dict] = None
    """Token usage from the API response.

    Contains ``prompt_tokens``, ``completion_tokens``, and ``total_tokens``
    keys, normalised across providers.  ``None`` when the provider does not
    expose usage information (e.g. some local models).
    """


class LLMProvider(ABC):
    """Abstract base for LLM providers.

    Implementations handle provider-specific API formats so consumers
    work with a uniform interface.
    """

    def __init__(self, model: str = "", api_key: str = "", **kwargs):
        self.model = model or self.default_model
        self.api_key = api_key or self._load_api_key()
        self.max_retries = kwargs.get("max_retries", 3)
        self._init_client(**kwargs)

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Default model name for this provider."""
        ...

    @property
    @abstractmethod
    def env_key_name(self) -> str:
        """Environment variable name for the API key."""
        ...

    @abstractmethod
    def _init_client(self, **kwargs):
        """Initialize the underlying API client."""

    @abstractmethod
    def _chat_completion_impl(
        self, messages: list[dict], tools: Optional[list[dict]] = None, **kwargs
    ) -> LLMResponse:
        """Actual API call — implemented by each provider."""

    def chat_completion(
        self, messages: list[dict], tools: Optional[list[dict]] = None, **kwargs
    ) -> LLMResponse:
        """Send a chat completion request with retry logic."""
        import time

        last_error = None
        for attempt in range(self.max_retries):
            try:
                return self._chat_completion_impl(messages, tools, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait = 2**attempt
                    logger.warning(
                        "API call failed (attempt %d/%d), retrying in %ds: %s",
                        attempt + 1, self.max_retries, wait, e,
                    )
                    time.sleep(wait)
        raise last_error

    def _load_api_key(self) -> str:
        import os
        return os.environ.get(self.env_key_name, "")
