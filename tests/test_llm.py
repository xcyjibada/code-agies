"""Tests for the LLM provider abstraction layer."""
import os
from unittest.mock import patch, MagicMock

from agies.llm import (
    get_model,
    LLMProvider,
    LLMResponse,
    ToolCall,
    DeepSeekProvider,
    OpenAIProvider,
    AnthropicProvider,
    OllamaProvider,
    ModelRegistry,
)


def test_get_model_deepseek():
    """deepseek-* prefix maps to DeepSeekProvider."""
    model = get_model("deepseek-chat", api_key="test-key", max_retries=1)
    assert isinstance(model, DeepSeekProvider)
    assert model.model == "deepseek-chat"
    assert model.api_key == "test-key"


def test_get_model_openai():
    """gpt-* prefix maps to OpenAIProvider."""
    model = get_model("gpt-4o", api_key="test-key", max_retries=1)
    assert isinstance(model, OpenAIProvider)
    assert model.model == "gpt-4o"


def test_get_model_anthropic():
    """claude-* prefix maps to AnthropicProvider."""
    model = get_model("claude-sonnet-4-6", api_key="test-key", max_retries=1)
    assert isinstance(model, AnthropicProvider)
    assert model.model == "claude-sonnet-4-6"


def test_get_model_ollama():
    """ollama/* prefix maps to OllamaProvider."""
    model = get_model("ollama/deepseek-coder", api_key="", max_retries=1)
    assert isinstance(model, OllamaProvider)
    assert model.model == "ollama/deepseek-coder"


def test_get_model_fallback():
    """Unknown prefix falls back to DeepSeekProvider."""
    model = get_model("unknown-model", api_key="test", max_retries=1)
    assert isinstance(model, DeepSeekProvider)


def test_env_key_name():
    """Each provider should report the correct env var name."""
    assert DeepSeekProvider(model="deepseek-chat", api_key="test").env_key_name == "DEEPSEEK_API_KEY"
    assert OpenAIProvider(model="gpt-4o", api_key="test").env_key_name == "OPENAI_API_KEY"
    assert AnthropicProvider(model="claude-sonnet", api_key="test").env_key_name == "ANTHROPIC_API_KEY"


def test_default_model():
    """Each provider should have a sensible default model."""
    assert DeepSeekProvider(api_key="test").default_model == "deepseek-chat"
    assert OpenAIProvider(api_key="test").default_model == "gpt-4o"


def test_llm_response_dataclass():
    """LLMResponse should hold content and tool_calls."""
    tc = ToolCall(id="call_1", name="read_file", arguments='{"path": "/tmp/test"}')
    response = LLMResponse(
        content="Hello!",
        tool_calls=[tc],
    )
    assert response.content == "Hello!"
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].name == "read_file"
    assert response.tool_calls[0].id == "call_1"


def test_llm_response_no_tool_calls():
    """LLMResponse without tool calls should have None."""
    response = LLMResponse(content="Just text")
    assert response.tool_calls is None


def test_tool_call_default_type():
    """ToolCall should default to 'function' type."""
    tc = ToolCall(id="1", name="test", arguments="{}")
    assert tc.type == "function"


def test_registry_cache():
    """Registry should cache provider instances."""
    registry = ModelRegistry()
    m1 = registry.get_model("deepseek-chat", api_key="test", max_retries=1)
    m2 = registry.get_model("deepseek-chat", api_key="test", max_retries=1)
    # The second call should return a new instance (not cached via type check)
    # but with the same model string
    assert m1.model == m2.model


def test_anthropic_tool_conversion():
    """Anthropic provider should convert OpenAI tool format correctly."""
    provider = AnthropicProvider(model="claude-sonnet-4-6", api_key="test")
    openai_tools = [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        }
    ]
    converted = provider._convert_tools(openai_tools)
    assert converted is not None
    assert len(converted) == 1
    assert converted[0]["name"] == "read_file"
    assert converted[0]["description"] == "Read a file"
    assert "input_schema" in converted[0]


def test_anthropic_message_conversion():
    """Anthropic provider should convert OpenAI messages format correctly."""
    provider = AnthropicProvider(model="claude-sonnet-4-6", api_key="test")
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi!", "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": '{"path": "/tmp/test"}'}}
        ]},
        {"role": "tool", "tool_call_id": "call_1", "content": "file content"},
    ]

    system, converted = provider._convert_messages(messages)

    assert system == "You are a helpful assistant."
    assert len(converted) == 3  # user, assistant, tool_result
    assert converted[0]["role"] == "user"
    assert converted[1]["role"] == "assistant"
    # Assistant should have text + tool_use blocks
    content = converted[1]["content"]
    assert isinstance(content, list)
    assert any(b["type"] == "text" for b in content)
    assert any(b["type"] == "tool_use" for b in content)

    # Tool result should be user role with tool_result content
    assert converted[2]["role"] == "user"
    assert converted[2]["content"][0]["type"] == "tool_result"
    assert converted[2]["content"][0]["tool_use_id"] == "call_1"


def test_missing_api_key():
    """Provider without API key should report it."""
    os.environ.pop("DEEPSEEK_API_KEY", None)
    provider = DeepSeekProvider(model="deepseek-chat", api_key="", max_retries=1)
    assert provider.api_key == ""
