"""Provider adapters for the LLM gateway.

Each adapter knows how to parse the response format of a specific LLM provider
and extract model completions, tool calls, and usage statistics in a
uniform manner.
"""

from __future__ import annotations

from .base import ProviderAdapter
from .openai import OpenAIAdapter
from .anthropic import AnthropicAdapter
from .gemini import GeminiAdapter
from .bedrock import BedrockAdapter
from .qwen import QwenAdapter
from .deepseek import DeepSeekAdapter
from .kimi import KimiAdapter
from .ollama import OllamaAdapter
from .generic import GenericAdapter

__all__ = [
    "ProviderAdapter",
    "OpenAIAdapter",
    "AnthropicAdapter",
    "GeminiAdapter",
    "BedrockAdapter",
    "QwenAdapter",
    "DeepSeekAdapter",
    "KimiAdapter",
    "OllamaAdapter",
    "GenericAdapter",
]
