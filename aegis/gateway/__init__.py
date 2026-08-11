"""LLM provider gateway with provenance attestation.

The gateway intercepts LLM API traffic, records model completions, issues
cryptographic attestations, and injects them back into responses so downstream
tool calls can be bound to real model outputs.  It also blocks CoreBreak
attacks by detecting injected ``tool_use`` blocks in request messages.
"""

from __future__ import annotations

from .interceptor import GatewayInterceptor
from .router import UpstreamRouter
from .server import run_gateway
from .adapters import (
    ProviderAdapter,
    OpenAIAdapter,
    AnthropicAdapter,
    GeminiAdapter,
    BedrockAdapter,
    QwenAdapter,
    DeepSeekAdapter,
    KimiAdapter,
    OllamaAdapter,
    GenericAdapter,
)
from .middleware import (
    Middleware,
    RateLimitMiddleware,
    RedactionMiddleware,
    LoggingMiddleware,
    BudgetMiddleware,
)

__all__ = [
    "GatewayInterceptor",
    "UpstreamRouter",
    "run_gateway",
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
    "Middleware",
    "RateLimitMiddleware",
    "RedactionMiddleware",
    "LoggingMiddleware",
    "BudgetMiddleware",
]
