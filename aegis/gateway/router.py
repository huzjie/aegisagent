"""Upstream router for the LLM gateway.

Routes requests to the appropriate provider based on model name, tenant,
or other routing criteria.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Pattern

from aegis.core.logging import get_logger
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

__all__ = ["UpstreamRouter", "UpstreamConfig"]

_log = get_logger(__name__)


class UpstreamConfig:
    """Configuration for a single upstream provider."""

    def __init__(
        self,
        name: str,
        base_url: str,
        api_key: str = "",
        model_patterns: Optional[List[str]] = None,
        adapter: Optional[ProviderAdapter] = None,
        timeout_s: float = 30.0,
        max_retries: int = 3,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model_patterns = model_patterns or []
        self.adapter = adapter or self._create_adapter(name)
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.metadata = metadata or {}
        self._compiled_patterns: List[Pattern[str]] = [
            re.compile(p, re.IGNORECASE) for p in self.model_patterns
        ]

    def _create_adapter(self, name: str) -> ProviderAdapter:
        """Create an adapter based on provider name."""
        adapters = {
            "openai": OpenAIAdapter,
            "anthropic": AnthropicAdapter,
            "gemini": GeminiAdapter,
            "bedrock": BedrockAdapter,
            "qwen": QwenAdapter,
            "deepseek": DeepSeekAdapter,
            "kimi": KimiAdapter,
            "ollama": OllamaAdapter,
        }
        adapter_cls = adapters.get(name.lower(), GenericAdapter)
        return adapter_cls()

    def matches_model(self, model: str) -> bool:
        """Check if this upstream handles the given model."""
        if not self._compiled_patterns:
            return True  # No patterns = accepts all
        return any(p.search(model) for p in self._compiled_patterns)


class UpstreamRouter:
    """Route requests to upstream providers based on model and routing rules.

    The router maintains a list of configured upstreams and selects the
    appropriate one for each request based on model name matching.
    """

    def __init__(self, upstreams: Optional[List[UpstreamConfig]] = None) -> None:
        self._upstreams: List[UpstreamConfig] = list(upstreams or [])
        self._default: Optional[UpstreamConfig] = None
        self._request_count: int = 0

    def add_upstream(self, config: UpstreamConfig) -> None:
        """Add an upstream configuration."""
        self._upstreams.append(config)
        if self._default is None:
            self._default = config

    def set_default(self, name: str) -> bool:
        """Set the default upstream by name.

        Returns:
            ``True`` if the upstream was found and set as default.
        """
        for upstream in self._upstreams:
            if upstream.name == name:
                self._default = upstream
                return True
        return False

    def route(self, model: str = "", **kwargs: Any) -> Optional[UpstreamConfig]:
        """Select an upstream for the given model.

        Args:
            model: the model name to route.
            **kwargs: additional routing criteria.

        Returns:
            The selected :class:`UpstreamConfig`, or ``None`` if no match.
        """
        self._request_count += 1

        # Try exact model match first
        for upstream in self._upstreams:
            if upstream.model_patterns and upstream.matches_model(model):
                return upstream

        # Fall back to default
        if self._default is not None:
            return self._default

        _log.warning("no upstream found for model", fields={"model": model})
        return None

    def get_adapter(self, model: str = "") -> Optional[ProviderAdapter]:
        """Get the adapter for the given model.

        Convenience method that combines :meth:`route` with adapter extraction.
        """
        upstream = self.route(model)
        return upstream.adapter if upstream else None

    @property
    def upstreams(self) -> List[UpstreamConfig]:
        """Return a list of configured upstreams."""
        return list(self._upstreams)

    @property
    def request_count(self) -> int:
        """Number of routing decisions made."""
        return self._request_count

    def __len__(self) -> int:
        return len(self._upstreams)
