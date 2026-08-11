"""Abstract base class for provider adapters.

A :class:`ProviderAdapter` translates between the gateway's internal
representation and the wire format of a specific LLM provider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from aegis.core.types import ModelCompletion

__all__ = ["ProviderAdapter"]


class ProviderAdapter(ABC):
    """Interface for LLM provider response parsers.

    Subclasses implement :meth:`parse_response` to extract model completions
    from the provider's response format.
    """

    name: str = "base"

    @abstractmethod
    def parse_response(
        self,
        response: Dict[str, Any],
        session_id: str = "",
        turn: int = 0,
        model: str = "",
    ) -> Tuple[Optional[ModelCompletion], Dict[str, Any]]:
        """Parse a provider response into a model completion.

        Args:
            response: the raw response dictionary from the provider.
            session_id: the session identifier.
            turn: the conversation turn number.
            model: the model name.

        Returns:
            A tuple ``(completion, metadata)`` where *completion* is the
            extracted :class:`ModelCompletion` (or ``None`` if the response
            does not contain a completion) and *metadata* is a dictionary of
            provider-specific information.
        """
        # pragma: no cover - interface

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract tool calls from a response.

        Default implementation returns an empty list; subclasses override.
        """
        return []

    def extract_usage(self, response: Dict[str, Any]) -> Dict[str, int]:
        """Extract token usage from a response.

        Default implementation returns an empty dict; subclasses override.
        """
        return {}

    def format_request(self, messages: List[Dict[str, Any]], **kwargs: Any) -> Dict[str, Any]:
        """Format outgoing messages into the provider's request format.

        Default implementation returns the messages as-is; subclasses override.
        """
        return {"messages": messages, **kwargs}
