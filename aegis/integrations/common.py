"""Common integration base class.

Provides shared functionality for all framework integrations.
"""

from __future__ import annotations

from typing import Any, Optional

from aegis.sdk.client import AegisAgent

__all__ = ["IntegrationBase"]


class IntegrationBase:
    """Base class for framework integrations.

    Args:
        agent: AegisAgent instance to use for governance.
    """

    def __init__(self, agent: Optional[AegisAgent] = None) -> None:
        self.agent = agent or AegisAgent()

    def get_agent(self) -> AegisAgent:
        """Get the underlying AegisAgent instance."""
        return self.agent
