"""Third-party framework integrations for AegisAgent.

Provides adapters for popular agent frameworks including LangChain,
LlamaIndex, AutoGen, CrewAI, OpenAI Agents SDK, Anthropic SDK, MCP,
Smolagents, and Agno.
"""

from __future__ import annotations

from .langchain import AegisCallbackHandler
from .llamaindex import AegisLlamaIndexHandler
from .autogen import AegisAutoGenMiddleware
from .crewai import AegisCrewAITool
from .openai_agents import AegisOpenAIAgent
from .anthropic_sdk import AegisAnthropicClient
from .mcp_sdk import AegisMCPServer
from .smolagents import AegisSmolAgent
from .agno import AegisAgnoAgent
from .common import IntegrationBase

__all__ = [
    "AegisCallbackHandler",
    "AegisLlamaIndexHandler",
    "AegisAutoGenMiddleware",
    "AegisCrewAITool",
    "AegisOpenAIAgent",
    "AegisAnthropicClient",
    "AegisMCPServer",
    "AegisSmolAgent",
    "AegisAgnoAgent",
    "IntegrationBase",
]
