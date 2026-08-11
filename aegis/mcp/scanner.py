"""Static risk scanning of MCP server tool surfaces.

Before any tool is forwarded, the proxy runs it through this scanner.  The
scanner is *static*: it inspects only the tool's advertised name, description,
annotations and parameter schema — never executes anything.  Its job is to
assign a defensible risk band and surface the specific reasons, so the policy
engine can decide whether a human must approve, whether sandboxing is forced,
and whether the tool is simply off-limits.

This is the first line of defence against the "trusted MCP server, dangerous
tool" pattern: a server can be fully pinned and authenticated yet still expose
a ``shell/exec`` tool that an agent should only ever call inside a sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional, Sequence

from ..core.logging import get_logger
from ..core.types import RiskLevel
from .protocol import ToolDefinition

__all__ = [
    "ToolRisk",
    "ToolFinding",
    "ToolScanReport",
    "ServerScanReport",
    "ScannerConfig",
    "ToolScanner",
]

_LOG = get_logger("aegis.mcp.scanner")


class ToolRisk(str, Enum):
    """Per-tool risk band, derived from hints found in the tool surface."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def min_risk(self) -> RiskLevel:
        """Map to the shared :class:`RiskLevel` scale."""
        return {
            ToolRisk.SAFE: RiskLevel.NONE,
            ToolRisk.LOW: RiskLevel.LOW,
            ToolRisk.MEDIUM: RiskLevel.MEDIUM,
            ToolRisk.HIGH: RiskLevel.HIGH,
            ToolRisk.CRITICAL: RiskLevel.CRITICAL,
        }[self]


@dataclass
class ToolFinding:
    """One concrete reason a tool was scored a given way."""

    code: str
    message: str
    severity: ToolRisk = ToolRisk.LOW

    def to_dict(self) -> dict:
        """Serialise the finding."""
        return {"code": self.code, "message": self.message, "severity": self.severity.value}


@dataclass
class ToolScanReport:
    """Scan result for a single tool."""

    tool: str
    risk: ToolRisk = ToolRisk.LOW
    findings: List[ToolFinding] = field(default_factory=list)
    force_sandbox: bool = False
    require_approval: bool = False
    block: bool = False

    @property
    def reasons(self) -> List[str]:
        """Return the human-readable finding messages."""
        return [f.message for f in self.findings]

    def to_dict(self) -> dict:
        """Serialise the report."""
        return {
            "tool": self.tool,
            "risk": self.risk.value,
            "force_sandbox": self.force_sandbox,
            "require_approval": self.require_approval,
            "block": self.block,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ServerScanReport:
    """Aggregate scan result for one server."""

    server_id: str
    tools: List[ToolScanReport] = field(default_factory=list)
    max_risk: ToolRisk = ToolRisk.SAFE
    blocked_tools: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialise the server report."""
        return {
            "server_id": self.server_id,
            "max_risk": self.max_risk.value,
            "blocked_tools": list(self.blocked_tools),
            "tools": [t.to_dict() for t in self.tools],
        }


@dataclass
class ScannerConfig:
    """Tunables for the tool scanner."""

    block_critical: bool = True
    force_sandbox_on_high: bool = True
    require_approval_on_high: bool = True
    treat_destructive_as_high: bool = True

    # Keyword groups used to infer intent from name/description/schema.
    shell_keywords: Sequence[str] = ("exec", "shell", "command", "run", "subprocess", "bash", "sh", "powershell", "cmd")
    fs_write_keywords: Sequence[str] = ("write", "upload", "delete", "remove", "rm ", "mkdir", "create file", "save", "move", "rename")
    network_keywords: Sequence[str] = ("fetch", "http", "https", "request", "get url", "download", "curl", "wget", "post")
    credential_keywords: Sequence[str] = ("api_key", "token", "secret", "password", "credential", "private_key", "auth")
    destructive_keywords: Sequence[str] = ("delete", "drop", "truncate", "purge", "reset", "wipe", "destroy", "rm ")

    def validate(self) -> None:
        """No-op validation hook."""
        return


class ToolScanner:
    """Static risk analysis of MCP tool definitions."""

    def __init__(self, config: Optional[ScannerConfig] = None) -> None:
        """Create the scanner.

        Args:
            config: Scanner tunables; defaults to safe-by-default.
        """
        self._config = config or ScannerConfig()
        self._config.validate()

    @property
    def config(self) -> ScannerConfig:
        """Return the active config."""
        return self._config

    def scan_tool(self, tool: ToolDefinition) -> ToolScanReport:
        """Assign a risk band and advisory flags to one tool.

        Args:
            tool: The tool definition to analyse.

        Returns:
            A populated :class:`ToolScanReport`.
        """
        report = ToolScanReport(tool=tool.qualified_name)
        text = self._surface_text(tool).lower()

        findings: List[ToolFinding] = []

        if self._any(text, self._config.shell_keywords):
            findings.append(ToolFinding("shell_exec", "tool can execute commands/shell", ToolRisk.CRITICAL))
        if self._any(text, self._config.fs_write_keywords):
            findings.append(ToolFinding("fs_write", "tool can write/delete filesystem objects", ToolRisk.HIGH))
        if self._any(text, self._config.network_keywords):
            findings.append(ToolFinding("network_egress", "tool can make outbound network requests", ToolRisk.MEDIUM))
        if self._any(text, self._config.destructive_keywords) or tool.annotations.destructive_hint:
            band = ToolRisk.HIGH if self._config.treat_destructive_as_high else ToolRisk.MEDIUM
            findings.append(ToolFinding("destructive", "tool is destructive (data loss possible)", band))
        if self._leaks_credential(tool):
            findings.append(ToolFinding("credential_param", "tool accepts a raw credential parameter", ToolRisk.HIGH))

        # Annotations can downgrade: an explicit read-only, non-destructive
        # tool with no other hints is treated as low risk.
        if not findings and tool.annotations.read_only_hint and not tool.annotations.destructive_hint:
            report.risk = ToolRisk.LOW
        else:
            report.risk = self._worse(findings)

        report.findings = findings
        report.force_sandbox = (
            self._config.force_sandbox_on_high
            and report.risk in (ToolRisk.HIGH, ToolRisk.CRITICAL)
        ) or any(f.code == "shell_exec" for f in findings)
        report.require_approval = (
            self._config.require_approval_on_high
            and report.risk in (ToolRisk.HIGH, ToolRisk.CRITICAL)
        )
        report.block = self._config.block_critical and report.risk is ToolRisk.CRITICAL
        return report

    def scan_server(self, server_id: str, tools: Sequence[ToolDefinition]) -> ServerScanReport:
        """Scan every tool of a server and aggregate.

        Args:
            server_id: Identifier of the server (for reporting).
            tools: The server's tool definitions.

        Returns:
            A :class:`ServerScanReport` with per-tool and aggregate results.
        """
        reports = [self.scan_tool(t) for t in tools]
        order = [ToolRisk.SAFE, ToolRisk.LOW, ToolRisk.MEDIUM, ToolRisk.HIGH, ToolRisk.CRITICAL]
        max_risk = ToolRisk.SAFE
        for rep in reports:
            if order.index(rep.risk) > order.index(max_risk):
                max_risk = rep.risk
        blocked = [rep.tool for rep in reports if rep.block]
        return ServerScanReport(
            server_id=server_id,
            tools=reports,
            max_risk=max_risk,
            blocked_tools=blocked,
        )

    # -- analysis helpers ---------------------------------------------------

    def _surface_text(self, tool: ToolDefinition) -> str:
        """Concatenate the name/description/schema into one searchable string."""
        parts = [tool.name, tool.description]
        for param in tool.parameters:
            parts.append(param.name)
            parts.append(param.description)
            if param.schema:
                parts.append(str(param.schema))
        return " ".join(parts)

    def _any(self, text: str, keywords: Sequence[str]) -> bool:
        """Return whether any keyword appears (substring) in ``text``."""
        return any(kw in text for kw in keywords)

    def _leaks_credential(self, tool: ToolDefinition) -> bool:
        """Detect a raw-credential parameter by name."""
        lowered = [p.name.lower() for p in tool.parameters]
        return any(
            any(c in name for c in self._config.credential_keywords)
            for name in lowered
        )

    @staticmethod
    def _worse(findings: List[ToolFinding]) -> ToolRisk:
        """Return the most severe risk among ``findings``."""
        order = [ToolRisk.SAFE, ToolRisk.LOW, ToolRisk.MEDIUM, ToolRisk.HIGH, ToolRisk.CRITICAL]
        worst = ToolRisk.LOW
        for f in findings:
            if order.index(f.severity) > order.index(worst):
                worst = f.severity
        return worst
