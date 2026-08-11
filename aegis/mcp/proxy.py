"""The MCP security proxy: the enforcement point between agent and servers.

Every MCP interaction in AegisAgent flows through :class:`McpProxy`.  When a
server is attached the proxy runs a full admission sequence, and when a tool is
called it runs a full enforcement sequence.  Both are fail-closed.

Admission (``attach``)
    1. build the transport, connect, run the MCP handshake,
    2. compute an identity fingerprint and check it against
       :class:`~aegis.mcp.pinning.ServerPinner`,
    3. run :class:`~aegis.mcp.registry_guard.RegistryGuard` for shadowing and
       provider spoofing,
    4. run :class:`~aegis.mcp.scanner.ToolScanner` over the advertised tools,
    5. register in the :class:`~aegis.mcp.inventory.McpInventory` with the
       resulting per-tool obligations (block / sandbox / approval).

Enforcement (``call``)
    1. resolve the tool and reject unknown or disabled servers,
    2. refuse block-listed tools outright,
    3. sanitise outbound arguments (secret redaction, key allow-listing),
    4. apply the per-tool rate budget,
    5. forward, then sanitise the inbound result for secrets and injection,
    6. record everything to the audit ledger (lazily imported).

Optional collaborators (policy engine, approval workflow, sandbox runner) are
resolved lazily so this module imports cleanly on its own and no import cycle
is created.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional

from ..core.errors import (
    AuthorizationError,
    BlockedByPolicy,
    NotFoundError,
    RateLimited,
    UpstreamError,
    ValidationError,
)
from ..core.logging import get_logger
from ..core.types import RiskLevel, Severity, utc_now
from ..core.utils import TokenBucket
from .client import ClientConfig, ClientError, McpClient
from .inventory import McpInventory, ServerEntry, ToolLookup
from .pinning import PinError, PinningPolicy, PinState, ServerPinner
from .protocol import CallRequest, CallResult, McpError, McpErrorCode, ServerInfo, ToolDefinition
from .registry_guard import GuardVerdict, RegistryGuard, RegistryGuardConfig
from .sanitizer import ArgumentSanitizer, SanitizeDecision, SanitizerConfig
from .scanner import ScannerConfig, ToolScanReport, ToolScanner
from .transports import TransportSpec, build_transport

__all__ = ["McpProxy", "ProxyConfig", "ProxyStats", "ToolObligations"]

_LOG = get_logger("aegis.mcp.proxy")


@dataclass
class ToolObligations:
    """Per-tool enforcement requirements produced at admission time."""

    blocked: bool = False
    require_sandbox: bool = False
    require_approval: bool = False
    min_risk: RiskLevel = RiskLevel.LOW
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the obligations."""
        return {
            "blocked": self.blocked,
            "require_sandbox": self.require_sandbox,
            "require_approval": self.require_approval,
            "min_risk": self.min_risk.value,
            "reasons": list(self.reasons),
        }


@dataclass
class ProxyConfig:
    """Construction parameters for :class:`McpProxy`."""

    pinning: PinningPolicy = field(default_factory=PinningPolicy)
    guard: RegistryGuardConfig = field(default_factory=RegistryGuardConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    sanitizer: SanitizerConfig = field(default_factory=SanitizerConfig)
    client: ClientConfig = field(default_factory=ClientConfig)
    calls_per_minute: int = 120
    max_servers: int = 32
    fail_closed: bool = True
    auto_disable_on_guard_flag: bool = True


@dataclass
class ProxyStats:
    """Counters describing proxy activity."""

    servers_attached: int = 0
    servers_rejected: int = 0
    calls_forwarded: int = 0
    calls_blocked: int = 0
    calls_redacted: int = 0
    results_blocked: int = 0
    rate_limited: int = 0

    def as_dict(self) -> Dict[str, int]:
        """Return the counters as a plain mapping."""
        return {
            "servers_attached": self.servers_attached,
            "servers_rejected": self.servers_rejected,
            "calls_forwarded": self.calls_forwarded,
            "calls_blocked": self.calls_blocked,
            "calls_redacted": self.calls_redacted,
            "results_blocked": self.results_blocked,
            "rate_limited": self.rate_limited,
        }


class McpProxy:
    """Security-enforcing proxy in front of one or more MCP servers."""

    def __init__(self, config: Optional[ProxyConfig] = None, *, tenant_id: str = "default") -> None:
        """Create the proxy.

        Args:
            config: Tunables for pinning, guard, scanner, sanitizer and rates.
            tenant_id: Tenant this proxy instance serves.
        """
        self._config = config or ProxyConfig()
        self._tenant_id = tenant_id
        self._inventory = McpInventory()
        self._pinner = ServerPinner(self._config.pinning)
        self._guard = RegistryGuard(self._config.guard)
        self._scanner = ToolScanner(self._config.scanner)
        self._sanitizer = ArgumentSanitizer(self._config.sanitizer)
        self._clients: Dict[str, McpClient] = {}
        self._obligations: Dict[str, ToolObligations] = {}
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.RLock()
        self._stats = ProxyStats()

    # -- properties ---------------------------------------------------------

    @property
    def inventory(self) -> McpInventory:
        """Return the server/tool registry."""
        return self._inventory

    @property
    def pinner(self) -> ServerPinner:
        """Return the identity pinner."""
        return self._pinner

    @property
    def scanner(self) -> ToolScanner:
        """Return the tool scanner."""
        return self._scanner

    @property
    def sanitizer(self) -> ArgumentSanitizer:
        """Return the argument/result sanitizer."""
        return self._sanitizer

    @property
    def stats(self) -> ProxyStats:
        """Return the activity counters."""
        return self._stats

    # -- admission ----------------------------------------------------------

    def attach(
        self,
        server_id: str,
        spec: TransportSpec,
        *,
        client: Optional[McpClient] = None,
        trust_on_first_use: bool = True,
    ) -> ServerEntry:
        """Connect, vet and register an MCP server.

        Args:
            server_id: Stable identifier for the server.
            spec: How to reach it.
            client: Pre-built client (used by tests / in-process servers).
            trust_on_first_use: Auto-pin an unseen server.  Set false in
                hardened deployments where every server must be pre-pinned.

        Returns:
            The registered :class:`ServerEntry`.

        Raises:
            AuthorizationError: Pinning failed (impersonation) or the registry
                guard rejected the server.
            UpstreamError: The server could not be reached or initialised.
            RateLimited: The proxy already holds ``max_servers`` servers.
        """
        with self._lock:
            if len(self._clients) >= self._config.max_servers:
                self._stats.servers_rejected += 1
                raise RateLimited(
                    f"proxy already manages {self._config.max_servers} servers",
                    retry_after=60,
                )

        cfg = ClientConfig(
            server_id=server_id,
            name=server_id,
            protocol_version=self._config.client.protocol_version,
            request_timeout_s=self._config.client.request_timeout_s,
        )
        mcp_client = client or McpClient(spec, config=cfg)
        try:
            info: ServerInfo = mcp_client.connect()
        except (ClientError, McpError) as exc:
            self._stats.servers_rejected += 1
            raise UpstreamError(f"failed to initialise MCP server {server_id}: {exc}", cause=exc)

        tool_names = [t.name for t in info.tools or mcp_client.tools]
        tools: List[ToolDefinition] = list(info.tools or mcp_client.tools)
        info.tools = tools

        # 1) identity pinning
        fingerprint = ServerPinner.compute_fingerprint(
            server_id,
            {
                "name": info.name,
                "version": info.version,
                "transport": info.transport.value,
                "capabilities": info.capabilities,
                "tools": tool_names,
            },
        )
        info.fingerprint = fingerprint
        pinned = False
        try:
            state = self._pinner.verify(server_id, fingerprint)
            if state is PinState.UNKNOWN:
                if not trust_on_first_use and self._config.fail_closed:
                    mcp_client.close()
                    self._stats.servers_rejected += 1
                    raise AuthorizationError(
                        f"server {server_id} is not pre-pinned and TOFU is disabled",
                        details={"server_id": server_id},
                    )
                self._pinner.record(
                    server_id, fingerprint, version=info.version,
                    transport=info.transport.value, tool_count=len(tools),
                )
            pinned = True
        except PinError as exc:
            mcp_client.close()
            self._stats.servers_rejected += 1
            self._audit(
                "mcp.server.pin_failed",
                {"server_id": server_id, "error": str(exc)},
                Severity.CRITICAL,
            )
            raise AuthorizationError(str(exc), details={"server_id": server_id})

        # 2) registry guard (shadowing / spoofing)
        known = [
            _KnownServerView(entry.server_id, entry.name, [t.name for t in entry.tools], entry.enabled)
            for entry in self._inventory.list_servers()
        ]
        report = self._guard.evaluate(server_id, info.name, tool_names, known_servers=known)
        enabled = True
        if report.verdict is GuardVerdict.REJECT:
            mcp_client.close()
            self._stats.servers_rejected += 1
            self._audit(
                "mcp.server.guard_rejected",
                {"server_id": server_id, "report": report.to_dict()},
                Severity.CRITICAL,
            )
            raise AuthorizationError(
                f"registry guard rejected server {server_id}: {'; '.join(report.reasons)}",
                details=report.to_dict(),
            )
        if not report.clean:
            _LOG.warning("registry guard flagged server", extra=report.to_dict())
            self._audit("mcp.server.guard_flagged", {"server_id": server_id, "report": report.to_dict()}, Severity.HIGH)
            if self._config.auto_disable_on_guard_flag:
                enabled = False

        # 3) tool scanning → obligations
        scan = self._scanner.scan_server(server_id, tools)
        with self._lock:
            for tool_report in scan.tools:
                self._obligations[tool_report.tool] = self._obligations_from(tool_report)

        # 4) register
        now = utc_now()
        entry = self._inventory.register(
            server_id, _spec_to_dict(spec), info,
            pinned=pinned, enabled=enabled, registered_at=now, last_seen=now,
        )
        with self._lock:
            self._clients[server_id] = mcp_client
            self._stats.servers_attached += 1
        self._audit(
            "mcp.server.attached",
            {
                "server_id": server_id,
                "name": info.name,
                "transport": info.transport.value,
                "tools": len(tools),
                "max_risk": scan.max_risk.value,
                "blocked_tools": scan.blocked_tools,
                "enabled": enabled,
            },
            Severity.INFO if enabled else Severity.HIGH,
        )
        _LOG.info(
            "mcp server attached",
            extra={"server_id": server_id, "tools": len(tools), "enabled": enabled, "max_risk": scan.max_risk.value},
        )
        return entry

    def _obligations_from(self, report: ToolScanReport) -> ToolObligations:
        """Translate a scan report into enforcement obligations."""
        return ToolObligations(
            blocked=report.block,
            require_sandbox=report.force_sandbox,
            require_approval=report.require_approval,
            min_risk=report.risk.min_risk,
            reasons=list(report.reasons),
        )

    def detach(self, server_id: str) -> bool:
        """Disconnect and unregister a server.

        Args:
            server_id: The server to remove.

        Returns:
            ``True`` when a server was removed.
        """
        with self._lock:
            client = self._clients.pop(server_id, None)
        if client is not None:
            try:
                client.close()
            except Exception:  # pragma: no cover - teardown
                pass
        removed = self._inventory.unregister(server_id)
        if removed:
            self._audit("mcp.server.detached", {"server_id": server_id}, Severity.INFO)
        return removed

    def detach_all(self) -> int:
        """Disconnect every server; returns the count removed."""
        count = 0
        for entry in list(self._inventory.list_servers()):
            if self.detach(entry.server_id):
                count += 1
        return count

    # -- enforcement --------------------------------------------------------

    def obligations_for(self, tool: str) -> ToolObligations:
        """Return the enforcement obligations recorded for a tool.

        Args:
            tool: Qualified (``server::tool``) or bare tool name.

        Returns:
            The obligations; a fail-closed default (approval + sandbox) is
            returned for unknown tools when ``fail_closed`` is set.
        """
        with self._lock:
            found = self._obligations.get(tool)
        if found is not None:
            return found
        if "::" not in tool:
            try:
                lookup = self._inventory.resolve(tool)
                with self._lock:
                    found = self._obligations.get(lookup.qualified_name)
                if found is not None:
                    return found
            except NotFoundError:
                pass
        if self._config.fail_closed:
            return ToolObligations(
                require_sandbox=True,
                require_approval=True,
                min_risk=RiskLevel.HIGH,
                reasons=["unknown tool; fail-closed defaults applied"],
            )
        return ToolObligations()

    def call(self, request: CallRequest, *, approved: bool = False) -> CallResult:
        """Forward a tool call through the full enforcement sequence.

        Args:
            request: The call the agent wants to make.
            approved: Set by the caller when a valid approval receipt was
                already redeemed for this exact call.  The proxy never mints
                approvals itself; it only refuses when one is required and
                absent.

        Returns:
            The (sanitised) call result.

        Raises:
            NotFoundError: The tool or its server is unknown/disabled.
            BlockedByPolicy: The tool is block-listed, requires an approval
                that was not supplied, or its result tripped the sanitizer.
            RateLimited: The per-tool call budget is exhausted.
            UpstreamError: The server failed to answer.
        """
        started = time.monotonic()
        lookup: ToolLookup = self._inventory.resolve(request.tool if "::" in request.tool else request.qualified_name or request.tool)
        qualified = lookup.qualified_name
        obligations = self.obligations_for(qualified)

        if obligations.blocked:
            self._stats.calls_blocked += 1
            self._audit_call("mcp.call.blocked", request, qualified, {"reasons": obligations.reasons}, Severity.HIGH)
            raise BlockedByPolicy(
                f"tool {qualified} is blocked by static scan: {'; '.join(obligations.reasons)}",
            )

        if obligations.require_approval and not approved:
            self._stats.calls_blocked += 1
            self._audit_call(
                "mcp.call.approval_required", request, qualified,
                {"reasons": obligations.reasons}, Severity.MEDIUM,
            )
            raise BlockedByPolicy(
                f"tool {qualified} requires human approval before execution",
            )

        if not self._consume_budget(qualified):
            self._stats.rate_limited += 1
            raise RateLimited(f"call budget exhausted for {qualified}", retry_after=10)

        clean_args, arg_verdict = self._sanitizer.sanitize_args(qualified, request.arguments)
        if arg_verdict.decision is SanitizeDecision.BLOCKED:
            self._stats.calls_blocked += 1
            self._audit_call("mcp.call.args_blocked", request, qualified, arg_verdict.to_dict(), Severity.HIGH)
            raise BlockedByPolicy(f"arguments rejected: {arg_verdict.blocked_reason}")
        if arg_verdict.mutated:
            self._stats.calls_redacted += 1

        forwarded = CallRequest(
            tool=lookup.tool.name,
            server=lookup.server_id,
            arguments=clean_args,
            call_id=request.call_id,
            session_id=request.session_id,
            agent_id=request.agent_id,
            tenant_id=request.tenant_id or self._tenant_id,
        )

        with self._lock:
            client = self._clients.get(lookup.server_id)
        if client is None:
            raise NotFoundError(f"no live client for server {lookup.server_id}", details={"server_id": lookup.server_id})

        try:
            result = client.call(forwarded)
        except ClientError as exc:
            self._audit_call("mcp.call.upstream_error", request, qualified, {"error": str(exc)}, Severity.MEDIUM)
            raise UpstreamError(f"MCP call failed: {exc}", cause=exc)

        clean_content, res_verdict = self._sanitizer.sanitize_result(qualified, result.content)
        if res_verdict.decision is SanitizeDecision.BLOCKED:
            self._stats.results_blocked += 1
            self._audit_call("mcp.result.blocked", request, qualified, res_verdict.to_dict(), Severity.CRITICAL)
            raise BlockedByPolicy(f"tool result rejected: {res_verdict.blocked_reason}")
        result.content = clean_content
        result.redacted = res_verdict.mutated
        result.duration_ms = (time.monotonic() - started) * 1000.0

        self._stats.calls_forwarded += 1
        self._audit_call(
            "mcp.call.forwarded", request, qualified,
            {
                "duration_ms": round(result.duration_ms, 2),
                "redacted_args": arg_verdict.redacted_keys,
                "redacted_result": res_verdict.mutated,
                "ok": result.ok,
            },
            Severity.INFO,
        )
        return result

    # -- budget -------------------------------------------------------------

    def _consume_budget(self, qualified: str) -> bool:
        """Consume one token from the per-tool rate budget."""
        rate = max(1, int(self._config.calls_per_minute))
        with self._lock:
            bucket = self._buckets.get(qualified)
            if bucket is None:
                bucket = TokenBucket(capacity=rate, refill_per_second=rate / 60.0)
                self._buckets[qualified] = bucket
        return bucket.consume(1)

    # -- audit --------------------------------------------------------------

    def _audit_call(
        self,
        action: str,
        request: CallRequest,
        qualified: str,
        payload: Mapping[str, Any],
        severity: Severity,
    ) -> None:
        """Emit an audit event for a call-path decision."""
        body: Dict[str, Any] = {
            "call_id": request.call_id,
            "tool": qualified,
            "session_id": request.session_id,
            "agent_id": request.agent_id,
        }
        body.update(payload)
        self._audit(action, body, severity)

    def _audit(self, action: str, payload: Mapping[str, Any], severity: Severity) -> None:
        """Write to the audit ledger, degrading to a log line if unavailable."""
        try:
            from ..audit.ledger import get_ledger  # type: ignore

            get_ledger().append(
                action=action,
                actor=str(payload.get("agent_id", "agent")),
                resource=str(payload.get("tool", payload.get("server_id", "mcp"))),
                severity=severity,
                tenant_id=self._tenant_id,
                payload=dict(payload),
            )
        except Exception:
            _LOG.debug("mcp audit unavailable", extra={"action": action})


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _KnownServerView:
    """Lightweight view the registry guard consumes."""

    __slots__ = ("server_id", "name", "tool_names", "enabled")

    def __init__(self, server_id: str, name: str, tool_names: List[str], enabled: bool) -> None:
        self.server_id = server_id
        self.name = name
        self.tool_names = tool_names
        self.enabled = enabled


def _spec_to_dict(spec: TransportSpec) -> Dict[str, Any]:
    """Serialise a transport spec without leaking its token."""
    return {
        "kind": spec.kind,
        "command": list(spec.command or []),
        "url": spec.url,
        "post_url": spec.post_url,
        "sse_url": spec.sse_url,
        "token": "***" if spec.token else "",
        "timeout_s": spec.timeout_s,
    }
