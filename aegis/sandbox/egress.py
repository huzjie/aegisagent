"""Outbound network control for sandboxed workloads.

Default-deny egress is the single highest-value control against agent data
exfiltration: prompt injection can make an agent *want* to POST your source
tree somewhere, but it cannot make the socket connect if the destination is not
on the allowlist.

Three layers are implemented here:

1. **Hard blocks** - cloud instance-metadata endpoints and link-local /
   loopback ranges are refused even if an operator allowlists them by mistake.
   ``169.254.169.254`` is how an escaped agent turns "I can make HTTP requests"
   into "I have your cloud role credentials".
2. **Allowlist** - domain globs plus CIDR ranges, evaluated after the hard
   blocks.
3. **Proxy environment** - :meth:`EgressController.http_proxy_env` renders the
   variables that make the sandboxed runtime route through a recording proxy,
   so even permitted traffic is observable.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from ..core.errors import EgressBlocked
from ..core.logging import get_logger
from ..core.types import SandboxSpec, utc_now
from ..core.utils import host_matches_allowlist

__all__ = [
    "EgressController",
    "ProxyRecorder",
    "BlockedAttempt",
    "METADATA_ENDPOINTS",
    "is_private_address",
]

log = get_logger("sandbox.egress")


#: Cloud metadata services.  Reaching any of these from inside a sandbox is a
#: credential-theft attempt, full stop - there is no legitimate agent use case.
METADATA_ENDPOINTS: Dict[str, str] = {
    "169.254.169.254": "AWS/Azure/OpenStack instance metadata (IMDS) - returns IAM role credentials",
    "fd00:ec2::254": "AWS IMDSv6 endpoint",
    "metadata.google.internal": "GCP metadata server - returns service-account access tokens",
    "metadata.goog": "GCP metadata alias",
    "169.254.170.2": "AWS ECS task metadata / task role credentials",
    "100.100.100.200": "Alibaba Cloud ECS metadata - returns RAM role credentials",
    "100.100.100.199": "Alibaba Cloud NTP/metadata auxiliary endpoint",
    "metadata.tencentyun.com": "Tencent Cloud CVM metadata - returns CAM role credentials",
    "169.254.0.0/16": "IPv4 link-local range that hosts every cloud metadata service",
}

#: Hostnames that resolve back to the gateway itself.  Allowing them lets a
#: sandboxed workload call the control plane and, for example, approve its own
#: pending request.
_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "host.docker.internal"}


def is_private_address(host: str) -> Tuple[bool, str]:
    """Classify ``host`` as a private/reserved address.

    Returns:
        ``(is_private, reason)``.  ``reason`` is empty when the address is a
        routable public one, or when ``host`` is not a literal IP.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False, ""
    if address.is_loopback:
        return True, "loopback address (would reach the gateway itself)"
    if address.is_link_local:
        return True, "link-local address (cloud metadata range)"
    if address.is_private:
        return True, "RFC1918 / private address (internal lateral movement)"
    if address.is_reserved:
        return True, "reserved address block"
    if address.is_multicast:
        return True, "multicast address"
    if address.is_unspecified:
        return True, "unspecified address"
    return False, ""


@dataclass
class BlockedAttempt:
    """One refused outbound destination."""

    target: str
    host: str
    port: int
    reason: str
    at: float = field(default_factory=utc_now)
    session_id: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "reason": self.reason,
            "at": self.at,
            "session_id": self.session_id,
        }


class ProxyRecorder:
    """Thread-safe ring buffer of blocked (and optionally allowed) destinations.

    The recorder is deliberately separate from the controller so a single
    recorder can be shared across many sandbox runs and surfaced as a single
    "what did the agents try to reach?" report.
    """

    def __init__(self, capacity: int = 2000) -> None:
        self.capacity = max(16, capacity)
        self._blocked: List[BlockedAttempt] = []
        self._allowed: List[Tuple[str, float]] = []
        self._lock = threading.Lock()

    def record_block(self, attempt: BlockedAttempt) -> None:
        """Append a blocked attempt, trimming the oldest entries."""
        with self._lock:
            self._blocked.append(attempt)
            if len(self._blocked) > self.capacity:
                del self._blocked[: len(self._blocked) - self.capacity]

    def record_allow(self, target: str) -> None:
        """Append an allowed destination for traffic-profile reporting."""
        with self._lock:
            self._allowed.append((target, utc_now()))
            if len(self._allowed) > self.capacity:
                del self._allowed[: len(self._allowed) - self.capacity]

    @property
    def blocked(self) -> List[BlockedAttempt]:
        with self._lock:
            return list(self._blocked)

    def blocked_targets(self) -> List[str]:
        """Unique blocked targets, preserving first-seen order."""
        seen: Dict[str, None] = {}
        for attempt in self.blocked:
            seen.setdefault(attempt.target, None)
        return list(seen)

    def top_reasons(self, limit: int = 5) -> List[Tuple[str, int]]:
        counts: Dict[str, int] = {}
        for attempt in self.blocked:
            counts[attempt.reason] = counts.get(attempt.reason, 0) + 1
        return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]

    def clear(self) -> None:
        with self._lock:
            self._blocked.clear()
            self._allowed.clear()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "blocked": len(self._blocked),
                "allowed": len(self._allowed),
                "unique_blocked": len({a.target for a in self._blocked}),
                "top_reasons": self.top_reasons(),
            }


class EgressController:
    """Decide whether a sandboxed workload may reach a destination.

    Args:
        allowlist: Domain globs (``*.pypi.org``), bare hostnames or CIDRs.
        mode: ``deny`` blocks everything, ``allowlist`` honours the list,
            ``allow`` permits anything except the hard blocks.  Even in
            ``allow`` mode metadata endpoints stay blocked.
        allowed_ports: Destination ports that may be used at all.
        resolve_dns: When True, hostnames are resolved and the resulting IPs are
            re-checked.  This defeats DNS rebinding, where ``evil.example.com``
            is allowlisted and then resolves to ``169.254.169.254``.
        recorder: Shared :class:`ProxyRecorder`.
    """

    def __init__(
        self,
        allowlist: Optional[Sequence[str]] = None,
        *,
        mode: str = "deny",
        allowed_ports: Optional[Sequence[int]] = None,
        resolve_dns: bool = True,
        recorder: Optional[ProxyRecorder] = None,
        proxy_url: str = "",
        session_id: str = "",
    ) -> None:
        self.allowlist: List[str] = [str(a).strip().lower() for a in (allowlist or []) if str(a).strip()]
        self.mode = (mode or "deny").lower()
        self.allowed_ports: Tuple[int, ...] = tuple(allowed_ports or (80, 443))
        self.resolve_dns = resolve_dns
        self.recorder = recorder or ProxyRecorder()
        self.proxy_url = proxy_url
        self.session_id = session_id
        self._dns_cache: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    @classmethod
    def from_spec(
        cls,
        spec: SandboxSpec,
        *,
        recorder: Optional[ProxyRecorder] = None,
        session_id: str = "",
        proxy_url: str = "",
    ) -> "EgressController":
        """Build a controller from the network fields of a :class:`SandboxSpec`."""
        return cls(
            spec.egress_allowlist,
            mode=spec.network,
            recorder=recorder,
            session_id=session_id,
            proxy_url=proxy_url,
        )

    # ------------------------------------------------------------------ #
    def _split(self, url_or_host: str) -> Tuple[str, int, str]:
        """Return ``(host, port, scheme)`` for a URL, ``host:port`` or bare host."""
        raw = str(url_or_host or "").strip()
        if not raw:
            return "", 0, ""
        if "://" in raw:
            parsed = urlparse(raw)
            host = (parsed.hostname or "").lower()
            scheme = (parsed.scheme or "").lower()
            port = parsed.port or (443 if scheme == "https" else 80)
            return host, int(port), scheme
        if raw.count(":") == 1 and not raw.startswith("["):
            host, _, port_text = raw.partition(":")
            try:
                return host.lower(), int(port_text), ""
            except ValueError:
                return raw.lower(), 0, ""
        return raw.strip("[]").lower(), 0, ""

    def _hard_block_reason(self, host: str) -> str:
        """Return a non-empty reason when ``host`` must never be reachable."""
        if not host:
            return "empty destination host"
        if host in _LOOPBACK_NAMES:
            return "loopback hostname (would reach the control plane itself)"
        for key, description in METADATA_ENDPOINTS.items():
            if "/" in key:
                try:
                    network = ipaddress.ip_network(key, strict=False)
                    if ipaddress.ip_address(host) in network:
                        return f"cloud metadata range {key}: {description}"
                except ValueError:
                    continue
            elif host == key or host.endswith("." + key):
                return f"cloud metadata endpoint: {description}"
        private, reason = is_private_address(host)
        if private:
            return reason
        return ""

    def _resolved_addresses(self, host: str) -> List[str]:
        """Resolve ``host`` to literal addresses, with a small cache."""
        with self._lock:
            cached = self._dns_cache.get(host)
        if cached is not None:
            return cached
        addresses: List[str] = []
        try:
            for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
                address = info[4][0]
                if address not in addresses:
                    addresses.append(str(address))
        except (socket.gaierror, UnicodeError, OSError):
            addresses = []
        with self._lock:
            self._dns_cache[host] = addresses
        return addresses

    # ------------------------------------------------------------------ #
    def check(self, url: str, *, port: Optional[int] = None) -> None:
        """Authorise an outbound destination.

        Raises:
            EgressBlocked: When the destination is hard-blocked, off-allowlist,
                on a disallowed port, or resolves to a blocked address.
        """
        host, parsed_port, scheme = self._split(url)
        effective_port = int(port or parsed_port or 0)

        def deny(reason: str) -> None:
            attempt = BlockedAttempt(
                target=str(url),
                host=host,
                port=effective_port,
                reason=reason,
                session_id=self.session_id,
            )
            self.recorder.record_block(attempt)
            log.warning("egress blocked", fields=attempt.as_dict())
            raise EgressBlocked(f"egress to {url} blocked: {reason}", details=attempt.as_dict())

        if not host:
            deny("destination could not be parsed")

        if scheme and scheme not in ("http", "https"):
            deny(f"scheme '{scheme}' is not permitted for sandbox egress")

        hard = self._hard_block_reason(host)
        if hard:
            deny(hard)

        if effective_port and effective_port not in self.allowed_ports:
            deny(f"port {effective_port} is not in the allowed set {list(self.allowed_ports)}")

        if self.mode == "deny":
            deny("sandbox network policy is default-deny")

        if self.mode != "allow":
            if not self.allowlist:
                deny("allowlist mode is active but the allowlist is empty")
            if not host_matches_allowlist(host, self.allowlist):
                deny(f"host '{host}' is not on the egress allowlist")

        if self.resolve_dns:
            for address in self._resolved_addresses(host):
                rebind = self._hard_block_reason(address)
                if rebind:
                    deny(f"DNS rebinding: {host} resolves to {address} - {rebind}")

        self.recorder.record_allow(str(url))

    def allows(self, url: str, *, port: Optional[int] = None) -> bool:
        """Non-raising variant of :meth:`check`."""
        try:
            self.check(url, port=port)
            return True
        except EgressBlocked:
            return False

    def filter_allowed(self, urls: Iterable[str]) -> Tuple[List[str], List[str]]:
        """Partition ``urls`` into ``(allowed, blocked)``."""
        allowed, blocked = [], []
        for url in urls:
            (allowed if self.allows(url) else blocked).append(url)
        return allowed, blocked

    # ------------------------------------------------------------------ #
    def http_proxy_env(self, spec: Optional[SandboxSpec] = None) -> Dict[str, str]:
        """Environment variables that force the sandbox through the proxy.

        When no proxy URL is configured and the policy is default-deny, the
        variables are still emitted pointing at an unroutable address: most
        HTTP clients honour ``*_proxy``, so this turns "silently exfiltrates"
        into "connection refused", which is the safer failure mode.
        """
        target = self.proxy_url or "http://127.0.0.1:1"
        no_proxy = "localhost,127.0.0.1,::1"
        env = {
            "HTTP_PROXY": target,
            "HTTPS_PROXY": target,
            "http_proxy": target,
            "https_proxy": target,
            "ALL_PROXY": target,
            "all_proxy": target,
            "NO_PROXY": no_proxy,
            "no_proxy": no_proxy,
            # Honoured by requests/httpx/pip and stops a workload from silently
            # disabling TLS verification to talk to an interception endpoint.
            "PYTHONHTTPSVERIFY": "1",
        }
        network_mode = (spec.network if spec else self.mode) or "deny"
        env["AEGIS_EGRESS_MODE"] = network_mode
        if self.allowlist:
            env["AEGIS_EGRESS_ALLOWLIST"] = ",".join(self.allowlist)
        return env

    def describe(self) -> Dict[str, Any]:
        """Configuration summary for audit and boundary reports."""
        return {
            "mode": self.mode,
            "allowlist": list(self.allowlist),
            "allowed_ports": list(self.allowed_ports),
            "resolve_dns": self.resolve_dns,
            "proxy_url": self.proxy_url,
            "hard_blocked": sorted(METADATA_ENDPOINTS),
            "recorder": self.recorder.stats(),
        }

    def on_block(self, callback: Callable[[BlockedAttempt], None]) -> None:
        """Register a callback invoked for every future blocked attempt."""
        original = self.recorder.record_block

        def wrapped(attempt: BlockedAttempt) -> None:
            original(attempt)
            try:
                callback(attempt)
            except Exception as exc:  # pragma: no cover - callback isolation
                log.warning("egress block callback failed", fields={"error": str(exc)})

        self.recorder.record_block = wrapped  # type: ignore[method-assign]

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<EgressController mode={self.mode} allow={len(self.allowlist)}>"
