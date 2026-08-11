"""Cryptographic pinning of MCP server and tool identity.

In the 2026-08 incidents several breaches began with a *trusted* MCP server
being swapped for a look-alike that exposed a near-identical tool surface but
leaked data or ran shell commands.  Pinning defeats this: the first time a
server is seen, its identity fingerprint is recorded; every later connection
must match *or* be explicitly re-pinned by a human.

This module is transport- and policy-agnostic.  It only answers "does this
server still look like the one we trusted?".
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional

from ..core.crypto import canonical_json, hmac_sign, sha256_hex
from ..core.errors import AegisError, ConflictError, NotFoundError, ValidationError
from ..core.logging import get_logger
from ..core.types import utc_now

__all__ = ["PinState", "PinRecord", "PinningPolicy", "ServerPinner", "PinError"]


class PinError(AegisError):
    """Raised when a server fails a pinning check."""


class PinState(str, Enum):
    """Lifecycle of a pinned identity."""

    UNKNOWN = "unknown"
    PINNED = "pinned"
    CHANGED = "changed"
    REVOKED = "revoked"


@dataclass
class PinRecord:
    """A recorded identity for one MCP server."""

    server_id: str
    fingerprint: str
    pin: str
    first_seen: float = field(default_factory=utc_now)
    last_seen: float = field(default_factory=utc_now)
    state: PinState = PinState.PINNED
    version: str = ""
    transport: str = ""
    tool_count: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the pin record."""
        data = {
            "server_id": self.server_id,
            "fingerprint": self.fingerprint,
            "pin": self.pin,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "state": self.state.value,
            "version": self.version,
            "transport": self.transport,
            "tool_count": self.tool_count,
            "history": list(self.history),
        }
        return data


@dataclass
class PinningPolicy:
    """Tunables for pinning behaviour."""

    enforce: bool = True
    allow_auto_pin: bool = True
    require_human_repin: bool = True
    pin_ttl_s: float = 0.0

    def validate(self) -> None:
        """Clamp values into a sane range."""
        self.pin_ttl_s = max(0.0, float(self.pin_ttl_s))


class ServerPinner:
    """Records and verifies MCP server identity fingerprints."""

    def __init__(self, policy: Optional[PinningPolicy] = None) -> None:
        """Create the pinner.

        Args:
            policy: Pinning tunables; defaults to enforcement on.
        """
        self._policy = policy or PinningPolicy()
        self._policy.validate()
        self._records: Dict[str, PinRecord] = {}
        self._lock = threading.RLock()

    @property
    def policy(self) -> PinningPolicy:
        """Return the active policy."""
        return self._policy

    @staticmethod
    def compute_fingerprint(server_id: str, info: Mapping[str, Any], *, key: str = "") -> str:
        """Compute a stable fingerprint over server identity.

        Args:
            server_id: Stable server identifier.
            info: A mapping of identity-relevant attributes (name, version,
                capabilities, tool names, transport).
            key: Optional HMAC key so fingerprints cannot be pre-computed by an
                attacker who controls the advertised attributes.

        Returns:
            A hex digest uniquely binding this server identity.
        """
        material = {
            "server_id": server_id,
            "name": str(info.get("name", "")),
            "version": str(info.get("version", "")),
            "transport": str(info.get("transport", "")),
            "capabilities": sorted(str(c) for c in info.get("capabilities", [])),
            "tools": sorted(str(t) for t in info.get("tools", [])),
        }
        body = canonical_json(material)
        if key:
            return hmac_sign(key, body)
        return sha256_hex(body)

    def record(self, server_id: str, fingerprint: str, *, version: str = "", transport: str = "", tool_count: int = 0) -> PinRecord:
        """Record a first-seen server, auto-pinning when permitted.

        Args:
            server_id: Stable server identifier.
            fingerprint: Fingerprint produced by :meth:`compute_fingerprint`.
            version: Server version string.
            transport: Transport kind name.
            tool_count: Number of tools advertised.

        Returns:
            The created pin record.

        Raises:
            PinError: Auto-pinning is disabled and no human record exists.
        """
        with self._lock:
            if server_id in self._records:
                raise ConflictError(f"server already pinned: {server_id}", details={"server_id": server_id})
            if not self._policy.allow_auto_pin and self._policy.enforce:
                raise PinError(f"server {server_id} is unknown and auto-pin is disabled")
            rec = PinRecord(
                server_id=server_id,
                fingerprint=fingerprint,
                pin=sha256_hex(f"{server_id}:{fingerprint}:{version}"),
                version=version,
                transport=transport,
                tool_count=int(tool_count),
                state=PinState.PINNED,
            )
            self._records[server_id] = rec
        return rec

    def verify(self, server_id: str, fingerprint: str) -> PinState:
        """Check a live fingerprint against the pinned record.

        Args:
            server_id: Stable server identifier.
            fingerprint: Fingerprint produced by :meth:`compute_fingerprint`
                for the current connection.

        Returns:
            The resulting :class:`PinState`.

        Raises:
            PinError: Enforcement is on and the fingerprint changed (this is
                the look-alike detection path) or the server is unknown and
                auto-pin is disabled.
        """
        with self._lock:
            rec = self._records.get(server_id)
            if rec is None:
                if self._policy.enforce and not self._policy.allow_auto_pin:
                    raise PinError(f"unknown server {server_id} and auto-pin disabled")
                return PinState.UNKNOWN
            rec.last_seen = utc_now()
            if rec.state is PinState.REVOKED:
                raise PinError(f"server {server_id} has been revoked", details={"server_id": server_id})
            if rec.fingerprint == fingerprint:
                return PinState.PINNED
            rec.state = PinState.CHANGED
            rec.history.append({"at": rec.last_seen, "event": "fingerprint_changed"})
            if self._policy.enforce:
                raise PinError(
                    f"server {server_id} fingerprint changed; possible impersonation",
                    details={"server_id": server_id, "expected": rec.fingerprint, "got": fingerprint},
                )
            return PinState.CHANGED

    def repin(self, server_id: str, fingerprint: str, *, actor: str = "human", version: str = "") -> PinRecord:
        """Explicitly re-pin a server after human review.

        Args:
            server_id: Stable server identifier.
            fingerprint: New fingerprint to trust.
            actor: Who authorised the re-pin (must be a human identity in
                practice; recorded for audit).
            version: New version string.

        Returns:
            The updated record.

        Raises:
            NotFoundError: The server is not known and auto-pin is off.
        """
        if self._policy.require_human_repin and actor in ("auto", "system", ""):
            raise ValidationError("re-pinning requires an explicit human actor")
        with self._lock:
            rec = self._records.get(server_id)
            now = utc_now()
            if rec is None:
                if not self._policy.allow_auto_pin:
                    raise NotFoundError(f"unknown server {server_id}", details={"server_id": server_id})
                rec = PinRecord(server_id=server_id, fingerprint=fingerprint, pin=sha256_hex(f"{server_id}:{fingerprint}"))
                self._records[server_id] = rec
            rec.fingerprint = fingerprint
            rec.pin = sha256_hex(f"{server_id}:{fingerprint}:{version}")
            rec.version = version
            rec.state = PinState.PINNED
            rec.last_seen = now
            rec.history.append({"at": now, "event": "repinned", "actor": actor})
        return rec

    def revoke(self, server_id: str, *, actor: str = "human") -> PinRecord:
        """Mark a server as revoked so future connections are refused.

        Args:
            server_id: Stable server identifier.
            actor: Who revoked it (recorded for audit).

        Returns:
            The updated record.

        Raises:
            NotFoundError: The server is not known.
        """
        with self._lock:
            rec = self._records.get(server_id)
            if rec is None:
                raise NotFoundError(f"unknown server {server_id}", details={"server_id": server_id})
            rec.state = PinState.REVOKED
            rec.history.append({"at": utc_now(), "event": "revoked", "actor": actor})
        return rec

    def get(self, server_id: str) -> Optional[PinRecord]:
        """Return a pin record by id, or ``None``."""
        with self._lock:
            return self._records.get(server_id)

    def all(self) -> List[PinRecord]:
        """Return all pin records."""
        with self._lock:
            return list(self._records.values())

    def known(self) -> List[str]:
        """Return the ids of all pinned servers."""
        with self._lock:
            return list(self._records.keys())
