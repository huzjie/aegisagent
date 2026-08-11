"""Break-glass: audited emergency bypass of the approval requirement.

During a real outage a responder sometimes must act faster than a two-person
approval allows.  Removing that pressure valve leads to something worse:
operators disabling AegisAgent entirely.  So the valve exists, but it is
expensive to pull:

* a written justification and an incident reference are mandatory,
* the grant is *scoped* to a tool glob and a session, never global,
* the TTL is short and hard - expiry is checked on every use,
* each grant is single-tenant, rate limited and counted,
* every mint, use, expiry and revocation emits a CRITICAL audit event,
* grants land in a review queue and stay flagged until a human signs them off.

A break-glass grant does **not** disable provenance, detection or sandboxing.
It only substitutes for the human approval step, and the resulting receipt is
marked ``break_glass=True`` so downstream systems can treat it differently.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..core.crypto import random_token
from ..core.errors import AuthorizationError, NotFoundError, RateLimited, ValidationError
from ..core.logging import get_logger
from ..core.types import Principal, Severity, new_id, utc_now
from ..core.utils import SlidingWindowCounter, any_glob_match, truncate

__all__ = ["BreakGlassGrant", "BreakGlassManager", "BreakGlassStats"]

_LOG = get_logger("aegis.approval.breakglass")

#: Roles allowed to mint a grant unless overridden.
DEFAULT_BREAK_GLASS_ROLES = ("incident_commander", "security", "admin")

#: Maximum grants a single principal may mint inside the rate window.
MAX_GRANTS_PER_PRINCIPAL = 3

#: Rate window in seconds.
GRANT_WINDOW_S = 3600.0

#: Absolute ceiling on grant lifetime regardless of what the caller asks for.
MAX_TTL_S = 3600

#: Minimum length of an acceptable justification.
MIN_JUSTIFICATION_LEN = 20


@dataclass
class BreakGlassGrant:
    """A scoped, expiring authorisation to bypass human approval."""

    id: str = field(default_factory=lambda: new_id("bg"))
    tenant_id: str = "default"
    principal_id: str = ""
    principal_name: str = ""
    reason: str = ""
    incident_ref: str = ""
    tool_scope: List[str] = field(default_factory=lambda: ["*"])
    session_id: str = ""
    max_uses: int = 1
    uses: int = 0
    issued_at: float = field(default_factory=utc_now)
    expires_at: float = 0.0
    revoked_at: Optional[float] = None
    revoked_by: str = ""
    reviewed: bool = False
    reviewed_by: str = ""
    reviewed_at: Optional[float] = None
    secret: str = field(default_factory=lambda: random_token(16))
    used_on: List[str] = field(default_factory=list)
    co_signer_id: str = ""

    def is_active(self, now: Optional[float] = None) -> bool:
        """Whether the grant can still be used right now."""
        moment = now if now is not None else utc_now()
        if self.revoked_at is not None:
            return False
        if self.expires_at > 0 and moment > self.expires_at:
            return False
        return self.uses < self.max_uses

    def remaining_s(self, now: Optional[float] = None) -> float:
        """Seconds of validity left, clamped at zero."""
        moment = now if now is not None else utc_now()
        return max(0.0, self.expires_at - moment) if self.expires_at else 0.0

    def covers(self, tool: str, *, session_id: str = "") -> bool:
        """Whether the grant authorises a specific call.

        Args:
            tool: Fully qualified tool name about to execute.
            session_id: Session the call belongs to.

        Returns:
            ``True`` only when the tool matches the scope globs and, if the
            grant was pinned to a session, the session matches too.
        """
        if self.session_id and session_id and self.session_id != session_id:
            return False
        return any_glob_match(tool, self.tool_scope)

    def to_dict(self, *, include_secret: bool = False) -> Dict[str, Any]:
        """Return a JSON-serialisable representation.

        Args:
            include_secret: When false (default) the redemption secret is
                masked so grants can safely be listed in a UI or log.
        """
        data = asdict(self)
        if not include_secret:
            data["secret"] = "***"
        return data

    def summary(self) -> str:
        """Return a single-line description used in alerts."""
        return (
            f"[{self.id}] break-glass by {self.principal_name or self.principal_id} "
            f"scope={','.join(self.tool_scope)} ttl={int(self.remaining_s())}s "
            f"incident={self.incident_ref or 'n/a'} :: {truncate(self.reason, 80)}"
        )


@dataclass
class BreakGlassStats:
    """Aggregate counters for the break-glass facility."""

    granted: int = 0
    used: int = 0
    denied: int = 0
    revoked: int = 0
    expired: int = 0
    pending_review: int = 0

    def as_dict(self) -> Dict[str, int]:
        """Return the counters as a plain mapping."""
        return asdict(self)


class BreakGlassManager:
    """Mint, validate, revoke and review emergency approval bypasses."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        ttl_s: int = 1800,
        allowed_roles: Optional[List[str]] = None,
        require_co_signer: bool = False,
        require_incident_ref: bool = True,
        tenant_id: str = "default",
    ) -> None:
        """Create a manager.

        Args:
            enabled: Master switch; when false every mint attempt is refused.
            ttl_s: Default grant lifetime, capped by :data:`MAX_TTL_S`.
            allowed_roles: Roles permitted to mint grants.
            require_co_signer: Demand a second principal on every grant, which
                turns break-glass into a two-person emergency procedure.
            require_incident_ref: Demand a ticket/incident identifier.
            tenant_id: Tenant this manager serves.
        """
        self._enabled = bool(enabled)
        self._ttl = min(MAX_TTL_S, max(60, int(ttl_s)))
        self._roles = list(allowed_roles or DEFAULT_BREAK_GLASS_ROLES)
        self._require_co_signer = bool(require_co_signer)
        self._require_incident_ref = bool(require_incident_ref)
        self._tenant_id = tenant_id
        self._grants: Dict[str, BreakGlassGrant] = {}
        self._rate = SlidingWindowCounter(window_s=GRANT_WINDOW_S)
        self._lock = threading.RLock()
        self._stats = BreakGlassStats()

    # -- properties ---------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Whether break-glass is available at all."""
        return self._enabled

    @property
    def stats(self) -> BreakGlassStats:
        """Return the live counters."""
        with self._lock:
            self._stats.pending_review = sum(1 for g in self._grants.values() if not g.reviewed)
        return self._stats

    # -- minting ------------------------------------------------------------

    def grant(
        self,
        principal: Principal,
        *,
        reason: str,
        incident_ref: str = "",
        tool_scope: Optional[List[str]] = None,
        session_id: str = "",
        ttl_s: Optional[int] = None,
        max_uses: int = 1,
        co_signer: Optional[Principal] = None,
    ) -> BreakGlassGrant:
        """Mint a new break-glass grant.

        Args:
            principal: The responder invoking the emergency path.
            reason: Written justification; must be substantive.
            incident_ref: Incident or change ticket identifier.
            tool_scope: Glob patterns of tools the grant covers.  Defaults to
                ``["*"]`` but a wildcard grant is logged at CRITICAL.
            session_id: Restrict the grant to one agent session.
            ttl_s: Override the default lifetime, still capped.
            max_uses: How many calls the grant may release.
            co_signer: Second principal, required when the manager was built
                with ``require_co_signer``.

        Returns:
            The active grant.

        Raises:
            AuthorizationError: Break-glass is disabled, the principal lacks a
                permitted role, or the co-signer requirement is unmet.
            ValidationError: The justification or incident reference is
                missing or too short.
            RateLimited: The principal minted too many grants recently.
        """
        if not self._enabled:
            self._stats.denied += 1
            raise AuthorizationError("break-glass is disabled for this deployment")
        if not principal.has_role(*self._roles):
            self._stats.denied += 1
            raise AuthorizationError(
                "principal is not permitted to invoke break-glass",
                details={"principal_id": principal.id, "allowed_roles": list(self._roles)},
            )
        justification = (reason or "").strip()
        if len(justification) < MIN_JUSTIFICATION_LEN:
            self._stats.denied += 1
            raise ValidationError(
                f"break-glass justification must be at least {MIN_JUSTIFICATION_LEN} characters",
                details={"length": len(justification)},
            )
        if self._require_incident_ref and not (incident_ref or "").strip():
            self._stats.denied += 1
            raise ValidationError("break-glass requires an incident reference")
        if self._require_co_signer:
            if co_signer is None:
                self._stats.denied += 1
                raise AuthorizationError("break-glass requires a co-signer in this deployment")
            if co_signer.id == principal.id:
                self._stats.denied += 1
                raise AuthorizationError("break-glass co-signer must be a different principal")
            if not co_signer.has_role(*self._roles):
                self._stats.denied += 1
                raise AuthorizationError("break-glass co-signer lacks a permitted role")
        if self._rate.count(principal.id) >= MAX_GRANTS_PER_PRINCIPAL:
            self._stats.denied += 1
            raise RateLimited(
                "break-glass grant rate exceeded for this principal",
                retry_after=GRANT_WINDOW_S,
                details={"principal_id": principal.id, "window_s": GRANT_WINDOW_S},
            )

        lifetime = min(MAX_TTL_S, max(60, int(ttl_s if ttl_s is not None else self._ttl)))
        scope = [s for s in (tool_scope or ["*"]) if str(s).strip()] or ["*"]
        now = utc_now()
        item = BreakGlassGrant(
            tenant_id=principal.tenant_id or self._tenant_id,
            principal_id=principal.id,
            principal_name=principal.name,
            reason=justification,
            incident_ref=incident_ref.strip(),
            tool_scope=scope,
            session_id=session_id,
            max_uses=max(1, int(max_uses)),
            issued_at=now,
            expires_at=now + lifetime,
            co_signer_id=co_signer.id if co_signer else "",
        )
        with self._lock:
            self._grants[item.id] = item
            self._stats.granted += 1
        self._rate.hit(principal.id)
        _LOG.critical(
            "BREAK-GLASS GRANTED",
            extra={
                "grant_id": item.id,
                "principal_id": principal.id,
                "scope": scope,
                "wildcard": "*" in scope,
                "ttl_s": lifetime,
                "incident_ref": item.incident_ref,
            },
        )
        self._audit("approval.break_glass.granted", item, Severity.CRITICAL)
        return item

    # -- redemption ---------------------------------------------------------

    def check(self, grant_id: str, tool: str, *, session_id: str = "") -> BreakGlassGrant:
        """Validate a grant for a specific call without consuming it.

        Args:
            grant_id: Identifier returned by :meth:`grant`.
            tool: Fully qualified tool name about to execute.
            session_id: Session the call belongs to.

        Returns:
            The grant when it is active and in scope.

        Raises:
            NotFoundError: No such grant.
            AuthorizationError: The grant is expired, revoked, exhausted or
                out of scope.
        """
        with self._lock:
            item = self._grants.get(grant_id)
        if item is None:
            raise NotFoundError("unknown break-glass grant", details={"grant_id": grant_id})
        if not item.is_active():
            self._stats.denied += 1
            if item.revoked_at is not None:
                raise AuthorizationError("break-glass grant was revoked", details={"grant_id": grant_id})
            if item.uses >= item.max_uses:
                raise AuthorizationError("break-glass grant is exhausted", details={"grant_id": grant_id})
            self._stats.expired += 1
            raise AuthorizationError("break-glass grant has expired", details={"grant_id": grant_id})
        if not item.covers(tool, session_id=session_id):
            self._stats.denied += 1
            raise AuthorizationError(
                "break-glass grant does not cover this tool or session",
                details={"grant_id": grant_id, "tool": tool, "scope": item.tool_scope},
            )
        return item

    def consume(self, grant_id: str, tool: str, *, session_id: str = "", call_id: str = "") -> BreakGlassGrant:
        """Validate and burn one use of a grant.

        Args:
            grant_id: Identifier returned by :meth:`grant`.
            tool: Fully qualified tool name being released.
            session_id: Session the call belongs to.
            call_id: Tool-call identifier recorded on the grant for audit.

        Returns:
            The grant after the use counter was incremented.

        Raises:
            NotFoundError: No such grant.
            AuthorizationError: The grant is not usable for this call.
        """
        item = self.check(grant_id, tool, session_id=session_id)
        with self._lock:
            item.uses += 1
            item.used_on.append(call_id or tool)
            self._stats.used += 1
        _LOG.critical(
            "BREAK-GLASS USED",
            extra={
                "grant_id": item.id,
                "tool": tool,
                "call_id": call_id,
                "uses": item.uses,
                "max_uses": item.max_uses,
            },
        )
        self._audit("approval.break_glass.used", item, Severity.CRITICAL, extra={"tool": tool, "call_id": call_id})
        return item

    # -- lifecycle ----------------------------------------------------------

    def revoke(self, grant_id: str, *, actor: str = "system", reason: str = "revoked") -> BreakGlassGrant:
        """Immediately invalidate a grant.

        Args:
            grant_id: Grant to revoke.
            actor: Who revoked it.
            reason: Stored for the post-incident review.

        Returns:
            The revoked grant.

        Raises:
            NotFoundError: No such grant.
        """
        with self._lock:
            item = self._grants.get(grant_id)
            if item is None:
                raise NotFoundError("unknown break-glass grant", details={"grant_id": grant_id})
            item.revoked_at = utc_now()
            item.revoked_by = actor
            item.reason = f"{item.reason} | revoked: {reason}"
            self._stats.revoked += 1
        _LOG.critical("BREAK-GLASS REVOKED", extra={"grant_id": grant_id, "actor": actor})
        self._audit("approval.break_glass.revoked", item, Severity.CRITICAL, extra={"actor": actor})
        return item

    def revoke_all(self, *, actor: str = "system", reason: str = "bulk revocation") -> int:
        """Revoke every active grant, e.g. when an incident is closed.

        Args:
            actor: Who requested the sweep.
            reason: Stored on each grant.

        Returns:
            The number of grants revoked.
        """
        count = 0
        for item in self.active():
            try:
                self.revoke(item.id, actor=actor, reason=reason)
                count += 1
            except NotFoundError:
                continue
        return count

    def review(self, grant_id: str, reviewer: Principal, *, note: str = "") -> BreakGlassGrant:
        """Sign off a grant during post-incident review.

        Args:
            grant_id: Grant being reviewed.
            reviewer: The reviewing principal, who must not be the requester.
            note: Review commentary appended to the reason.

        Returns:
            The reviewed grant.

        Raises:
            NotFoundError: No such grant.
            AuthorizationError: A requester attempted to review their own use.
        """
        with self._lock:
            item = self._grants.get(grant_id)
            if item is None:
                raise NotFoundError("unknown break-glass grant", details={"grant_id": grant_id})
            if reviewer.id == item.principal_id:
                raise AuthorizationError("break-glass use cannot be reviewed by the requester")
            item.reviewed = True
            item.reviewed_by = reviewer.id
            item.reviewed_at = utc_now()
            if note:
                item.reason = f"{item.reason} | review: {note}"
        self._audit("approval.break_glass.reviewed", item, Severity.HIGH, extra={"reviewer": reviewer.id})
        return item

    # -- queries ------------------------------------------------------------

    def get(self, grant_id: str) -> Optional[BreakGlassGrant]:
        """Return a grant by id, or ``None``."""
        with self._lock:
            return self._grants.get(grant_id)

    def active(self, *, session_id: str = "") -> List[BreakGlassGrant]:
        """List currently usable grants.

        Args:
            session_id: When given, only grants covering that session.

        Returns:
            Grants sorted by soonest expiry first.
        """
        now = utc_now()
        with self._lock:
            items = [g for g in self._grants.values() if g.is_active(now)]
        if session_id:
            items = [g for g in items if not g.session_id or g.session_id == session_id]
        items.sort(key=lambda g: g.expires_at)
        return items

    def find_for(self, tool: str, *, session_id: str = "") -> Optional[BreakGlassGrant]:
        """Return the first active grant covering ``tool``.

        Args:
            tool: Fully qualified tool name.
            session_id: Session the call belongs to.

        Returns:
            A usable grant, or ``None`` when the normal approval path applies.
        """
        for item in self.active(session_id=session_id):
            if item.covers(tool, session_id=session_id):
                return item
        return None

    def pending_review(self) -> List[BreakGlassGrant]:
        """List grants that were used but never signed off."""
        with self._lock:
            return [g for g in self._grants.values() if g.uses > 0 and not g.reviewed]

    def prune(self) -> int:
        """Drop expired grants that have already been reviewed.

        Returns:
            The number of records removed.
        """
        now = utc_now()
        removed = 0
        with self._lock:
            for gid, item in list(self._grants.items()):
                if item.reviewed and not item.is_active(now):
                    self._grants.pop(gid, None)
                    removed += 1
        return removed

    # -- audit --------------------------------------------------------------

    def _audit(
        self,
        action: str,
        grant: BreakGlassGrant,
        severity: Severity,
        *,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write a ledger entry, degrading to a log line when unavailable.

        The audit subsystem is imported lazily so that the approval layer can
        be used standalone and so that neither package imports the other at
        module load time.
        """
        payload: Dict[str, Any] = grant.to_dict()
        payload.update(extra or {})
        try:
            from ..audit.ledger import get_ledger  # type: ignore

            get_ledger().append(
                action=action,
                actor=grant.principal_id,
                resource=f"break_glass/{grant.id}",
                severity=severity,
                tenant_id=grant.tenant_id,
                payload=payload,
            )
        except Exception:
            _LOG.warning("break-glass audit unavailable", extra={"action": action, "grant_id": grant.id})
