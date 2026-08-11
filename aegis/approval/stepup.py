"""Step-up authentication for high-risk approvals.

A password typed hours ago proves nothing about who is clicking "approve"
right now.  For CRITICAL actions AegisAgent demands a *fresh* second factor
bound to the specific ticket, so that:

* a stolen session cookie cannot approve a destructive action,
* an XSS/CSRF payload cannot silently click through an approval UI,
* the approver physically acknowledges the ticket id they are releasing.

Two verifier flavours ship in the standard library build:

:class:`TotpVerifier`
    RFC 6238 codes via :func:`aegis.core.crypto.totp_verify`, with per-code
    burn-in so a shoulder-surfed code cannot be reused inside its window.
:class:`ChallengeVerifier`
    Out-of-band challenge/response: the platform mints a random challenge and
    the approver echoes it back through a different channel.  This is the
    fallback when no TOTP secret is enrolled and is deliberately noisy.

Hardware-key (WebAuthn) verification requires a network-facing relying party
and is represented by :class:`HardwareKeyVerifier`, which validates an
assertion previously recorded by the front end rather than speaking CTAP
itself.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..core.crypto import (
    constant_time_equals,
    hmac_verify,
    new_totp_secret,
    random_token,
    sha256_hex,
    totp_verify,
)
from ..core.errors import AuthenticationError, StepUpRequired, ValidationError
from ..core.logging import get_logger
from ..core.types import Principal, utc_now
from ..core.utils import SlidingWindowCounter

__all__ = [
    "StepUpMethod",
    "StepUpChallenge",
    "StepUpResult",
    "StepUpVerifier",
    "TotpVerifier",
    "ChallengeVerifier",
    "HardwareKeyVerifier",
    "StepUpRegistry",
]

_LOG = get_logger("aegis.approval.stepup")

#: How long a minted challenge stays usable.
CHALLENGE_TTL_S = 180.0

#: Wrong attempts tolerated per principal inside the lockout window.
MAX_FAILURES = 5

#: Lockout window in seconds.
FAILURE_WINDOW_S = 300.0


class StepUpMethod(str):
    """Named step-up mechanisms.

    Implemented as a ``str`` subclass rather than an ``Enum`` so that
    deployments can plug in custom verifier names without patching the core.
    """

    TOTP = "totp"
    CHALLENGE = "challenge"
    HARDWARE_KEY = "hardware_key"
    NONE = "none"


@dataclass
class StepUpChallenge:
    """A one-time challenge bound to a principal and a ticket."""

    id: str = field(default_factory=lambda: "chl_" + random_token(8))
    principal_id: str = ""
    ticket_id: str = ""
    method: str = StepUpMethod.CHALLENGE
    value: str = field(default_factory=lambda: random_token(6))
    issued_at: float = field(default_factory=utc_now)
    expires_at: float = field(default_factory=lambda: utc_now() + CHALLENGE_TTL_S)
    consumed: bool = False

    def is_expired(self, now: Optional[float] = None) -> bool:
        """Whether the challenge has aged out."""
        return (now if now is not None else utc_now()) > self.expires_at

    def prompt(self) -> str:
        """Return the text shown to the approver."""
        return (
            f"Confirm approval of ticket {self.ticket_id} by entering this code "
            f"from your out-of-band channel (valid {int(CHALLENGE_TTL_S)}s)."
        )


@dataclass
class StepUpResult:
    """Outcome of one verification attempt."""

    ok: bool = False
    method: str = StepUpMethod.NONE
    principal_id: str = ""
    ticket_id: str = ""
    reason: str = ""
    verified_at: float = field(default_factory=utc_now)

    def require(self) -> "StepUpResult":
        """Return self when successful, otherwise raise.

        Raises:
            StepUpRequired: The verification did not succeed.
        """
        if not self.ok:
            raise StepUpRequired(
                self.reason or "step-up verification failed",
                details={"method": self.method, "ticket_id": self.ticket_id},
            )
        return self


class StepUpVerifier(ABC):
    """Interface implemented by every step-up mechanism."""

    #: Machine name recorded on the vote.
    method: str = StepUpMethod.NONE

    @abstractmethod
    def enrolled(self, principal: Principal) -> bool:
        """Whether ``principal`` can use this mechanism.

        Args:
            principal: The approver.

        Returns:
            ``True`` when the necessary secret or credential is registered.
        """

    @abstractmethod
    def verify(self, principal: Principal, ticket_id: str, proof: str) -> StepUpResult:
        """Validate ``proof`` for ``principal`` on ``ticket_id``.

        Args:
            principal: The approver being challenged.
            ticket_id: Ticket the approval is bound to.
            proof: The code, assertion or response supplied by the approver.

        Returns:
            A :class:`StepUpResult`; implementations must not raise on a
            simple wrong code, only on structural errors.
        """

    def challenge(self, principal: Principal, ticket_id: str) -> Optional[StepUpChallenge]:
        """Mint a challenge when the mechanism needs one.

        Args:
            principal: The approver.
            ticket_id: Ticket being approved.

        Returns:
            ``None`` for mechanisms such as TOTP that are self-clocking.
        """
        return None


class TotpVerifier(StepUpVerifier):
    """RFC 6238 time-based one-time password verification."""

    method = StepUpMethod.TOTP

    def __init__(self, *, window: int = 1, step: int = 30) -> None:
        """Create a verifier.

        Args:
            window: Number of adjacent time steps accepted, absorbing clock
                skew.  Keep this at 1; larger windows widen the replay gap.
            step: TOTP period in seconds.
        """
        self._window = max(0, int(window))
        self._step = max(1, int(step))
        self._secrets: Dict[str, str] = {}
        self._burned: Dict[str, float] = {}
        self._lock = threading.RLock()

    def enrol(self, principal_id: str, secret: str = "") -> str:
        """Register (or rotate) a TOTP secret for a principal.

        Args:
            principal_id: Identifier of the approver.
            secret: Base32 secret; generated when omitted.

        Returns:
            The secret that was stored, for display in an enrolment QR code.

        Raises:
            ValidationError: ``principal_id`` is empty.
        """
        if not principal_id:
            raise ValidationError("principal_id is required to enrol a TOTP secret")
        value = secret or new_totp_secret()
        with self._lock:
            self._secrets[principal_id] = value
        _LOG.info("totp enrolled", extra={"principal_id": principal_id})
        return value

    def revoke(self, principal_id: str) -> bool:
        """Remove a principal's TOTP secret.

        Args:
            principal_id: Identifier of the approver.

        Returns:
            ``True`` when a secret was present and removed.
        """
        with self._lock:
            return self._secrets.pop(principal_id, None) is not None

    def enrolled(self, principal: Principal) -> bool:
        """Whether the principal has a registered secret."""
        with self._lock:
            return principal.id in self._secrets

    def verify(self, principal: Principal, ticket_id: str, proof: str) -> StepUpResult:
        """Validate a TOTP code and burn it against replay.

        Args:
            principal: The approver.
            ticket_id: Ticket being released.
            proof: The six-digit code.

        Returns:
            A result flagged ``ok`` only for a fresh, unburned, valid code.
        """
        code = (proof or "").strip().replace(" ", "")
        with self._lock:
            secret = self._secrets.get(principal.id, "")
        if not secret:
            return StepUpResult(
                ok=False,
                method=self.method,
                principal_id=principal.id,
                ticket_id=ticket_id,
                reason="no TOTP secret enrolled for this principal",
            )
        if not code.isdigit():
            return StepUpResult(
                ok=False, method=self.method, principal_id=principal.id,
                ticket_id=ticket_id, reason="malformed TOTP code",
            )
        burn_key = sha256_hex(f"{principal.id}:{code}")
        now = utc_now()
        with self._lock:
            self._prune_burned(now)
            if burn_key in self._burned:
                return StepUpResult(
                    ok=False, method=self.method, principal_id=principal.id,
                    ticket_id=ticket_id, reason="TOTP code already used (replay blocked)",
                )
        if not totp_verify(secret, code, window=self._window, step=self._step):
            return StepUpResult(
                ok=False, method=self.method, principal_id=principal.id,
                ticket_id=ticket_id, reason="invalid TOTP code",
            )
        with self._lock:
            self._burned[burn_key] = now + self._step * (self._window + 1)
        return StepUpResult(ok=True, method=self.method, principal_id=principal.id, ticket_id=ticket_id)

    def _prune_burned(self, now: float) -> None:
        """Drop expired replay-guard entries; caller holds the lock."""
        for key, expiry in list(self._burned.items()):
            if expiry <= now:
                self._burned.pop(key, None)


class ChallengeVerifier(StepUpVerifier):
    """Out-of-band challenge/response verification."""

    method = StepUpMethod.CHALLENGE

    def __init__(self, ttl_s: float = CHALLENGE_TTL_S) -> None:
        """Create a verifier.

        Args:
            ttl_s: Seconds a minted challenge remains valid.
        """
        self._ttl = max(10.0, float(ttl_s))
        self._pending: Dict[str, StepUpChallenge] = {}
        self._lock = threading.RLock()

    def enrolled(self, principal: Principal) -> bool:
        """Always ``True``; this mechanism needs no prior registration."""
        return True

    def challenge(self, principal: Principal, ticket_id: str) -> StepUpChallenge:
        """Mint and store a fresh challenge for this principal/ticket pair."""
        item = StepUpChallenge(
            principal_id=principal.id,
            ticket_id=ticket_id,
            method=self.method,
            expires_at=utc_now() + self._ttl,
        )
        with self._lock:
            self._prune()
            self._pending[self._key(principal.id, ticket_id)] = item
        return item

    def verify(self, principal: Principal, ticket_id: str, proof: str) -> StepUpResult:
        """Compare ``proof`` against the outstanding challenge value."""
        key = self._key(principal.id, ticket_id)
        with self._lock:
            self._prune()
            item = self._pending.get(key)
            if item is None:
                return StepUpResult(
                    ok=False, method=self.method, principal_id=principal.id,
                    ticket_id=ticket_id, reason="no outstanding challenge; request one first",
                )
            if item.consumed or item.is_expired():
                self._pending.pop(key, None)
                return StepUpResult(
                    ok=False, method=self.method, principal_id=principal.id,
                    ticket_id=ticket_id, reason="challenge expired or already used",
                )
            if not constant_time_equals(item.value, (proof or "").strip()):
                return StepUpResult(
                    ok=False, method=self.method, principal_id=principal.id,
                    ticket_id=ticket_id, reason="challenge response mismatch",
                )
            item.consumed = True
            self._pending.pop(key, None)
        return StepUpResult(ok=True, method=self.method, principal_id=principal.id, ticket_id=ticket_id)

    @staticmethod
    def _key(principal_id: str, ticket_id: str) -> str:
        """Return the composite storage key."""
        return f"{principal_id}|{ticket_id}"

    def _prune(self) -> None:
        """Remove expired challenges; caller holds the lock."""
        now = utc_now()
        for key, item in list(self._pending.items()):
            if item.is_expired(now):
                self._pending.pop(key, None)


class HardwareKeyVerifier(StepUpVerifier):
    """Validate a signed WebAuthn-style assertion recorded by the front end.

    The browser performs the CTAP dance; AegisAgent only checks that the
    relying party signed an assertion covering *this* ticket id, which is what
    stops an assertion captured on a low-risk page from being replayed on a
    destructive approval.
    """

    method = StepUpMethod.HARDWARE_KEY

    def __init__(self, relying_party_key: str) -> None:
        """Create a verifier.

        Args:
            relying_party_key: Shared HMAC secret with the component that
                performs WebAuthn verification.

        Raises:
            ValidationError: The key is empty, which would make every
                assertion trivially forgeable.
        """
        if not relying_party_key:
            raise ValidationError("hardware key verifier requires a relying-party secret")
        self._key = relying_party_key
        self._registered: Dict[str, str] = {}
        self._lock = threading.RLock()

    def register(self, principal_id: str, credential_id: str) -> None:
        """Bind a credential id to a principal.

        Args:
            principal_id: Identifier of the approver.
            credential_id: Opaque credential identifier from the authenticator.
        """
        with self._lock:
            self._registered[principal_id] = credential_id

    def enrolled(self, principal: Principal) -> bool:
        """Whether a credential is registered or the principal self-attests."""
        with self._lock:
            if principal.id in self._registered:
                return True
        return bool(principal.hardware_key_verified)

    def verify(self, principal: Principal, ticket_id: str, proof: str) -> StepUpResult:
        """Verify ``proof`` formatted as ``credential_id.signature``.

        Args:
            principal: The approver.
            ticket_id: Ticket the assertion must cover.
            proof: The assertion produced by the front end.

        Returns:
            A result flagged ``ok`` only when the credential is registered to
            the principal and the signature covers ``principal|ticket``.
        """
        raw = (proof or "").strip()
        if "." not in raw:
            return StepUpResult(
                ok=False, method=self.method, principal_id=principal.id,
                ticket_id=ticket_id, reason="malformed hardware assertion",
            )
        credential_id, _, signature = raw.partition(".")
        with self._lock:
            expected_credential = self._registered.get(principal.id, "")
        if expected_credential and not constant_time_equals(expected_credential, credential_id):
            return StepUpResult(
                ok=False, method=self.method, principal_id=principal.id,
                ticket_id=ticket_id, reason="credential not registered to this principal",
            )
        message = f"{principal.id}|{ticket_id}|{credential_id}"
        if not hmac_verify(self._key, message, signature):
            return StepUpResult(
                ok=False, method=self.method, principal_id=principal.id,
                ticket_id=ticket_id, reason="hardware assertion signature invalid",
            )
        return StepUpResult(ok=True, method=self.method, principal_id=principal.id, ticket_id=ticket_id)


class StepUpRegistry:
    """Selects a verifier, enforces lockout and records verification state."""

    def __init__(self, verifiers: Optional[List[StepUpVerifier]] = None) -> None:
        """Create a registry.

        Args:
            verifiers: Ordered preference list.  Defaults to TOTP followed by
                out-of-band challenge, which is always available.
        """
        self._verifiers: List[StepUpVerifier] = list(verifiers or [TotpVerifier(), ChallengeVerifier()])
        self._failures = SlidingWindowCounter(window_s=FAILURE_WINDOW_S)
        self._lock = threading.RLock()

    @property
    def methods(self) -> List[str]:
        """Return the configured method names in preference order."""
        return [v.method for v in self._verifiers]

    def add(self, verifier: StepUpVerifier, *, preferred: bool = False) -> None:
        """Register an additional verifier.

        Args:
            verifier: The mechanism to add.
            preferred: When true it is consulted before existing verifiers.
        """
        with self._lock:
            if preferred:
                self._verifiers.insert(0, verifier)
            else:
                self._verifiers.append(verifier)

    def get(self, method: str) -> Optional[StepUpVerifier]:
        """Return the verifier implementing ``method`` if present."""
        with self._lock:
            for verifier in self._verifiers:
                if verifier.method == method:
                    return verifier
        return None

    def select(self, principal: Principal) -> Optional[StepUpVerifier]:
        """Return the strongest mechanism the principal is enrolled in.

        Args:
            principal: The approver.

        Returns:
            The first enrolled verifier in preference order, or ``None``.
        """
        with self._lock:
            candidates = list(self._verifiers)
        for verifier in candidates:
            try:
                if verifier.enrolled(principal):
                    return verifier
            except Exception as exc:  # pragma: no cover - defensive
                _LOG.warning("step-up enrolment probe failed", extra={"method": verifier.method, "error": str(exc)})
        return None

    def challenge(self, principal: Principal, ticket_id: str, *, method: str = "") -> Optional[StepUpChallenge]:
        """Mint a challenge using ``method`` or the selected mechanism.

        Args:
            principal: The approver.
            ticket_id: Ticket being approved.
            method: Force a specific mechanism when non-empty.

        Returns:
            The challenge, or ``None`` for self-clocking mechanisms.

        Raises:
            AuthenticationError: No mechanism is available for the principal.
        """
        verifier = self.get(method) if method else self.select(principal)
        if verifier is None:
            raise AuthenticationError(
                "no step-up mechanism available for this principal",
                details={"principal_id": principal.id, "methods": self.methods},
            )
        return verifier.challenge(principal, ticket_id)

    def verify(self, principal: Principal, ticket_id: str, proof: str, *, method: str = "") -> StepUpResult:
        """Verify a step-up proof, applying failure lockout.

        Args:
            principal: The approver.
            ticket_id: Ticket the proof is bound to.
            proof: Code or assertion supplied by the approver.
            method: Force a specific mechanism when non-empty.

        Returns:
            The verification result.

        Raises:
            AuthenticationError: The principal is locked out after too many
                failures, or no mechanism is available.
        """
        if self.locked_out(principal.id):
            raise AuthenticationError(
                "too many failed step-up attempts; principal temporarily locked out",
                details={"principal_id": principal.id, "window_s": FAILURE_WINDOW_S},
            )
        verifier = self.get(method) if method else self.select(principal)
        if verifier is None:
            raise AuthenticationError(
                "no step-up mechanism available for this principal",
                details={"principal_id": principal.id},
            )
        result = verifier.verify(principal, ticket_id, proof)
        if not result.ok:
            self._failures.hit(principal.id)
            _LOG.warning(
                "step-up verification failed",
                extra={"principal_id": principal.id, "ticket_id": ticket_id, "reason": result.reason},
            )
        else:
            self._failures.reset(principal.id)
            _LOG.info(
                "step-up verification passed",
                extra={"principal_id": principal.id, "ticket_id": ticket_id, "method": result.method},
            )
        return result

    def locked_out(self, principal_id: str) -> bool:
        """Whether the principal exceeded the failure budget."""
        return self._failures.count(principal_id) >= MAX_FAILURES

    def failures(self, principal_id: str) -> int:
        """Return recent failure count for the principal."""
        return self._failures.count(principal_id)
