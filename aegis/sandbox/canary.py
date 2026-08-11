"""Canary tokens: tripwires that prove sandbox content escaped.

A canary is a unique, worthless-but-realistic secret planted inside the sandbox
(environment variable, file, URL).  Nothing legitimate ever reads it, so if the
value later appears in a tool argument, an LLM prompt, an outbound HTTP body or
an audit log, exactly one thing happened: **content crossed the isolation
boundary**.

This is how the 2026-08 evaluation escapes were finally attributed - not by
watching syscalls, but by finding sandbox-only strings in third-party systems.
Canaries are cheap, have no false negatives for the paths they cover, and work
identically on Windows and POSIX.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from ..core.crypto import random_token, sha256_hex
from ..core.logging import get_logger
from ..core.types import Finding, DetectorKind, Severity, new_id, utc_now

__all__ = ["CanaryToken", "CanaryTokenManager", "CanaryHit"]

log = get_logger("sandbox.canary")

#: Shapes that look like the real thing to an attacker (and to an LLM being
#: socially engineered), but are provably synthetic to us.
_SHAPES: Dict[str, str] = {
    "openai_key": "sk-aegiscanary{token}",
    "aws_key": "AKIAAEGIS{token}",
    "github_pat": "ghp_aegiscanary{token}",
    "generic_secret": "aegis-canary-{token}",
    "bearer": "Bearer aegis.{token}",
    "url": "https://canary-{token}.aegis-invalid.test/beacon",
    "hostname": "canary-{token}.aegis-invalid.test",
    "db_password": "Aegis!Canary!{token}",
}

#: Environment variable names chosen because scrapers and injected prompts look
#: for exactly these keys.
_ENV_SLOTS: Dict[str, str] = {
    "OPENAI_API_KEY": "openai_key",
    "AWS_SECRET_ACCESS_KEY": "aws_key",
    "GITHUB_TOKEN": "github_pat",
    "DATABASE_URL": "url",
    "INTERNAL_API_TOKEN": "generic_secret",
}


@dataclass(frozen=True)
class CanaryToken:
    """One planted token."""

    id: str
    value: str
    shape: str
    slot: str = ""
    session_id: str = ""
    created_at: float = field(default=0.0)

    @property
    def digest(self) -> str:
        """Hash of the value - safe to log without re-leaking the canary."""
        return sha256_hex(self.value)[:16]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "shape": self.shape,
            "slot": self.slot,
            "session_id": self.session_id,
            "digest": self.digest,
            "created_at": self.created_at,
        }


@dataclass
class CanaryHit:
    """A canary value observed outside the sandbox."""

    token: CanaryToken
    location: str
    excerpt: str
    at: float = field(default_factory=utc_now)

    def to_finding(self) -> Finding:
        """Convert into a platform :class:`Finding` (always critical)."""
        return Finding(
            id=new_id("fnd"),
            detector="sandbox.canary",
            kind=DetectorKind.SANDBOX_ESCAPE,
            severity=Severity.CRITICAL,
            title="Sandbox canary token observed outside the sandbox",
            description=(
                f"Canary {self.token.id} (shape={self.token.shape}, slot="
                f"{self.token.slot or 'n/a'}) was found in {self.location}. "
                "This value exists only inside the isolated execution "
                "environment, so its presence here is direct evidence that "
                "sandbox content crossed the isolation boundary."
            ),
            confidence=1.0,
            evidence=[self.excerpt],
            location=self.location,
            remediation=(
                "Treat the session as compromised: quarantine it, rotate any "
                "real credentials that shared the sandbox, and run "
                "SandboxBoundaryTester against the driver before reusing it."
            ),
            references=["CWE-200", "OWASP LLM02:2025 Sensitive Information Disclosure"],
            tags=["canary", "sandbox-escape", "exfiltration"],
        )


class CanaryTokenManager:
    """Mint, plant and detect canary tokens.

    Args:
        shapes: Which token shapes to mint per session.  Defaults to one of
            every registered shape that has an environment slot, which gives
            broad coverage without bloating the environment.
        on_trigger: Callback invoked (outside the lock) for every hit.
    """

    def __init__(
        self,
        *,
        shapes: Optional[Sequence[str]] = None,
        on_trigger: Optional[Callable[[CanaryHit], None]] = None,
        max_sessions: int = 512,
    ) -> None:
        unknown = [s for s in (shapes or []) if s not in _SHAPES]
        if unknown:
            raise ValueError(f"unknown canary shapes: {unknown}")
        self.shapes: List[str] = list(shapes or list(_ENV_SLOTS.values()))
        self.max_sessions = max(1, max_sessions)
        self._by_session: Dict[str, List[CanaryToken]] = {}
        self._by_value: Dict[str, CanaryToken] = {}
        self._hits: List[CanaryHit] = []
        self._callbacks: List[Callable[[CanaryHit], None]] = []
        self._lock = threading.RLock()
        if on_trigger:
            self._callbacks.append(on_trigger)

    # ------------------------------------------------------------------ #
    # Minting
    # ------------------------------------------------------------------ #
    def _mint_one(self, shape: str, session_id: str, slot: str = "") -> CanaryToken:
        token = CanaryToken(
            id=new_id("cnry"),
            value=_SHAPES[shape].format(token=random_token(12).replace("-", "").replace("_", "")),
            shape=shape,
            slot=slot,
            session_id=session_id,
            created_at=utc_now(),
        )
        self._by_value[token.value] = token
        return token

    def mint(self, session_id: str, *, count: Optional[int] = None) -> List[str]:
        """Mint canary values for ``session_id``.

        Returns:
            The raw canary strings, ready to be injected into a
            :attr:`SandboxSpec.canary_tokens` list.
        """
        with self._lock:
            shapes = self.shapes if count is None else self.shapes[: max(1, count)]
            slots = list(_ENV_SLOTS.items())
            tokens: List[CanaryToken] = []
            for index, shape in enumerate(shapes):
                slot = ""
                for name, slot_shape in slots:
                    if slot_shape == shape and not any(t.slot == name for t in tokens):
                        slot = name
                        break
                if not slot:
                    slot = f"AEGIS_CANARY_{index}"
                tokens.append(self._mint_one(shape, session_id, slot))
            self._by_session[session_id] = tokens
            self._evict()
        log.debug(
            "canaries minted",
            fields={"session_id": session_id, "count": len(tokens)},
        )
        return [t.value for t in tokens]

    def _evict(self) -> None:
        """Bound memory by dropping the oldest sessions."""
        while len(self._by_session) > self.max_sessions:
            oldest = min(
                self._by_session,
                key=lambda sid: min((t.created_at for t in self._by_session[sid]), default=0.0),
            )
            for token in self._by_session.pop(oldest, []):
                self._by_value.pop(token.value, None)

    def tokens_for(self, session_id: str) -> List[CanaryToken]:
        """Return the token objects minted for a session."""
        with self._lock:
            return list(self._by_session.get(session_id, []))

    # ------------------------------------------------------------------ #
    # Injection
    # ------------------------------------------------------------------ #
    def env_for(self, session_id: str) -> Dict[str, str]:
        """Environment variables carrying this session's canaries."""
        return {t.slot: t.value for t in self.tokens_for(session_id) if t.slot}

    def files_for(self, session_id: str) -> Dict[str, str]:
        """Decoy files planted in the sandbox working directory.

        The names mirror what a credential-harvesting payload greps for.
        """
        tokens = self.tokens_for(session_id)
        if not tokens:
            return {}
        by_shape = {t.shape: t.value for t in tokens}
        env_lines = "\n".join(f"{t.slot or t.shape.upper()}={t.value}" for t in tokens)
        files = {
            ".env": f"# generated credentials\n{env_lines}\n",
            ".aegis-canary": "\n".join(t.value for t in tokens) + "\n",
        }
        if "aws_key" in by_shape:
            files[".aws/credentials"] = (
                "[default]\n"
                "aws_access_key_id = AKIAAEGISCANARYONLY\n"
                f"aws_secret_access_key = {by_shape['aws_key']}\n"
            )
        if "url" in by_shape:
            files["config.json"] = (
                '{\n  "callback_url": "' + by_shape["url"] + '",\n  "environment": "sandbox"\n}\n'
            )
        return files

    # ------------------------------------------------------------------ #
    # Detection
    # ------------------------------------------------------------------ #
    def check_leak(
        self,
        text: Any,
        *,
        location: str = "unknown",
        session_id: str = "",
    ) -> List[str]:
        """Scan ``text`` for any known canary value.

        Args:
            text: Any object; non-strings are stringified so dicts, lists and
                tool results can be passed directly.
            location: Where the content came from, recorded on the hit.
            session_id: Restrict the scan to one session's canaries when given.

        Returns:
            The canary values found.  A non-empty result means escape.
        """
        haystack = text if isinstance(text, str) else str(text)
        if not haystack:
            return []
        with self._lock:
            candidates = (
                {t.value: t for t in self._by_session.get(session_id, [])}
                if session_id
                else dict(self._by_value)
            )
        found: List[str] = []
        hits: List[CanaryHit] = []
        for value, token in candidates.items():
            index = haystack.find(value)
            if index < 0:
                continue
            found.append(value)
            start = max(0, index - 40)
            end = min(len(haystack), index + len(value) + 40)
            excerpt = haystack[start:end].replace(value, f"<canary:{token.id}>")
            hits.append(CanaryHit(token=token, location=location, excerpt=excerpt))

        for hit in hits:
            self._register_hit(hit)
        return found

    def check_many(self, chunks: Iterable[Any], *, location: str = "batch") -> List[str]:
        """Scan several payloads, returning the union of canaries found."""
        found: List[str] = []
        for chunk in chunks:
            for value in self.check_leak(chunk, location=location):
                if value not in found:
                    found.append(value)
        return found

    def _register_hit(self, hit: CanaryHit) -> None:
        with self._lock:
            self._hits.append(hit)
            callbacks = list(self._callbacks)
        log.error(
            "CANARY TRIGGERED - sandbox content observed outside the boundary",
            fields={
                "canary_id": hit.token.id,
                "shape": hit.token.shape,
                "digest": hit.token.digest,
                "location": hit.location,
                "session_id": hit.token.session_id,
            },
        )
        for callback in callbacks:
            try:
                callback(hit)
            except Exception as exc:  # pragma: no cover - callback isolation
                log.warning("canary callback failed", fields={"error": str(exc)})

    def on_trigger(self, callback: Callable[[CanaryHit], None]) -> None:
        """Register an additional trigger callback."""
        with self._lock:
            self._callbacks.append(callback)

    # ------------------------------------------------------------------ #
    @property
    def triggered(self) -> List[CanaryHit]:
        """Every hit recorded so far, oldest first."""
        with self._lock:
            return list(self._hits)

    def findings(self) -> List[Finding]:
        """Convert every hit into a platform finding."""
        return [hit.to_finding() for hit in self.triggered]

    def scrub(self, text: str) -> str:
        """Replace canary values in ``text`` before it is stored or displayed."""
        out = text or ""
        with self._lock:
            values = list(self._by_value)
        for value in values:
            out = out.replace(value, "<redacted-canary>")
        return out

    def reset(self, session_id: Optional[str] = None) -> None:
        """Forget one session's canaries, or all of them."""
        with self._lock:
            if session_id is None:
                self._by_session.clear()
                self._by_value.clear()
                self._hits.clear()
                return
            for token in self._by_session.pop(session_id, []):
                self._by_value.pop(token.value, None)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "sessions": len(self._by_session),
                "active_tokens": len(self._by_value),
                "hits": len(self._hits),
                "shapes": list(self.shapes),
            }


#: Regex that matches any Aegis canary shape - used as a cheap pre-filter when
#: the exact token set is not available (e.g. in a detached log processor).
CANARY_HINT_RE = re.compile(
    r"(sk-aegiscanary|AKIAAEGIS|ghp_aegiscanary|aegis-canary-|aegis-invalid\.test|Aegis!Canary!)",
    re.IGNORECASE,
)


def looks_like_canary(text: str) -> bool:
    """Fast heuristic check with no access to the minted token registry."""
    return bool(CANARY_HINT_RE.search(text or ""))
