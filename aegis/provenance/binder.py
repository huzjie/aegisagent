"""Issue attestations at the only moment they can be trusted: completion time.

``ProvenanceBinder`` sits directly behind the model client.  When a completion
comes back it is recorded and every tool call the model emitted gets a signed,
single-use attestation.  Downstream, nothing may dispatch a tool without
presenting one of those tokens.

This inverts the CoreBreak failure mode.  In the vulnerable runtimes the event
loop dispatched whatever ``tool_use`` block it found in the message list, so an
attacker only had to append one.  Here, an appended block has no attestation:
the binder never saw it, never hashed its arguments and never signed it, so the
verifier classifies it as ``UNSIGNED`` (or ``ORPHANED`` if the attacker also
invents a completion id).
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Tuple

from ..core.config import Settings, get_settings
from ..core.crypto import Signer, build_signer, random_nonce
from ..core.errors import ValidationError
from ..core.logging import get_logger
from ..core.types import ModelCompletion, ToolCall, utc_now
from .attestation import (
    Attestation,
    encode_attestation,
    hash_arguments,
    iter_tool_calls,
)
from .session_ledger import SessionLedger

__all__ = ["ProvenanceBinder"]

_LOG = get_logger("provenance.binder")


class ProvenanceBinder:
    """Records model completions and mints attestations for their tool calls.

    Parameters
    ----------
    issuer:
        Logical name written into every token.  Verifiers reject issuers that
        are not on their ``trusted_issuers`` list.
    signer:
        Pre-built :class:`~aegis.core.crypto.Signer`.  When omitted one is built
        from ``signing_algorithm`` / ``signing_key`` / ``key_id``.
    ledger:
        Shared :class:`SessionLedger`.  Binder and verifier **must** share the
        same instance (or the same backing store) - the ledger is what turns a
        signature into a provenance proof.
    default_ttl_s:
        Attestation lifetime.  Short by design: a token that outlives the turn
        it belongs to becomes a replayable capability.
    """

    def __init__(
        self,
        *,
        issuer: str = "aegis-gateway",
        signer: Optional[Signer] = None,
        signing_algorithm: str = "hmac-sha256",
        signing_key: str = "",
        key_id: str = "default",
        ledger: Optional[SessionLedger] = None,
        default_ttl_s: float = 300.0,
    ) -> None:
        self.issuer = issuer or "aegis-gateway"
        self.signer: Signer = signer or build_signer(signing_algorithm, signing_key, key_id)
        self.ledger = ledger if ledger is not None else SessionLedger()
        self.default_ttl_s = float(default_ttl_s)
        self._lock = threading.RLock()
        self._bound: Dict[str, ModelCompletion] = {}
        self._arg_hashes: Dict[str, List[Tuple[str, str]]] = {}
        self._issued_count = 0

    # ------------------------------------------------------------------ #
    # Construction helpers
    # ------------------------------------------------------------------ #
    @classmethod
    def from_settings(
        cls,
        settings: Optional[Settings] = None,
        *,
        ledger: Optional[SessionLedger] = None,
    ) -> "ProvenanceBinder":
        """Build a binder from the ``provenance`` / ``security`` config sections."""
        settings = settings or get_settings()
        issuers = settings.get("provenance.trusted_issuers", ["aegis-gateway"]) or ["aegis-gateway"]
        return cls(
            issuer=str(issuers[0]),
            signing_algorithm=str(settings.get("security.signing_algorithm", "hmac-sha256")),
            signing_key=str(settings.get("security.signing_key", "")),
            key_id=str(settings.get("security.signing_key_id", "default")),
            ledger=ledger,
            default_ttl_s=float(settings.get("provenance.max_age_s", 300)),
        )

    # ------------------------------------------------------------------ #
    # Binding
    # ------------------------------------------------------------------ #
    def bind_completion(self, completion: ModelCompletion) -> None:
        """Record a completion and pre-compute the argument hash of each call.

        Called once per model turn, *before* any tool is dispatched.  Hashing
        here (rather than at dispatch time) is what makes argument tampering
        detectable: the hash is taken from the raw provider response.
        """
        if not completion.id:
            raise ValidationError("completion must carry an id before it can be bound")
        pairs = [(name, hash_arguments(args)) for name, args in iter_tool_calls(completion) if name]
        with self._lock:
            self._bound[completion.id] = completion
            self._arg_hashes[completion.id] = pairs
        self.ledger.record_completion(completion)
        _LOG.debug(
            "bound completion",
            fields={
                "completion_id": completion.id,
                "session_id": completion.session_id,
                "tool_calls": len(pairs),
            },
        )

    def is_bound(self, completion_id: str) -> bool:
        """True when :meth:`bind_completion` has seen this completion."""
        with self._lock:
            return completion_id in self._bound

    def bound_tools(self, completion_id: str) -> List[str]:
        """Tool names the model actually emitted for a bound completion."""
        with self._lock:
            return [name for name, _ in self._arg_hashes.get(completion_id, [])]

    # ------------------------------------------------------------------ #
    # Issuing
    # ------------------------------------------------------------------ #
    def issue(
        self,
        completion_id: str,
        tool: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        ttl_s: Optional[float] = None,
        agent_id: str = "",
        session_id: str = "",
        turn: Optional[int] = None,
        strict: bool = True,
    ) -> str:
        """Mint one attestation token.

        Parameters
        ----------
        strict:
            When True (default) the binder refuses to sign a tool that the bound
            completion never emitted, or whose arguments differ from the
            recorded ones.  Disabling it is only appropriate for gateways that
            deliberately rewrite arguments *before* binding.

        Raises
        ------
        ValidationError
            When ``strict`` is set and the request does not correspond to a
            recorded tool call.  Refusing to sign here means the verifier will
            later see ``UNSIGNED`` rather than a genuine-looking token.
        """
        args = arguments or {}
        args_hash = hash_arguments(args)

        with self._lock:
            completion = self._bound.get(completion_id)
            recorded = self._arg_hashes.get(completion_id, [])

        if completion is None:
            completion = self.ledger.get_completion(completion_id)
            if completion is not None:
                recorded = [
                    (name, hash_arguments(call_args))
                    for name, call_args in iter_tool_calls(completion)
                    if name
                ]

        if strict:
            if completion is None:
                raise ValidationError(
                    f"refusing to attest tool {tool!r}: completion {completion_id!r} was never bound"
                )
            names = [name for name, _ in recorded]
            if tool not in names:
                raise ValidationError(
                    f"refusing to attest tool {tool!r}: completion {completion_id!r} emitted "
                    f"{names or ['<none>']}"
                )
            if not any(name == tool and digest == args_hash for name, digest in recorded):
                raise ValidationError(
                    f"refusing to attest tool {tool!r}: arguments do not match the recorded "
                    f"tool call for completion {completion_id!r}"
                )

        now = utc_now()
        lifetime = float(ttl_s if ttl_s is not None else self.default_ttl_s)
        attestation = Attestation(
            issuer=self.issuer,
            session_id=session_id or (completion.session_id if completion else ""),
            completion_id=completion_id,
            tool=tool,
            args_hash=args_hash,
            nonce=random_nonce(),
            issued_at=now,
            expires_at=now + max(1.0, lifetime),
            key_id=self.signer.key_id,
            agent_id=agent_id,
            turn=int(turn if turn is not None else (completion.turn if completion else 0)),
        )
        token = encode_attestation(attestation, self.signer)
        with self._lock:
            self._issued_count += 1
        return token

    def issue_for_completion(
        self,
        completion: ModelCompletion,
        *,
        ttl_s: Optional[float] = None,
        agent_id: str = "",
        bind: bool = True,
    ) -> Dict[int, str]:
        """Bind a completion and attest every tool call it contains.

        Returns a ``{tool_call_index: token}`` mapping so callers can attach the
        right token to the right dispatch without relying on tool names being
        unique inside a single turn.
        """
        if bind and not self.is_bound(completion.id):
            self.bind_completion(completion)

        tokens: Dict[int, str] = {}
        for index, (name, args) in enumerate(iter_tool_calls(completion)):
            if not name:
                _LOG.warning(
                    "skipping unnamed tool call",
                    fields={"completion_id": completion.id, "index": index},
                )
                continue
            tokens[index] = self.issue(
                completion.id,
                name,
                args,
                ttl_s=ttl_s,
                agent_id=agent_id,
                session_id=completion.session_id,
                turn=completion.turn,
                strict=False,
            )
        return tokens

    def attach(self, call: ToolCall, *, ttl_s: Optional[float] = None) -> ToolCall:
        """Stamp an existing :class:`ToolCall` with a fresh attestation in place.

        Used by the gateway when it constructs the outbound call itself.
        """
        if not call.completion_id:
            raise ValidationError("cannot attest a tool call with no completion_id")
        call.attestation = self.issue(
            call.completion_id,
            call.tool,
            call.arguments,
            ttl_s=ttl_s,
            agent_id=call.agent_id,
            session_id=call.session_id,
            turn=call.turn,
            strict=False,
        )
        return call

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        """Counters for the metrics endpoint."""
        with self._lock:
            return {
                "issuer": self.issuer,
                "algorithm": self.signer.algorithm,
                "key_id": self.signer.key_id,
                "bound_completions": len(self._bound),
                "issued": self._issued_count,
                "default_ttl_s": self.default_ttl_s,
            }

    def forget(self, completion_id: str) -> None:
        """Drop cached binding state for a completed turn."""
        with self._lock:
            self._bound.pop(completion_id, None)
            self._arg_hashes.pop(completion_id, None)
