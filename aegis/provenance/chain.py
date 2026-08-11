"""Multi-hop provenance for sub-agent delegation.

A single attestation answers "did the model ask for this?".  Once agents start
spawning agents, that is no longer enough - you also need to answer "and was the
agent that is asking actually allowed to ask, by someone who was allowed to
delegate?".

``ProvenanceChain`` builds a *delegation chain*: agent A holds an attestation for
``deploy::rollout``; it hands agent B a narrower, signed delegation token; B may
hand C something narrower still.  Every link records its parent verbatim, so the
whole chain can be replayed from any leaf back to the original model completion.

Three invariants are enforced on every hop:

1. **Depth** - chains longer than ``max_depth`` are rejected outright.  Unbounded
   delegation is how a low-trust research agent quietly acquires production
   credentials.
2. **Monotonic narrowing** - a child's scope must be a subset of its parent's.
   Privilege can only shrink as it travels down the chain.
3. **Non-extending lifetime** - a child token may not outlive its parent, so
   revoking the root revokes the subtree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.crypto import Signer, build_signer, random_nonce
from ..core.errors import ProvenanceError, ValidationError
from ..core.logging import get_logger
from ..core.types import ProvenanceRecord, ProvenanceStatus, utc_now
from ..core.utils import glob_match
from .attestation import (
    ATTESTATION_TYPE,
    DELEGATION_TYPE,
    Attestation,
    decode_envelope,
    encode_envelope,
)
from .session_ledger import SessionLedger

__all__ = ["DelegationLink", "delegation_subject", "ProvenanceChain"]

_LOG = get_logger("provenance.chain")

MAX_CHAIN_DEPTH = 4


@dataclass
class DelegationLink:
    """One hop in a delegation chain, signed by the gateway."""

    version: str = "1"
    issuer: str = "aegis-gateway"
    parent_token: str = ""
    parent_agent: str = ""
    child_agent: str = ""
    session_id: str = ""
    scope: List[str] = field(default_factory=list)
    depth: int = 1
    nonce: str = field(default_factory=random_nonce)
    issued_at: float = field(default_factory=utc_now)
    expires_at: float = 0.0
    key_id: str = "default"
    reason: str = ""

    def is_expired(self, now: Optional[float] = None, clock_skew_s: float = 0.0) -> bool:
        """True when this hop is past its validity window."""
        return (now if now is not None else utc_now()) > self.expires_at + max(0.0, clock_skew_s)

    @classmethod
    def from_subject(cls, subject: Dict[str, Any]) -> "DelegationLink":
        """Rebuild a link from a decoded token payload."""
        if not isinstance(subject, dict):
            raise ValidationError("delegation subject must be a mapping")
        try:
            return cls(
                version=str(subject.get("v", "1")),
                issuer=str(subject.get("iss", "")),
                parent_token=str(subject.get("parent", "")),
                parent_agent=str(subject.get("pag", "")),
                child_agent=str(subject.get("cag", "")),
                session_id=str(subject.get("sid", "")),
                scope=[str(s) for s in (subject.get("scope") or [])],
                depth=int(subject.get("depth", 1) or 1),
                nonce=str(subject.get("nonce", "")),
                issued_at=float(subject.get("iat", 0.0)),
                expires_at=float(subject.get("exp", 0.0)),
                key_id=str(subject.get("kid", "default")),
                reason=str(subject.get("why", "")),
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"malformed delegation subject: {exc}", cause=exc) from exc


def delegation_subject(link: DelegationLink) -> Dict[str, Any]:
    """Canonical, signature-covered subject of a delegation link."""
    return {
        "v": link.version,
        "iss": link.issuer,
        "parent": link.parent_token,
        "pag": link.parent_agent,
        "cag": link.child_agent,
        "sid": link.session_id,
        "scope": sorted(link.scope),
        "depth": int(link.depth),
        "nonce": link.nonce,
        "iat": round(float(link.issued_at), 6),
        "exp": round(float(link.expires_at), 6),
        "kid": link.key_id,
        "why": link.reason,
    }


def scope_covers(parent_scope: Sequence[str], candidate: str) -> bool:
    """True when ``candidate`` falls inside at least one parent scope pattern."""
    return any(glob_match(candidate, pattern) for pattern in parent_scope or [])


def narrows(parent_scope: Sequence[str], child_scope: Sequence[str]) -> Tuple[bool, List[str]]:
    """Check that every child scope entry is covered by the parent.

    Returns ``(ok, offending_entries)``.  An empty child scope is treated as an
    error rather than "inherit everything": silent inheritance is how delegation
    chains accidentally widen.
    """
    if not child_scope:
        return False, ["<empty>"]
    offenders = [entry for entry in child_scope if not scope_covers(parent_scope, entry)]
    return (not offenders), offenders


class ProvenanceChain:
    """Issues and verifies delegation chains rooted at a real attestation.

    Parameters
    ----------
    signer:
        Key used to sign and verify every hop.  Same key material as the
        attestation binder.
    ledger:
        Optional session ledger.  When supplied, the root attestation is also
        checked against a recorded completion, so a chain cannot be rooted in a
        completion that never ran.
    max_depth:
        Hard cap on chain length, counted in delegation hops (the root
        attestation is depth 0).
    trusted_issuers:
        Accepted ``iss`` values across every hop.
    """

    def __init__(
        self,
        *,
        signer: Optional[Signer] = None,
        signing_algorithm: str = "hmac-sha256",
        signing_key: str = "",
        key_id: str = "default",
        ledger: Optional[SessionLedger] = None,
        issuer: str = "aegis-gateway",
        max_depth: int = MAX_CHAIN_DEPTH,
        trusted_issuers: Optional[Sequence[str]] = None,
        clock_skew_s: float = 30.0,
        default_ttl_s: float = 300.0,
    ) -> None:
        self.signer: Signer = signer or build_signer(signing_algorithm, signing_key, key_id)
        self.ledger = ledger
        self.issuer = issuer or "aegis-gateway"
        self.max_depth = max(1, int(max_depth))
        self.trusted_issuers = list(trusted_issuers or [])
        self.clock_skew_s = float(clock_skew_s)
        self.default_ttl_s = float(default_ttl_s)

    # ------------------------------------------------------------------ #
    # Issuing
    # ------------------------------------------------------------------ #
    def delegate(
        self,
        parent_att: str,
        child_agent: str,
        scope: Sequence[str],
        *,
        ttl_s: Optional[float] = None,
        reason: str = "",
    ) -> str:
        """Mint a delegation token for ``child_agent``, narrowed to ``scope``.

        ``parent_att`` may be either a root attestation token or another
        delegation token, which is how chains longer than two hops are built.

        Raises
        ------
        ProvenanceError
            When the parent cannot be verified, the depth cap would be exceeded,
            or the requested scope is not a subset of the parent's.
        """
        if not child_agent:
            raise ProvenanceError("delegation requires a child agent identity")
        parent_kind, parent_payload = self._decode_verified(parent_att)

        if parent_kind == ATTESTATION_TYPE:
            parent = Attestation.from_subject(parent_payload)
            parent_scope = [parent.tool] if parent.tool else []
            parent_agent = parent.agent_id
            session_id = parent.session_id
            parent_expiry = parent.expires_at
            depth = 1
        else:
            parent_link = DelegationLink.from_subject(parent_payload)
            parent_scope = list(parent_link.scope)
            parent_agent = parent_link.child_agent
            session_id = parent_link.session_id
            parent_expiry = parent_link.expires_at
            depth = parent_link.depth + 1

        if depth > self.max_depth:
            raise ProvenanceError(
                f"delegation depth {depth} exceeds max_depth={self.max_depth}",
                details={"depth": depth, "max_depth": self.max_depth},
            )

        requested = [str(s) for s in scope]
        ok, offenders = narrows(parent_scope, requested)
        if not ok:
            raise ProvenanceError(
                f"delegated scope must narrow the parent scope {parent_scope}; "
                f"{offenders} are not covered",
                details={"parent_scope": list(parent_scope), "offenders": offenders},
            )

        now = utc_now()
        lifetime = float(ttl_s if ttl_s is not None else self.default_ttl_s)
        expires_at = now + max(1.0, lifetime)
        if parent_expiry > 0:
            # A child may never outlive its parent.
            expires_at = min(expires_at, parent_expiry)
        if expires_at <= now:
            raise ProvenanceError(
                "parent authorisation has already expired - nothing left to delegate"
            )

        link = DelegationLink(
            issuer=self.issuer,
            parent_token=parent_att,
            parent_agent=parent_agent,
            child_agent=child_agent,
            session_id=session_id,
            scope=requested,
            depth=depth,
            nonce=random_nonce(),
            issued_at=now,
            expires_at=expires_at,
            key_id=self.signer.key_id,
            reason=reason,
        )
        _LOG.debug(
            "issued delegation",
            fields={
                "parent_agent": parent_agent,
                "child_agent": child_agent,
                "depth": depth,
                "scope": requested,
            },
        )
        return encode_envelope(
            delegation_subject(link), self.signer, typ=DELEGATION_TYPE, key_id=self.signer.key_id
        )

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    def verify_chain(self, token: str) -> List[ProvenanceRecord]:
        """Walk a delegation chain from leaf to root and audit every hop.

        Returns one :class:`ProvenanceRecord` per hop, ordered **root first**.
        The chain as a whole is trustworthy only when every record is; use
        :meth:`chain_ok` for the boolean shortcut.

        Verification never raises for a bad chain - a malformed hop yields a
        ``FORGED`` record so callers get the full picture instead of the first
        exception.
        """
        hops: List[Tuple[str, Dict[str, Any], bool, str]] = []
        cursor = token
        guard = 0
        records: List[ProvenanceRecord] = []

        while cursor:
            guard += 1
            if guard > self.max_depth + 2:
                records.append(
                    self._record(
                        ProvenanceStatus.FORGED,
                        "chain-overflow",
                        f"delegation chain longer than max_depth={self.max_depth} - refusing "
                        f"to unwind further (possible token-cycling attack)",
                    )
                )
                break
            try:
                claims, signature = decode_envelope(cursor)
            except ValidationError as exc:
                records.append(
                    self._record(ProvenanceStatus.FORGED, "undecodable", f"hop is not decodable: {exc.message}")
                )
                break
            header = claims["header"]
            payload = claims["payload"]
            verified = self.signer.verify(claims["signing_input"], signature)
            typ = str(header.get("typ", ""))
            hops.append((typ, payload, verified, cursor))
            if typ == DELEGATION_TYPE:
                cursor = str(payload.get("parent") or "")
                if not cursor:
                    records.append(
                        self._record(
                            ProvenanceStatus.ORPHANED,
                            str(payload.get("cag", "")),
                            "delegation link has no parent token - the chain is not rooted "
                            "in any model completion",
                        )
                    )
                    break
            else:
                break

        if not hops:
            if not records:
                records.append(
                    self._record(ProvenanceStatus.FORGED, "empty", "no verifiable hops in token")
                )
            return records

        # hops[-1] is the root; walk root -> leaf so scope narrowing reads naturally.
        ordered = list(reversed(hops))
        chain_records: List[ProvenanceRecord] = []
        parent_scope: List[str] = []
        parent_expiry = 0.0
        parent_child_agent = ""

        for index, (typ, payload, verified, _raw) in enumerate(ordered):
            if index == 0:
                record, parent_scope, parent_expiry, parent_child_agent = self._verify_root(
                    typ, payload, verified
                )
                chain_records.append(record)
                continue
            record, parent_scope, parent_expiry, parent_child_agent = self._verify_hop(
                typ, payload, verified, index, parent_scope, parent_expiry, parent_child_agent
            )
            chain_records.append(record)

        return chain_records + records

    def _verify_root(
        self, typ: str, payload: Dict[str, Any], verified: bool
    ) -> Tuple[ProvenanceRecord, List[str], float, str]:
        """Audit the root attestation of a chain."""
        if typ != ATTESTATION_TYPE:
            return (
                self._record(
                    ProvenanceStatus.FORGED,
                    "root",
                    f"chain root has type {typ!r}; a chain must be rooted in a real "
                    f"{ATTESTATION_TYPE} attestation",
                ),
                [],
                0.0,
                "",
            )
        if not verified:
            return (
                self._record(
                    ProvenanceStatus.FORGED, "root", "root attestation signature does not verify"
                ),
                [],
                0.0,
                "",
            )
        try:
            att = Attestation.from_subject(payload)
        except ValidationError as exc:
            return (
                self._record(ProvenanceStatus.FORGED, "root", f"root payload invalid: {exc.message}"),
                [],
                0.0,
                "",
            )

        record = ProvenanceRecord(
            call_id=f"root:{att.agent_id or att.session_id or 'unknown'}",
            completion_id=att.completion_id,
            issuer=att.issuer,
            signature_algorithm=self.signer.algorithm,
            bound_hash=att.args_hash,
            issued_at=att.issued_at,
            nonce=att.nonce,
            status=ProvenanceStatus.VERIFIED,
        )
        if self.trusted_issuers and att.issuer not in self.trusted_issuers:
            record.status = ProvenanceStatus.UNTRUSTED_ISSUER
            record.reasons.append(
                f"root issuer {att.issuer!r} is not trusted {self.trusted_issuers}"
            )
        elif self.ledger is not None and self.ledger.get_completion(att.completion_id) is None:
            record.status = ProvenanceStatus.ORPHANED
            record.reasons.append(
                f"root completion {att.completion_id!r} is absent from the session ledger - "
                f"the chain is rooted in a model turn that never ran (CVE-2026-18830)"
            )
        elif att.is_expired(clock_skew_s=self.clock_skew_s):
            record.status = ProvenanceStatus.EXPIRED
            record.reasons.append("root attestation has expired")
        else:
            record.reasons.append(
                f"root attestation authorises {att.tool!r} for completion {att.completion_id}"
            )
        return record, ([att.tool] if att.tool else []), att.expires_at, att.agent_id

    def _verify_hop(
        self,
        typ: str,
        payload: Dict[str, Any],
        verified: bool,
        index: int,
        parent_scope: List[str],
        parent_expiry: float,
        parent_child_agent: str,
    ) -> Tuple[ProvenanceRecord, List[str], float, str]:
        """Audit one delegation hop against its parent."""
        if typ != DELEGATION_TYPE:
            return (
                self._record(
                    ProvenanceStatus.FORGED, f"hop{index}", f"unexpected hop type {typ!r}"
                ),
                parent_scope,
                parent_expiry,
                parent_child_agent,
            )
        if not verified:
            return (
                self._record(
                    ProvenanceStatus.FORGED,
                    f"hop{index}",
                    "delegation signature does not verify - the link was not minted by this gateway",
                ),
                parent_scope,
                parent_expiry,
                parent_child_agent,
            )
        try:
            link = DelegationLink.from_subject(payload)
        except ValidationError as exc:
            return (
                self._record(ProvenanceStatus.FORGED, f"hop{index}", f"invalid link: {exc.message}"),
                parent_scope,
                parent_expiry,
                parent_child_agent,
            )

        record = ProvenanceRecord(
            call_id=f"{link.child_agent}@depth{link.depth}",
            issuer=link.issuer,
            signature_algorithm=self.signer.algorithm,
            issued_at=link.issued_at,
            nonce=link.nonce,
            status=ProvenanceStatus.VERIFIED,
        )
        problems: List[str] = []

        if self.trusted_issuers and link.issuer not in self.trusted_issuers:
            record.status = ProvenanceStatus.UNTRUSTED_ISSUER
            problems.append(f"hop issuer {link.issuer!r} is not trusted {self.trusted_issuers}")
        if link.depth != index:
            problems.append(
                f"declared depth {link.depth} does not match its position {index} in the chain"
            )
            record.status = ProvenanceStatus.MISMATCHED
        if link.depth > self.max_depth:
            problems.append(f"depth {link.depth} exceeds max_depth={self.max_depth}")
            record.status = ProvenanceStatus.MISMATCHED
        if parent_child_agent and link.parent_agent and link.parent_agent != parent_child_agent:
            problems.append(
                f"link claims parent agent {link.parent_agent!r} but the previous hop "
                f"delegated to {parent_child_agent!r}"
            )
            record.status = ProvenanceStatus.MISMATCHED

        ok, offenders = narrows(parent_scope, link.scope)
        if not ok:
            problems.append(
                f"scope escalation: {offenders} are not covered by the parent scope "
                f"{parent_scope} - a sub-agent may never gain privilege its delegator lacked"
            )
            record.status = ProvenanceStatus.MISMATCHED
        if parent_expiry > 0 and link.expires_at > parent_expiry + self.clock_skew_s:
            problems.append(
                f"lifetime extension: hop expires at {link.expires_at:.0f} but its parent "
                f"expires at {parent_expiry:.0f}"
            )
            record.status = ProvenanceStatus.MISMATCHED
        if link.is_expired(clock_skew_s=self.clock_skew_s):
            problems.append("delegation hop has expired")
            if record.status is ProvenanceStatus.VERIFIED:
                record.status = ProvenanceStatus.EXPIRED

        if problems:
            record.reasons.extend(problems)
        else:
            record.reasons.append(
                f"{link.parent_agent or '<root>'} -> {link.child_agent} scoped to {link.scope}"
            )
        effective_scope = link.scope if ok else parent_scope
        effective_expiry = min(link.expires_at, parent_expiry) if parent_expiry else link.expires_at
        return record, list(effective_scope), effective_expiry, link.child_agent

    # ------------------------------------------------------------------ #
    # Convenience
    # ------------------------------------------------------------------ #
    def chain_ok(self, token: str) -> bool:
        """True when every hop of the chain verifies."""
        records = self.verify_chain(token)
        return bool(records) and all(r.trustworthy for r in records)

    def effective_scope(self, token: str) -> List[str]:
        """Scope granted by the leaf of the chain, or ``[]`` when it is invalid."""
        try:
            typ, payload = self._decode_verified(token)
        except ProvenanceError:
            return []
        if typ == ATTESTATION_TYPE:
            att = Attestation.from_subject(payload)
            return [att.tool] if att.tool else []
        link = DelegationLink.from_subject(payload)
        return list(link.scope)

    def authorizes(self, token: str, tool: str) -> bool:
        """True when the chain is valid *and* its leaf scope covers ``tool``."""
        if not self.chain_ok(token):
            return False
        return scope_covers(self.effective_scope(token), tool)

    def describe(self, token: str) -> str:
        """Render a chain as an indented, reviewer-friendly tree."""
        records = self.verify_chain(token)
        lines = [f"delegation chain ({len(records)} hop(s)):"]
        for depth, record in enumerate(records):
            marker = "OK " if record.trustworthy else "!! "
            indent = "  " * (depth + 1)
            lines.append(f"{indent}{marker}[{record.status.value}] {record.call_id}")
            for reason in record.reasons:
                lines.append(f"{indent}    - {reason}")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _decode_verified(self, token: str) -> Tuple[str, Dict[str, Any]]:
        """Decode a token and assert its signature, returning ``(typ, payload)``."""
        try:
            claims, signature = decode_envelope(token)
        except ValidationError as exc:
            raise ProvenanceError(f"token is not decodable: {exc.message}", cause=exc) from exc
        if not self.signer.verify(claims["signing_input"], signature):
            raise ProvenanceError("token signature does not verify")
        typ = str(claims["header"].get("typ", ""))
        if typ not in (ATTESTATION_TYPE, DELEGATION_TYPE):
            raise ProvenanceError(f"unsupported token type {typ!r}")
        return typ, claims["payload"]

    @staticmethod
    def _record(status: ProvenanceStatus, call_id: str, reason: str) -> ProvenanceRecord:
        record = ProvenanceRecord(call_id=call_id, status=status)
        record.reasons.append(reason)
        return record
