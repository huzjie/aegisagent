"""Bind a tool call back to a real model completion - or refuse to run it.

This is the heart of AegisAgent.  Everything else in the platform is defence in
depth; this module is the actual fix for the CoreBreak class of vulnerabilities
disclosed by the CSA in 2026-08.

Why the ordering below is what it is
------------------------------------
The checks run cheapest-and-most-fundamental first, so that the *reason* a call
is rejected is always the most informative one available:

===  ==========================  =======================================================
#    Outcome                     What it catches
===  ==========================  =======================================================
1    ``UNSIGNED``                No attestation at all - the raw CoreBreak injection.
2    ``FORGED``                  Token is undecodable or the signature does not verify.
3    ``UNTRUSTED_ISSUER``        Signature is valid but minted by a key we do not accept.
4    ``ORPHANED``                Completion id references a model turn that never ran.
                                 *AWS Bedrock AgentCore, CVE-2026-18830 (CVSS 8.6).*
5    ``MISMATCHED``              The completion ran, but it never asked for this tool, or
                                 the arguments were altered after the model produced them.
                                 *Google ADK for Python, CVE-2026-18236 (CVSS 9.3).*
6    ``REPLAYED``                A previously spent nonce was presented again.
                                 *Vercel @ai-sdk/harness-codex, CVE-2026-64650/64651.*
7    ``EXPIRED``                 Structurally sound but stale beyond ``max_age_s``.
8    ``VERIFIED``                Cryptographically bound to a recorded completion.
===  ==========================  =======================================================

Checks 4 and 5 are the ones the vulnerable runtimes skipped entirely.  A valid
signature alone is *not* provenance: the gateway also has to prove the model
turn happened and that it asked for exactly this tool with exactly these
arguments.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.config import Settings, get_settings
from ..core.crypto import Signer, build_signer
from ..core.errors import ValidationError
from ..core.logging import get_logger
from ..core.types import (
    ModelCompletion,
    ProvenanceRecord,
    ProvenanceStatus,
    ToolCall,
    diff_arguments,
    utc_now,
)
from ..core.utils import truncate
from .attestation import (
    ATTESTATION_TYPE,
    Attestation,
    decode_attestation,
    hash_arguments,
    iter_tool_calls,
)
from .replay_guard import ReplayGuard
from .session_ledger import SessionLedger

__all__ = ["ProvenanceVerifier"]

_LOG = get_logger("provenance.verifier")

#: How each terminal status maps onto the CVE it defends against - surfaced in
#: findings, incident tickets and the red-team report.
CVE_REFERENCES: Dict[ProvenanceStatus, List[str]] = {
    ProvenanceStatus.UNSIGNED: ["CVE-2026-18830", "OWASP-LLM06"],
    ProvenanceStatus.FORGED: ["CVE-2026-18830", "CVE-2026-64650", "OWASP-LLM06"],
    ProvenanceStatus.UNTRUSTED_ISSUER: ["CVE-2026-64651"],
    ProvenanceStatus.ORPHANED: ["CVE-2026-18830"],
    ProvenanceStatus.MISMATCHED: ["CVE-2026-18236"],
    ProvenanceStatus.REPLAYED: ["CVE-2026-64650", "CVE-2026-64651"],
    ProvenanceStatus.EXPIRED: ["CVE-2026-64650"],
    ProvenanceStatus.MISSING: ["CVE-2026-18830"],
    ProvenanceStatus.VERIFIED: [],
}


class ProvenanceVerifier:
    """Verifies that a tool call was genuinely authorised by a model completion.

    Parameters
    ----------
    ledger:
        Shared :class:`~aegis.provenance.session_ledger.SessionLedger`.  Must be
        the same instance the :class:`~aegis.provenance.binder.ProvenanceBinder`
        writes to, otherwise every call looks orphaned.
    signer:
        Verification key.  For HMAC this is the *same* key the binder signs
        with; for Ed25519 it is the public half.
    trusted_issuers:
        Issuer names accepted in the ``iss`` claim.  An empty list means
        "accept any issuer", which is only sensible in development.
    require_attestation:
        When False, calls without a token are reported as ``MISSING`` rather
        than ``UNSIGNED`` so a rollout can start in observation mode.
    max_age_s / clock_skew_s:
        Freshness window.  ``clock_skew_s`` also tolerates attestations whose
        ``issued_at`` sits slightly in the future relative to this host.
    """

    def __init__(
        self,
        *,
        ledger: Optional[SessionLedger] = None,
        signer: Optional[Signer] = None,
        settings: Optional[Settings] = None,
        signing_algorithm: str = "hmac-sha256",
        signing_key: str = "",
        key_id: str = "default",
        replay_guard: Optional[ReplayGuard] = None,
        trusted_issuers: Optional[Sequence[str]] = None,
        require_attestation: bool = True,
        max_age_s: float = 300.0,
        clock_skew_s: float = 30.0,
        enforce_session_binding: bool = True,
        mode: str = "enforce",
    ) -> None:
        # ``settings`` supplies the defaults; any explicit keyword still wins, so
        # tests and embedders can override one knob without rebuilding config.
        if settings is not None:
            signing_algorithm = str(
                settings.get("security.signing_algorithm", signing_algorithm)
            )
            signing_key = str(settings.get("security.signing_key", signing_key) or "")
            key_id = str(settings.get("security.signing_key_id", key_id))
            if trusted_issuers is None:
                trusted_issuers = list(settings.get("provenance.trusted_issuers", []) or [])
            require_attestation = bool(
                settings.get("provenance.require_attestation", require_attestation)
            )
            max_age_s = float(settings.get("provenance.max_age_s", max_age_s))
            clock_skew_s = float(settings.get("provenance.clock_skew_s", clock_skew_s))
            mode = str(settings.get("provenance.mode", mode))
            if replay_guard is None:
                replay_guard = ReplayGuard(
                    ttl_s=float(settings.get("provenance.nonce_ttl_s", 900))
                )

        self.settings = settings
        self.ledger = ledger if ledger is not None else SessionLedger()
        self.signer: Signer = signer or build_signer(signing_algorithm, signing_key, key_id)
        self.replay_guard = replay_guard if replay_guard is not None else ReplayGuard(
            ttl_s=max_age_s + clock_skew_s + 600.0
        )
        self.trusted_issuers: List[str] = list(trusted_issuers or [])
        self.require_attestation = bool(require_attestation)
        self.max_age_s = float(max_age_s)
        self.clock_skew_s = float(clock_skew_s)
        self.enforce_session_binding = bool(enforce_session_binding)
        self.mode = str(mode or "enforce").strip().lower()
        self._lock = threading.Lock()
        self._counts: Dict[str, int] = {}

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_settings(
        cls,
        settings: Optional[Settings] = None,
        *,
        ledger: Optional[SessionLedger] = None,
        replay_guard: Optional[ReplayGuard] = None,
    ) -> "ProvenanceVerifier":
        """Build a verifier from the ``provenance`` / ``security`` config sections."""
        return cls(
            ledger=ledger,
            settings=settings or get_settings(),
            replay_guard=replay_guard,
        )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def verify(self, call: ToolCall) -> ProvenanceRecord:
        """Run the full provenance ladder against one tool call.

        Never raises for a *failed* verification - it returns a
        :class:`ProvenanceRecord` describing exactly why the call could not be
        bound.  Enforcement (raising / denying) is the middleware's job, so that
        monitor-mode deployments can observe without breaking traffic.
        """
        now = utc_now()
        observed_hash = hash_arguments(call.arguments)
        record = ProvenanceRecord(
            call_id=call.id,
            status=ProvenanceStatus.MISSING,
            completion_id=call.completion_id,
            signature_algorithm=self.signer.algorithm,
            observed_hash=observed_hash,
            verified_at=now,
        )

        # --- 0a. Quarantined session ------------------------------------ #
        # A frozen session keeps producing calls until the orchestrator notices.
        # We annotate rather than short-circuit: the remaining checks still add
        # forensic value, and the policy layer is what turns this into a verdict.
        if call.session_id and self.ledger.is_quarantined(call.session_id):
            record.reasons.append(
                f"session {call.session_id!r} is quarantined - every call from it is "
                f"suspect until an operator releases the session"
            )

        # --- 0b. Bypass mode -------------------------------------------- #
        # ``provenance.mode: off`` is an explicit operator decision to run without
        # this control (migration / debugging).  It is reported as VERIFIED so the
        # pipeline behaves, but the reason string records that nothing was proven.
        if self.mode == "off":
            return self._finish(
                record,
                ProvenanceStatus.VERIFIED,
                "provenance.mode is 'off' - verification bypassed by configuration; "
                "this call was NOT cryptographically bound to a model completion",
                call,
            )

        # --- 1. No attestation at all ---------------------------------- #
        # The bare CoreBreak primitive: a tool_use block appended to the request
        # by the caller. The model never ran, so nothing ever minted a token.
        if not call.attestation:
            if self.require_attestation:
                return self._finish(
                    record,
                    ProvenanceStatus.UNSIGNED,
                    f"tool call {call.qualified_name!r} carries no attestation while "
                    f"provenance.require_attestation is enabled - it cannot be traced to "
                    f"any model completion",
                    call,
                )
            # Tokens are not mandatory here, so fall back to a weak check: the
            # call still has to name a completion that really exists in the
            # ledger and really emitted this tool.  This is strictly weaker than
            # a signature (anyone who can forge the call can copy a completion
            # id) but it catches the CVE-2026-18830 pattern outright.
            return self._verify_unsigned(record, call, observed_hash)

        # --- 2. Undecodable or unsigned-by-us token -> FORGED ----------- #
        try:
            claims, signature = decode_attestation(call.attestation)
        except ValidationError as exc:
            return self._finish(
                record,
                ProvenanceStatus.FORGED,
                f"attestation token is malformed: {exc.message}",
                call,
            )

        header = claims.get("header", {})
        payload = claims.get("payload", {})
        signing_input = claims.get("signing_input", "")
        record.signature_algorithm = str(header.get("alg", self.signer.algorithm))

        if str(header.get("typ", "")) != ATTESTATION_TYPE:
            return self._finish(
                record,
                ProvenanceStatus.FORGED,
                f"attestation has wrong token type {header.get('typ')!r}; expected "
                f"{ATTESTATION_TYPE!r} (a delegation token must be verified via "
                f"ProvenanceChain, not presented directly)",
                call,
            )

        if not self.signer.verify(signing_input, signature):
            return self._finish(
                record,
                ProvenanceStatus.FORGED,
                "attestation signature does not verify against the gateway key "
                f"(alg={header.get('alg')} kid={header.get('kid')}) - the token was not "
                "minted by this gateway",
                call,
            )

        try:
            att = Attestation.from_subject(payload)
        except ValidationError as exc:
            return self._finish(
                record,
                ProvenanceStatus.FORGED,
                f"attestation payload is not a valid subject: {exc.message}",
                call,
            )

        record.issuer = att.issuer
        record.nonce = att.nonce
        record.issued_at = att.issued_at
        record.bound_hash = att.args_hash
        record.completion_id = att.completion_id or call.completion_id

        # --- 3. Valid signature, unacceptable issuer -------------------- #
        if self.trusted_issuers and att.issuer not in self.trusted_issuers:
            return self._finish(
                record,
                ProvenanceStatus.UNTRUSTED_ISSUER,
                f"attestation issuer {att.issuer!r} is not in the trusted set "
                f"{self.trusted_issuers} - a valid signature from an unauthorised minter "
                f"is still an unauthorised call",
                call,
            )

        # --- 4. The completion never happened -> ORPHANED --------------- #
        # CVE-2026-18830 (AWS Bedrock AgentCore, CVSS 8.6): the event loop
        # dispatched a tool_use block that no model turn had produced.
        if not att.completion_id:
            return self._finish(
                record,
                ProvenanceStatus.ORPHANED,
                "attestation carries no completion_id - there is nothing to trace the "
                "call back to",
                call,
            )
        completion = self.ledger.get_completion(att.completion_id)
        if completion is None:
            return self._finish(
                record,
                ProvenanceStatus.ORPHANED,
                f"completion {att.completion_id!r} is not in the session ledger - the "
                f"model turn that supposedly requested {call.qualified_name!r} never ran "
                f"(CVE-2026-18830 pattern)",
                call,
            )

        if self.enforce_session_binding and att.session_id and call.session_id:
            if att.session_id != call.session_id:
                return self._finish(
                    record,
                    ProvenanceStatus.MISMATCHED,
                    f"attestation was issued for session {att.session_id!r} but the call "
                    f"arrived on session {call.session_id!r} - cross-session token reuse",
                    call,
                )
        if completion.session_id and call.session_id and completion.session_id != call.session_id:
            return self._finish(
                record,
                ProvenanceStatus.MISMATCHED,
                f"completion {att.completion_id!r} belongs to session "
                f"{completion.session_id!r}, not {call.session_id!r}",
                call,
            )

        # --- 5. The completion ran, but not like this -> MISMATCHED ----- #
        # CVE-2026-18236 (Google ADK for Python, CVSS 9.3): the confirmation
        # handler never checked that the tool belonged to the agent, that it
        # actually required confirmation, or that name and arguments still
        # matched the original record.
        mismatch = self._check_against_completion(record, att, call, completion, observed_hash)
        if mismatch is not None:
            return mismatch

        # --- 6. Nonce already spent -> REPLAYED ------------------------- #
        if not self.replay_guard.check_and_consume(att.nonce, att.issued_at):
            return self._finish(
                record,
                ProvenanceStatus.REPLAYED,
                f"attestation nonce {truncate(att.nonce, 32)!r} has already been consumed - "
                f"a single model authorisation may only be redeemed once",
                call,
            )

        # --- 7. Too old (or implausibly future-dated) -> EXPIRED -------- #
        age = now - att.issued_at
        if age > self.max_age_s + self.clock_skew_s:
            return self._finish(
                record,
                ProvenanceStatus.EXPIRED,
                f"attestation is {age:.1f}s old, beyond max_age_s={self.max_age_s:.0f} "
                f"(+{self.clock_skew_s:.0f}s skew tolerance)",
                call,
            )
        if att.is_expired(now, self.clock_skew_s):
            return self._finish(
                record,
                ProvenanceStatus.EXPIRED,
                f"attestation expired at {att.expires_at:.0f} (now {now:.0f}, skew "
                f"tolerance {self.clock_skew_s:.0f}s)",
                call,
            )
        if age < -self.clock_skew_s:
            return self._finish(
                record,
                ProvenanceStatus.EXPIRED,
                f"attestation is dated {-age:.1f}s in the future, beyond the "
                f"{self.clock_skew_s:.0f}s clock-skew tolerance",
                call,
            )

        # --- 8. Fully bound -------------------------------------------- #
        return self._finish(
            record,
            ProvenanceStatus.VERIFIED,
            f"bound to completion {att.completion_id} (turn {att.turn}) issued by "
            f"{att.issuer}; arguments hash {observed_hash[:16]} matches the recorded call",
            call,
        )

    def verify_batch(self, calls: Iterable[ToolCall]) -> List[ProvenanceRecord]:
        """Verify a sequence of calls, preserving input order.

        Useful for parallel tool calls in a single turn: each one carries its own
        nonce, so a batch where two entries share a nonce will correctly report
        the second as ``REPLAYED``.
        """
        return [self.verify(call) for call in calls]

    # ------------------------------------------------------------------ #
    # MISMATCHED analysis
    # ------------------------------------------------------------------ #
    def _verify_unsigned(
        self,
        record: ProvenanceRecord,
        call: ToolCall,
        observed_hash: str,
    ) -> ProvenanceRecord:
        """Weak provenance when attestation is not required.

        The call names a completion id; if that completion is in the ledger and
        actually emitted this tool (with matching arguments) we treat it as the
        closest thing to provenance we can get without a signature.  Otherwise
        it is ORPHANED - the model turn never happened, which is the
        CVE-2026-18830 pattern.
        """
        if not call.completion_id:
            return self._finish(
                record,
                ProvenanceStatus.MISSING,
                "no attestation and no completion_id - the call cannot be traced to "
                "any model turn",
                call,
            )
        completion = self.ledger.get_completion(call.completion_id)
        if completion is None:
            return self._finish(
                record,
                ProvenanceStatus.ORPHANED,
                f"completion {call.completion_id!r} is not in the session ledger - the "
                f"call claims a model turn that never ran (CVE-2026-18830 pattern)",
                call,
            )
        emitted = [
            (name, args)
            for name, args in iter_tool_calls(completion)
            if self._names_match(name, call.qualified_name) or self._names_match(name, call.tool)
        ]
        if not emitted:
            return self._finish(
                record,
                ProvenanceStatus.MISMATCHED,
                f"completion {call.completion_id!r} never requested {call.qualified_name!r}",
                call,
            )
        recorded_hashes = [hash_arguments(args) for _, args in emitted]
        if observed_hash not in recorded_hashes:
            return self._finish(
                record,
                ProvenanceStatus.MISMATCHED,
                f"arguments for {call.qualified_name!r} differ from the completion "
                f"{call.completion_id!r} record (weak-check)",
                call,
                evidence=self._argument_evidence(emitted[0][1], call.arguments),
            )
        return self._finish(
            record,
            ProvenanceStatus.VERIFIED,
            f"weakly bound to completion {call.completion_id!r} via ledger lookup "
            f"(no signature - require_attestation is disabled)",
            call,
        )

    def _check_against_completion(
        self,
        record: ProvenanceRecord,
        att: Attestation,
        call: ToolCall,
        completion: ModelCompletion,
        observed_hash: str,
    ) -> Optional[ProvenanceRecord]:
        """Cross-check the token, the live call and the recorded completion.

        Returns a finished ``MISMATCHED`` record, or ``None`` when the three
        views agree.
        """
        # 5a. Does the token even describe the tool being dispatched?
        if not self._same_tool(att.tool, call):
            return self._finish(
                record,
                ProvenanceStatus.MISMATCHED,
                f"attestation authorises tool {att.tool!r} but the dispatched call is "
                f"{call.qualified_name!r} - a token issued for one tool is being replayed "
                f"onto another (CVE-2026-18236 pattern)",
                call,
            )

        # 5b. Were the arguments altered after the token was minted?
        if att.args_hash != observed_hash:
            recorded_args = self._recorded_arguments(completion, att.tool)
            return self._finish(
                record,
                ProvenanceStatus.MISMATCHED,
                f"argument hash mismatch for {call.qualified_name!r}: attested "
                f"{att.args_hash[:16]} but observed {observed_hash[:16]} - the arguments "
                f"were modified after the model authorised them",
                call,
                evidence=self._argument_evidence(recorded_args, call.arguments),
            )

        # 5c. Did this completion actually emit that tool?
        emitted = iter_tool_calls(completion)
        names = [name for name, _ in emitted if name]
        if not any(self._names_match(name, att.tool) for name in names):
            return self._finish(
                record,
                ProvenanceStatus.MISMATCHED,
                f"completion {completion.id!r} emitted {names or ['<no tool calls>']} - "
                f"it never requested {att.tool!r}",
                call,
            )

        # 5d. Do the arguments still match what the model actually produced?
        candidates = [
            (name, args) for name, args in emitted if self._names_match(name, att.tool)
        ]
        recorded_hashes = [hash_arguments(args) for _, args in candidates]
        if observed_hash not in recorded_hashes:
            expected_args = candidates[0][1] if candidates else {}
            return self._finish(
                record,
                ProvenanceStatus.MISMATCHED,
                f"arguments for {att.tool!r} differ from every variant recorded on "
                f"completion {completion.id!r} (observed {observed_hash[:16]}, recorded "
                f"{[h[:16] for h in recorded_hashes]})",
                call,
                evidence=self._argument_evidence(expected_args, call.arguments),
            )

        # 5e. Turn consistency - a token from turn 3 must not drive turn 7.
        if att.turn and completion.turn and att.turn != completion.turn:
            return self._finish(
                record,
                ProvenanceStatus.MISMATCHED,
                f"attestation claims turn {att.turn} but completion {completion.id!r} was "
                f"turn {completion.turn}",
                call,
            )
        return None

    @staticmethod
    def _names_match(recorded: str, attested: str) -> bool:
        """Tolerate ``server::tool`` vs bare ``tool`` naming on either side."""
        if not recorded or not attested:
            return False
        if recorded == attested:
            return True
        return recorded.split("::")[-1] == attested.split("::")[-1]

    @classmethod
    def _same_tool(cls, attested: str, call: ToolCall) -> bool:
        return cls._names_match(call.tool, attested) or cls._names_match(
            call.qualified_name, attested
        )

    @classmethod
    def _recorded_arguments(cls, completion: ModelCompletion, tool: str) -> Dict[str, Any]:
        for name, args in iter_tool_calls(completion):
            if cls._names_match(name, tool):
                return args
        return {}

    @staticmethod
    def _argument_evidence(
        expected: Dict[str, Any], observed: Dict[str, Any]
    ) -> List[str]:
        """Render :func:`diff_arguments` output as reviewer-friendly evidence."""
        diffs = diff_arguments(expected or {}, observed or {})
        if not diffs:
            return ["arguments are structurally identical but hash differently "
                    "(check for non-canonical encoding or duplicate keys)"]
        lines = [f"{len(diffs)} argument(s) differ from the recorded tool call:"]
        for key, want, got in diffs[:12]:
            lines.append(
                f"  - {key}: recorded={truncate(repr(want), 120)} "
                f"observed={truncate(repr(got), 120)}"
            )
        if len(diffs) > 12:
            lines.append(f"  … and {len(diffs) - 12} more")
        return lines

    # ------------------------------------------------------------------ #
    # Result assembly
    # ------------------------------------------------------------------ #
    def _finish(
        self,
        record: ProvenanceRecord,
        status: ProvenanceStatus,
        reason: str,
        call: ToolCall,
        *,
        evidence: Optional[Sequence[str]] = None,
    ) -> ProvenanceRecord:
        """Stamp the terminal status, reasons and CVE references onto a record."""
        record.status = status
        record.verified_at = utc_now()
        record.reasons.append(reason)
        if evidence:
            record.reasons.extend(evidence)
        references = CVE_REFERENCES.get(status, [])
        if status is not ProvenanceStatus.VERIFIED and references:
            record.reasons.append("defends: " + ", ".join(references))

        with self._lock:
            self._counts[status.value] = self._counts.get(status.value, 0) + 1

        if status is not ProvenanceStatus.VERIFIED:
            _LOG.warning(
                "provenance check failed",
                fields={
                    "status": status.value,
                    "call_id": call.id,
                    "session_id": call.session_id,
                    "tool": call.qualified_name,
                    "completion_id": record.completion_id,
                    "risk": status.risk.value,
                },
            )
        return record

    # ------------------------------------------------------------------ #
    # Reporting
    # ------------------------------------------------------------------ #
    def explain(self, record: ProvenanceRecord) -> str:
        """Render a provenance record as a short multi-line incident summary."""
        header = (
            f"[{record.status.value.upper()}] call={record.call_id or '<unknown>'} "
            f"risk={record.status.risk.value} completion={record.completion_id or '<none>'}"
        )
        lines = [header]
        if record.issuer:
            lines.append(f"  issuer     : {record.issuer} (alg={record.signature_algorithm})")
        if record.bound_hash or record.observed_hash:
            lines.append(
                f"  args       : attested={record.bound_hash[:16] or '-'} "
                f"observed={record.observed_hash[:16] or '-'}"
            )
        if record.nonce:
            lines.append(f"  nonce      : {truncate(record.nonce, 40)}")
        if record.issued_at:
            lines.append(
                f"  freshness  : issued {max(0.0, record.verified_at - record.issued_at):.1f}s "
                f"before verification"
            )
        for reason in record.reasons:
            lines.append(f"  · {reason}" if not reason.startswith("  ") else reason)
        if record.status.is_trustworthy:
            lines.append("  verdict    : bound to a recorded model completion - safe to dispatch")
        else:
            lines.append(
                "  verdict    : NOT bound to any recorded model completion - dispatching "
                "would reproduce the CoreBreak vulnerability class"
            )
        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        """Verification counters plus the effective configuration."""
        with self._lock:
            counts = dict(self._counts)
        total = sum(counts.values())
        verified = counts.get(ProvenanceStatus.VERIFIED.value, 0)
        return {
            "total": total,
            "verified": verified,
            "verified_rate": round(verified / total, 4) if total else 0.0,
            "by_status": counts,
            "require_attestation": self.require_attestation,
            "trusted_issuers": list(self.trusted_issuers),
            "max_age_s": self.max_age_s,
            "clock_skew_s": self.clock_skew_s,
            "replay": self.replay_guard.stats(),
        }

    def reset_stats(self) -> None:
        """Zero the counters (used between red-team scenarios)."""
        with self._lock:
            self._counts.clear()

    def summarize(self, records: Sequence[ProvenanceRecord]) -> Dict[str, Any]:
        """Aggregate a batch of records for reporting."""
        by_status: Dict[str, int] = {}
        worst: Tuple[int, str] = (0, ProvenanceStatus.VERIFIED.value)
        for record in records:
            by_status[record.status.value] = by_status.get(record.status.value, 0) + 1
            score = record.status.risk.score
            if score > worst[0]:
                worst = (score, record.status.value)
        return {
            "total": len(records),
            "trustworthy": sum(1 for r in records if r.trustworthy),
            "by_status": by_status,
            "worst_status": worst[1],
        }
