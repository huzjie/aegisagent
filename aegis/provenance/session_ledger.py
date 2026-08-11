"""Append-only, hash-chained ledger of everything that happened in a session.

The ledger is the *ground truth* a provenance verifier consults when it asks the
only question that matters:

    "Did a model completion in this session really emit this tool call?"

Every entry is linked to its predecessor with ``chain_hash(prev, payload)`` so an
attacker who gains write access cannot retro-fit a completion record to justify
a tool call they injected - rewriting history breaks the chain and
:meth:`SessionLedger.verify_chain` reports the exact broken link.

The ledger is deliberately *not* the audit ledger: it is hot, per-session state
optimised for the verification path.  Durable, tenant-wide auditing lives in
``aegis.audit``.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..core.crypto import chain_hash
from ..core.logging import get_logger
from ..core.types import (
    ModelCompletion,
    ToolCall,
    ToolResult,
    to_dict,
    utc_now,
)
from .attestation import hash_arguments, iter_tool_calls

__all__ = ["LedgerEntry", "SessionLedger"]

_LOG = get_logger("provenance.ledger")

GENESIS_HASH = "0" * 64

EVENT_COMPLETION = "completion"
EVENT_CALL = "call"
EVENT_RESULT = "result"
EVENT_QUARANTINE = "quarantine"


class LedgerEntry(dict):
    """A single chained ledger record.

    Implemented as a ``dict`` subclass so entries serialise straight to JSONL
    while still offering attribute-style helpers for the hot fields.
    """

    @property
    def sequence(self) -> int:
        return int(self.get("seq", 0))

    @property
    def kind(self) -> str:
        return str(self.get("type", ""))

    @property
    def hash(self) -> str:
        return str(self.get("hash", ""))

    @property
    def prev_hash(self) -> str:
        return str(self.get("prev_hash", ""))

    @property
    def payload(self) -> Dict[str, Any]:
        body = self.get("payload")
        return body if isinstance(body, dict) else {}


class SessionLedger:
    """Thread-safe, append-only session event log with a per-session hash chain.

    Parameters
    ----------
    persist_path:
        Optional JSONL file.  Every appended entry is flushed immediately so a
        crash cannot silently drop the evidence that would have exposed a
        forged tool call.
    max_entries_per_session:
        Soft cap used to bound memory in long-running gateways.  When exceeded
        the *oldest* entries are dropped from memory but the running chain head
        is preserved, so :meth:`verify_chain` reports a truncated - not broken -
        chain.
    """

    def __init__(
        self,
        *,
        persist_path: Optional[str] = None,
        max_entries_per_session: int = 5000,
    ) -> None:
        self._lock = threading.RLock()
        self._entries: Dict[str, List[LedgerEntry]] = {}
        self._heads: Dict[str, str] = {}
        self._sequence: Dict[str, int] = {}
        self._truncated: Dict[str, int] = {}
        self._completions: Dict[str, ModelCompletion] = {}
        self._completion_index: Dict[str, List[str]] = {}
        self._arg_hashes: Dict[str, Dict[str, str]] = {}
        self._quarantined: Dict[str, float] = {}
        self.max_entries_per_session = max(64, int(max_entries_per_session))
        self._persist_path: Optional[Path] = Path(persist_path) if persist_path else None
        if self._persist_path is not None:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Append path
    # ------------------------------------------------------------------ #
    def _append(self, session_id: str, kind: str, payload: Dict[str, Any]) -> LedgerEntry:
        """Append one chained entry.  Caller must already hold the lock."""
        session_id = session_id or "unknown"
        seq = self._sequence.get(session_id, 0) + 1
        prev = self._heads.get(session_id, GENESIS_HASH)
        body = {
            "seq": seq,
            "type": kind,
            "ts": utc_now(),
            "session_id": session_id,
            "payload": payload,
        }
        entry = LedgerEntry(body)
        entry["prev_hash"] = prev
        entry["hash"] = chain_hash(prev, body)

        bucket = self._entries.setdefault(session_id, [])
        bucket.append(entry)
        overflow = len(bucket) - self.max_entries_per_session
        if overflow > 0:
            del bucket[:overflow]
            self._truncated[session_id] = self._truncated.get(session_id, 0) + overflow

        self._sequence[session_id] = seq
        self._heads[session_id] = entry["hash"]
        self._persist(entry)
        return entry

    def _persist(self, entry: LedgerEntry) -> None:
        if self._persist_path is None:
            return
        try:
            with self._persist_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except OSError as exc:  # pragma: no cover - degraded but non-fatal
            _LOG.warning("could not persist ledger entry: %s", exc)

    # ------------------------------------------------------------------ #
    # Recording
    # ------------------------------------------------------------------ #
    def record_completion(self, completion: ModelCompletion) -> LedgerEntry:
        """Register a model turn and pre-hash the arguments of its tool calls.

        Pre-hashing here means the verification path never has to re-serialise
        provider payloads, and the hashes are captured *before* any downstream
        component has had a chance to mutate them.
        """
        with self._lock:
            self._completions[completion.id] = completion
            self._completion_index.setdefault(completion.session_id, []).append(completion.id)
            hashes: Dict[str, str] = {}
            for name, args in iter_tool_calls(completion):
                if name:
                    hashes[name] = hash_arguments(args)
            self._arg_hashes[completion.id] = hashes
            return self._append(
                completion.session_id,
                EVENT_COMPLETION,
                {
                    "completion_id": completion.id,
                    "turn": completion.turn,
                    "model": completion.model,
                    "provider": completion.provider,
                    "finish_reason": completion.finish_reason,
                    "tool_calls": [
                        {"tool": name, "args_hash": hash_arguments(args)}
                        for name, args in iter_tool_calls(completion)
                    ],
                    "response_hash": completion.response_hash,
                },
            )

    def record_call(self, call: ToolCall) -> LedgerEntry:
        """Register an attempted tool invocation."""
        with self._lock:
            return self._append(
                call.session_id,
                EVENT_CALL,
                {
                    "call_id": call.id,
                    "tool": call.tool,
                    "server": call.server,
                    "qualified_name": call.qualified_name,
                    "agent_id": call.agent_id,
                    "completion_id": call.completion_id,
                    "turn": call.turn,
                    "source": call.source,
                    "args_hash": hash_arguments(call.arguments),
                    "has_attestation": bool(call.attestation),
                },
            )

    def record_result(self, result: ToolResult, *, session_id: str = "") -> LedgerEntry:
        """Register the outcome of a tool invocation.

        ``session_id`` may be omitted when the originating call is already in the
        ledger - it is then resolved from the recorded call entry.
        """
        with self._lock:
            resolved = session_id or self._session_for_call(result.call_id) or "unknown"
            return self._append(
                resolved,
                EVENT_RESULT,
                {
                    "call_id": result.call_id,
                    "ok": result.ok,
                    "error": result.error,
                    "duration_ms": result.duration_ms,
                    "redacted": result.redacted,
                    "truncated": result.truncated,
                    "bytes_out": result.bytes_out,
                },
            )

    def _session_for_call(self, call_id: str) -> Optional[str]:
        for session_id, entries in self._entries.items():
            for entry in reversed(entries):
                if entry.kind == EVENT_CALL and entry.payload.get("call_id") == call_id:
                    return session_id
        return None

    # ------------------------------------------------------------------ #
    # Lookups
    # ------------------------------------------------------------------ #
    def get_completion(self, completion_id: str) -> Optional[ModelCompletion]:
        """Return a recorded completion, or ``None`` when it never happened.

        A ``None`` here is the signal for ``ProvenanceStatus.ORPHANED`` - the
        exact condition exploited by CVE-2026-18830.
        """
        with self._lock:
            return self._completions.get(completion_id or "")

    def argument_hashes(self, completion_id: str) -> Dict[str, str]:
        """Pre-computed ``tool -> args_hash`` map for a recorded completion."""
        with self._lock:
            return dict(self._arg_hashes.get(completion_id or "", {}))

    def completions_for(self, session_id: str) -> List[ModelCompletion]:
        """All completions recorded for a session, oldest first."""
        with self._lock:
            ids = list(self._completion_index.get(session_id, []))
            return [self._completions[i] for i in ids if i in self._completions]

    def entries(self, session_id: str) -> List[LedgerEntry]:
        """Immutable snapshot of a session's chained entries."""
        with self._lock:
            return list(self._entries.get(session_id, []))

    def recent_tools(self, session_id: str, n: int = 20) -> List[str]:
        """Names of the last ``n`` tools invoked in a session, oldest first."""
        with self._lock:
            entries = self._entries.get(session_id, [])
            names = [
                str(e.payload.get("qualified_name") or e.payload.get("tool") or "")
                for e in entries
                if e.kind == EVENT_CALL
            ]
        return [name for name in names if name][-max(0, int(n)):]

    def counters(self, session_id: str) -> Dict[str, int]:
        """Aggregate counters the policy engine can reference from conditions."""
        with self._lock:
            entries = self._entries.get(session_id, [])
            counters: Dict[str, int] = {
                "entries": len(entries),
                "completions": 0,
                "calls": 0,
                "results": 0,
                "failures": 0,
                "unattested_calls": 0,
                "truncated": self._truncated.get(session_id, 0),
            }
            per_tool: Dict[str, int] = {}
            for entry in entries:
                if entry.kind == EVENT_COMPLETION:
                    counters["completions"] += 1
                elif entry.kind == EVENT_CALL:
                    counters["calls"] += 1
                    if not entry.payload.get("has_attestation"):
                        counters["unattested_calls"] += 1
                    tool = str(entry.payload.get("qualified_name") or entry.payload.get("tool") or "")
                    if tool:
                        per_tool[tool] = per_tool.get(tool, 0) + 1
                elif entry.kind == EVENT_RESULT:
                    counters["results"] += 1
                    if not entry.payload.get("ok", True):
                        counters["failures"] += 1
            for tool, count in per_tool.items():
                counters[f"tool:{tool}"] = count
            counters["distinct_tools"] = len(per_tool)
            return counters

    def sessions(self) -> List[str]:
        """Every session id the ledger currently knows about."""
        with self._lock:
            return sorted(self._entries)

    # ------------------------------------------------------------------ #
    # Integrity
    # ------------------------------------------------------------------ #
    def verify_chain(self, session_id: str) -> Tuple[bool, List[str]]:
        """Recompute the hash chain and report every inconsistency found.

        Returns ``(ok, problems)``.  ``problems`` holds human-readable strings
        naming the sequence number of each broken link so an incident responder
        can pinpoint tampering instead of guessing.
        """
        with self._lock:
            entries = list(self._entries.get(session_id, []))
            truncated = self._truncated.get(session_id, 0)

        problems: List[str] = []
        if not entries:
            return True, problems

        expected_prev = GENESIS_HASH if not truncated else entries[0].prev_hash
        expected_seq = entries[0].sequence
        for entry in entries:
            if entry.sequence != expected_seq:
                problems.append(
                    f"sequence gap at entry {entry.sequence}: expected seq={expected_seq}"
                )
                expected_seq = entry.sequence
            if entry.prev_hash != expected_prev:
                problems.append(
                    f"broken link at seq={entry.sequence}: prev_hash={entry.prev_hash[:16]} "
                    f"but predecessor hashed to {expected_prev[:16]}"
                )
            body = {
                "seq": entry.sequence,
                "type": entry.kind,
                "ts": entry.get("ts"),
                "session_id": entry.get("session_id"),
                "payload": entry.payload,
            }
            recomputed = chain_hash(entry.prev_hash, body)
            if recomputed != entry.hash:
                problems.append(
                    f"payload tampered at seq={entry.sequence}: stored hash {entry.hash[:16]} "
                    f"!= recomputed {recomputed[:16]}"
                )
            expected_prev = entry.hash
            expected_seq += 1

        if truncated:
            problems.append(
                f"note: {truncated} entries were evicted from memory - chain verified from "
                f"seq={entries[0].sequence} onwards only"
            )
        hard_failures = [p for p in problems if not p.startswith("note:")]
        return (not hard_failures), problems

    def head(self, session_id: str) -> str:
        """Current chain head for a session (genesis when empty)."""
        with self._lock:
            return self._heads.get(session_id, GENESIS_HASH)

    # ------------------------------------------------------------------ #
    # Containment
    # ------------------------------------------------------------------ #
    def quarantine(self, session_id: str, reason: str = "") -> LedgerEntry:
        """Freeze a session after a provenance breach.

        Quarantine is recorded *in the chain* so the containment action itself is
        tamper-evident.
        """
        with self._lock:
            self._quarantined[session_id] = utc_now()
            return self._append(
                session_id,
                EVENT_QUARANTINE,
                {"reason": reason or "provenance breach", "at": utc_now()},
            )

    def is_quarantined(self, session_id: str) -> bool:
        """True when the session has been frozen."""
        with self._lock:
            return session_id in self._quarantined

    def release(self, session_id: str) -> bool:
        """Lift a quarantine (break-glass path).  Returns True when one existed."""
        with self._lock:
            existed = self._quarantined.pop(session_id, None) is not None
        if existed:
            with self._lock:
                self._append(session_id, EVENT_QUARANTINE, {"reason": "released", "at": utc_now()})
        return existed

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #
    def forget(self, session_id: str) -> None:
        """Drop all in-memory state for a finished session."""
        with self._lock:
            self._entries.pop(session_id, None)
            self._heads.pop(session_id, None)
            self._sequence.pop(session_id, None)
            self._truncated.pop(session_id, None)
            self._quarantined.pop(session_id, None)
            for completion_id in self._completion_index.pop(session_id, []):
                self._completions.pop(completion_id, None)
                self._arg_hashes.pop(completion_id, None)

    def export(self, session_id: str) -> List[Dict[str, Any]]:
        """Serialise a session's chain for offline forensics."""
        return [dict(entry) for entry in self.entries(session_id)]

    def stats(self) -> Dict[str, Any]:
        """Coarse ledger metrics for the ``/metrics`` endpoint."""
        with self._lock:
            return {
                "sessions": len(self._entries),
                "entries": sum(len(v) for v in self._entries.values()),
                "completions": len(self._completions),
                "quarantined": len(self._quarantined),
                "persisted": self._persist_path is not None,
            }

    def bulk_record_completions(self, completions: Iterable[ModelCompletion]) -> int:
        """Convenience used by replay/import tooling.  Returns the count."""
        count = 0
        for completion in completions:
            self.record_completion(completion)
            count += 1
        return count

    def describe_completion(self, completion_id: str) -> Dict[str, Any]:
        """JSON-safe view of a recorded completion (used by the API layer)."""
        completion = self.get_completion(completion_id)
        if completion is None:
            return {}
        payload = to_dict(completion)
        payload["arg_hashes"] = self.argument_hashes(completion_id)
        return payload
