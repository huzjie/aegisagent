"""Provenance: cryptographically bind every tool call to a real model turn.

This package is AegisAgent's answer to the **CoreBreak** vulnerability family
disclosed by the Cloud Security Alliance in 2026-08:

* ``CVE-2026-18830`` - AWS Bedrock AgentCore (CVSS 8.6)
* ``CVE-2026-18236`` - Google ADK for Python (CVSS 9.3)
* ``CVE-2026-64650`` / ``CVE-2026-64651`` - Vercel ``@ai-sdk/harness-codex``

All four share one root cause: **tool-dispatch instructions were never checked
for provenance or authorisation before being executed.** An attacker could paste
a ``tool_use`` block into the last message of an API request and the event loop
would run it, with the model never having been invoked; or forge a
human-approval confirmation, because the confirmation handler never verified
that the target tool belonged to the agent, that it genuinely required
confirmation, or that its name and arguments still matched the original record.

Typical wiring::

    from aegis.provenance import (
        ProvenanceBinder, ProvenanceMiddleware, ProvenanceVerifier, SessionLedger,
    )

    ledger  = SessionLedger(persist_path="data/sessions.jsonl")
    binder  = ProvenanceBinder(signing_key=KEY, ledger=ledger)
    verifier = ProvenanceVerifier(ledger=ledger, signing_key=KEY,
                                  trusted_issuers=["aegis-gateway"])
    guard   = ProvenanceMiddleware(verifier, mode="enforce")

    # 1. right after the model responds
    tokens = binder.issue_for_completion(completion)

    # 2. right before anything is dispatched
    guard(tool_call)          # raises unless the call is bound to `completion`
"""

from __future__ import annotations

from .attestation import (  # noqa: F401
    ATTESTATION_TYPE,
    ATTESTATION_VERSION,
    DELEGATION_TYPE,
    Attestation,
    args_hash_of,
    attestation_subject,
    decode_attestation,
    encode_attestation,
    hash_arguments,
    iter_tool_calls,
    normalize_tool_call,
)
from .binder import ProvenanceBinder  # noqa: F401
from .chain import (  # noqa: F401
    MAX_CHAIN_DEPTH,
    DelegationLink,
    ProvenanceChain,
    delegation_subject,
    narrows,
    scope_covers,
)
from .middleware import MODES, ProvenanceMiddleware  # noqa: F401
from .replay_guard import (  # noqa: F401
    MemoryReplayBackend,
    ReplayGuard,
    ReplayGuardBackend,
    SqliteReplayBackend,
)
from .session_ledger import LedgerEntry, SessionLedger  # noqa: F401
from .store import (  # noqa: F401
    InMemoryProvenanceStore,
    ProvenanceStore,
    SQLiteProvenanceStore,
    build_store,
    record_to_row,
    row_to_record,
)
from .verifier import CVE_REFERENCES, ProvenanceVerifier  # noqa: F401

__all__ = [
    # attestation
    "ATTESTATION_TYPE",
    "ATTESTATION_VERSION",
    "DELEGATION_TYPE",
    "Attestation",
    "args_hash_of",
    "attestation_subject",
    "decode_attestation",
    "encode_attestation",
    "hash_arguments",
    "iter_tool_calls",
    "normalize_tool_call",
    # issuing
    "ProvenanceBinder",
    # ledger
    "LedgerEntry",
    "SessionLedger",
    # replay
    "MemoryReplayBackend",
    "ReplayGuard",
    "ReplayGuardBackend",
    "SqliteReplayBackend",
    # verification
    "CVE_REFERENCES",
    "ProvenanceVerifier",
    # delegation
    "MAX_CHAIN_DEPTH",
    "DelegationLink",
    "ProvenanceChain",
    "delegation_subject",
    "narrows",
    "scope_covers",
    # enforcement
    "MODES",
    "ProvenanceMiddleware",
    # persistence
    "InMemoryProvenanceStore",
    "ProvenanceStore",
    "SQLiteProvenanceStore",
    "build_store",
    "record_to_row",
    "row_to_record",
]
