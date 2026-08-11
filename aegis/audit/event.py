"""Audit event record model.

A lightweight wrapper around the :class:`aegis.core.types.AuditEvent` dataclass
that adds serialisation helpers and a canonical payload used for hashing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from aegis.core.types import AuditEvent, Severity, new_id, utc_now, to_dict
from aegis.core.crypto import canonical_json

__all__ = ["AuditEventRecord", "record_to_dict", "event_from_record"]


@dataclass
class AuditEventRecord:
    """Domain-level representation of one immutable ledger entry.

    The record mirrors :class:`aegis.core.types.AuditEvent` but provides
    convenience factories and a serialisation interface used by the ledger,
    exporters and aggregators.
    """

    id: str = field(default_factory=lambda: new_id("evt"))
    sequence: int = 0
    timestamp: float = field(default_factory=utc_now)
    tenant_id: str = "default"
    actor: str = "system"
    action: str = ""
    resource: str = ""
    outcome: str = "success"
    severity: Severity = Severity.INFO
    session_id: str = ""
    agent_id: str = ""
    principal_id: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""
    signature: str = ""

    @classmethod
    def from_core(cls, event: AuditEvent) -> "AuditEventRecord":
        """Construct from the core :class:`AuditEvent` dataclass."""
        return cls(
            id=event.id,
            sequence=event.sequence,
            timestamp=event.timestamp,
            tenant_id=event.tenant_id,
            actor=event.actor,
            action=event.action,
            resource=event.resource,
            outcome=event.outcome,
            severity=event.severity,
            session_id=event.session_id,
            payload=dict(event.payload),
            prev_hash=event.prev_hash,
            hash=event.hash,
            signature=event.signature,
        )

    def to_core(self) -> AuditEvent:
        """Convert back to the core :class:`AuditEvent` dataclass."""
        return AuditEvent(
            id=self.id,
            sequence=self.sequence,
            timestamp=self.timestamp,
            tenant_id=self.tenant_id,
            actor=self.actor,
            action=self.action,
            resource=self.resource,
            outcome=self.outcome,
            severity=self.severity,
            session_id=self.session_id,
            payload=dict(self.payload),
            prev_hash=self.prev_hash,
            hash=self.hash,
            signature=self.signature,
        )

    def hashable_payload(self) -> Dict[str, Any]:
        """Deterministic subset used for chain hashing and signing.

        The ``hash`` and ``signature`` fields are excluded so that verification
        can recompute the hash from stable data.
        """
        return {
            "id": self.id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "severity": self.severity.value,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "principal_id": self.principal_id,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
        }

    def to_json(self) -> str:
        """Serialise to a JSON string suitable for JSONL storage."""
        return json.dumps(record_to_dict(self), ensure_ascii=False, default=str)

    @classmethod
    def from_json(cls, line: str) -> "AuditEventRecord":
        """Deserialise a JSONL line produced by :meth:`to_json`."""
        data = json.loads(line)
        if "severity" in data and isinstance(data["severity"], str):
            data["severity"] = Severity(data["severity"])
        return event_from_record(data)


def record_to_dict(record: AuditEventRecord) -> Dict[str, Any]:
    """Convert an :class:`AuditEventRecord` into a JSON-safe dictionary."""
    data = {
        "id": record.id,
        "sequence": record.sequence,
        "timestamp": record.timestamp,
        "tenant_id": record.tenant_id,
        "actor": record.actor,
        "action": record.action,
        "resource": record.resource,
        "outcome": record.outcome,
        "severity": record.severity.value,
        "session_id": record.session_id,
        "agent_id": record.agent_id,
        "principal_id": record.principal_id,
        "payload": record.payload,
        "prev_hash": record.prev_hash,
        "hash": record.hash,
        "signature": record.signature,
    }
    return data


def event_from_record(data: Dict[str, Any]) -> AuditEventRecord:
    """Build an :class:`AuditEventRecord` from a plain dictionary."""
    severity = data.get("severity", "info")
    if isinstance(severity, str):
        try:
            severity = Severity(severity)
        except ValueError:
            severity = Severity.INFO
    return AuditEventRecord(
        id=data.get("id", new_id("evt")),
        sequence=int(data.get("sequence", 0)),
        timestamp=float(data.get("timestamp", utc_now())),
        tenant_id=str(data.get("tenant_id", "default")),
        actor=str(data.get("actor", "system")),
        action=str(data.get("action", "")),
        resource=str(data.get("resource", "")),
        outcome=str(data.get("outcome", "success")),
        severity=severity,
        session_id=str(data.get("session_id", "")),
        agent_id=str(data.get("agent_id", "")),
        principal_id=str(data.get("principal_id", "")),
        payload=dict(data.get("payload") or {}),
        prev_hash=str(data.get("prev_hash", "")),
        hash=str(data.get("hash", "")),
        signature=str(data.get("signature", "")),
    )
