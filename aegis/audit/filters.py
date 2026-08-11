"""Audit event filtering predicates.

The :class:`AuditFilter` dataclass encapsulates the filter criteria used by
:meth:`aegis.audit.ledger.AuditLedger.query`.  Each attribute represents an
independent axis; all non-empty criteria are combined with AND semantics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Pattern, Sequence, Tuple

from .event import AuditEventRecord

__all__ = ["AuditFilter"]

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class AuditFilter:
    """Declarative description of the events a caller cares about.

    Attributes:
        actions: action names to match (case-insensitive, supports ``*`` globs).
        severities: minimum severity level or an explicit list.
        agents: agent identifiers.
        sessions: session identifiers.
        tenants: tenant identifiers.
        principals: principal identifiers.
        time_range: ``(start_epoch, end_epoch)`` tuple; either may be ``None``.
        text_search: regular expression applied to the JSON payload.
        outcomes: outcome strings (``success`` / ``failure`` / …).
        resources: resource identifiers.
    """

    actions: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    min_severity: str = ""
    agents: List[str] = field(default_factory=list)
    sessions: List[str] = field(default_factory=list)
    tenants: List[str] = field(default_factory=list)
    principals: List[str] = field(default_factory=list)
    outcomes: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    time_range: Tuple[Optional[float], Optional[float]] = (None, None)
    text_search: str = ""
    limit: int = 0

    def _compile_action_patterns(self) -> List[Pattern[str]]:
        patterns: List[Pattern[str]] = []
        for action in self.actions:
            regex = re.escape(action).replace(r"\*", ".*").replace(r"\?", ".")
            patterns.append(re.compile(f"^{regex}$", re.IGNORECASE))
        return patterns

    def _severity_score(self, severity: str) -> int:
        return _SEVERITY_ORDER.get(severity.lower(), 0)

    def matches(self, event: AuditEventRecord) -> bool:
        """Return ``True`` if the event satisfies every criterion."""
        if self.actions:
            action_lower = (event.action or "").lower()
            patterns = self._compile_action_patterns()
            if not any(p.match(action_lower) for p in patterns):
                return False

        if self.severities:
            if event.severity.value not in {s.lower() for s in self.severities}:
                return False

        if self.min_severity:
            threshold = self._severity_score(self.min_severity)
            if self._severity_score(event.severity.value) < threshold:
                return False

        if self.agents and event.agent_id not in self.agents:
            return False
        if self.sessions and event.session_id not in self.sessions:
            return False
        if self.tenants and event.tenant_id not in self.tenants:
            return False
        if self.principals and event.principal_id not in self.principals:
            return False
        if self.outcomes and (event.outcome or "").lower() not in {o.lower() for o in self.outcomes}:
            return False
        if self.resources and event.resource not in self.resources:
            return False

        start, end = self.time_range
        if start is not None and event.timestamp < start:
            return False
        if end is not None and event.timestamp > end:
            return False

        if self.text_search:
            try:
                pattern = re.compile(self.text_search, re.IGNORECASE)
            except re.error:
                pattern = re.compile(re.escape(self.text_search), re.IGNORECASE)
            blob = event.payload and _stringify_payload(event.payload) or ""
            if not pattern.search(blob):
                return False

        return True


def _stringify_payload(data: Any) -> str:
    """Flatten a nested structure into a searchable string."""
    if isinstance(data, dict):
        return " ".join(
            f"{k}:{_stringify_payload(v)}" for k, v in data.items()
        )
    if isinstance(data, (list, tuple)):
        return " ".join(_stringify_payload(item) for item in data)
    return str(data)
