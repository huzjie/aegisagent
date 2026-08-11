"""Statistical aggregation over audit events.

Provides a stateless :class:`AuditAggregator` that computes bucketed summaries
of a sequence of :class:`AuditEventRecord` instances, useful for dashboards
and compliance reports.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .event import AuditEventRecord

__all__ = ["AuditAggregator", "AuditSummary"]


@dataclass
class AuditSummary:
    """Statistical summary produced by :class:`AuditAggregator`."""

    total: int = 0
    by_action: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_outcome: Dict[str, int] = field(default_factory=dict)
    by_agent: Dict[str, int] = field(default_factory=dict)
    by_tenant: Dict[str, int] = field(default_factory=dict)
    by_hour: Dict[str, int] = field(default_factory=dict)
    first_event_ts: float = 0.0
    last_event_ts: float = 0.0
    error_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe dictionary representation."""
        return {
            "total": self.total,
            "by_action": dict(self.by_action),
            "by_severity": dict(self.by_severity),
            "by_outcome": dict(self.by_outcome),
            "by_agent": dict(self.by_agent),
            "by_tenant": dict(self.by_tenant),
            "by_hour": dict(self.by_hour),
            "first_event_ts": self.first_event_ts,
            "last_event_ts": self.last_event_ts,
            "error_count": self.error_count,
        }


class AuditAggregator:
    """Compute bucketed summaries over audit events.

    The aggregator is intentionally stateless — each call to :meth:`summary`
    walks the provided event iterable from scratch.  For very large ledgers
    callers should pre-filter via :class:`AuditFilter` before aggregating.
    """

    def __init__(self) -> None:
        self._summary = AuditSummary()

    def summary(self, events: Iterable[AuditEventRecord]) -> AuditSummary:
        """Produce a :class:`AuditSummary` for the given event iterable."""
        result = AuditSummary()
        action_counts: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)
        outcome_counts: Dict[str, int] = defaultdict(int)
        agent_counts: Dict[str, int] = defaultdict(int)
        tenant_counts: Dict[str, int] = defaultdict(int)
        hour_counts: Dict[str, int] = defaultdict(int)
        error_count = 0
        total = 0
        first_ts = float("inf")
        last_ts = 0.0

        for event in events:
            total += 1
            action_counts[event.action or "unknown"] += 1
            severity_counts[event.severity.value] += 1
            outcome_counts[event.outcome or "unknown"] += 1
            if event.agent_id:
                agent_counts[event.agent_id] += 1
            if event.tenant_id:
                tenant_counts[event.tenant_id] += 1
            bucket = _hour_bucket(event.timestamp)
            hour_counts[bucket] += 1
            if event.outcome and event.outcome != "success":
                error_count += 1
            if event.timestamp < first_ts:
                first_ts = event.timestamp
            if event.timestamp > last_ts:
                last_ts = event.timestamp

        result.total = total
        result.by_action = dict(action_counts)
        result.by_severity = dict(severity_counts)
        result.by_outcome = dict(outcome_counts)
        result.by_agent = dict(agent_counts)
        result.by_tenant = dict(tenant_counts)
        result.by_hour = dict(hour_counts)
        result.error_count = error_count
        result.first_event_ts = first_ts if first_ts != float("inf") else 0.0
        result.last_event_ts = last_ts

        self._summary = result
        return result

    @property
    def last_summary(self) -> AuditSummary:
        """Return the most recently computed summary."""
        return self._summary

    def top_actions(self, limit: int = 10) -> List[tuple]:
        """Return the most common actions from the last summary."""
        return sorted(
            self._summary.by_action.items(),
            key=lambda kv: kv[1],
            reverse=True,
        )[:limit]

    def top_agents(self, limit: int = 10) -> List[tuple]:
        """Return the agents that generated the most events."""
        return sorted(
            self._summary.by_agent.items(),
            key=lambda kv: kv[1],
            reverse=True,
        )[:limit]

    def severity_distribution(self) -> Dict[str, float]:
        """Return severity counts as fractions of the total."""
        total = self._summary.total
        if not total:
            return {}
        return {k: round(v / total, 4) for k, v in self._summary.by_severity.items()}


def _hour_bucket(ts: float) -> str:
    """Return an ISO-style ``YYYY-MM-DDTHH`` bucket key for *ts*."""
    return time.strftime("%Y-%m-%dT%H", time.gmtime(ts))
