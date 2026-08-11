"""Tamper-evident audit subsystem.

The :mod:`aegis.audit` package exposes an append-only ledger whose events are
chained by SHA-256 hashes and signed with HMAC-SHA256, making any modification
detectable.  It additionally provides filtering, aggregation, multi-format
export and a lightweight alerting engine.
"""

from __future__ import annotations

from .ledger import AuditLedger
from .event import AuditEventRecord
from .filters import AuditFilter
from .aggregator import AuditAggregator, AuditSummary
from .exporters import AuditExporter
from .alerting import AuditAlertEngine, AlertRule

__all__ = [
    "AuditLedger",
    "AuditEventRecord",
    "AuditFilter",
    "AuditAggregator",
    "AuditSummary",
    "AuditExporter",
    "AuditAlertEngine",
    "AlertRule",
]
