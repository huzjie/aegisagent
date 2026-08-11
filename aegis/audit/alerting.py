"""Rule-based alerting over the audit ledger.

The :class:`AuditAlertEngine` inspects incoming events against a set of
declarative :class:`AlertRule` objects and dispatches notifications through
registered callbacks.  It supports three built-in rule kinds:

* ``frequency`` — fires when events matching a predicate exceed a threshold
  within a sliding window.
* ``action`` — fires immediately when a specific action occurs.
* ``chain_break`` — fires when a gap or hash mismatch is detected during
  chain verification.
"""

from __future__ import annotations

import re
import time
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence

from aegis.core.types import Severity
from aegis.core.logging import get_logger
from .event import AuditEventRecord

__all__ = ["AlertRule", "AuditAlertEngine", "AlertFired"]

_log = get_logger(__name__)

Notifier = Callable[["AlertFired"], None]


@dataclass
class AlertFired:
    """Record of a rule that triggered."""

    rule_id: str
    rule_name: str
    kind: str
    severity: str
    message: str
    event_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    fired_at: float = field(default_factory=time.time)


@dataclass
class AlertRule:
    """Declarative alert definition.

    Args:
        id: unique rule identifier.
        name: human-readable name.
        kind: one of ``frequency``, ``action``, ``chain_break``.
        action_pattern: glob pattern matched against event actions (for
            ``action`` and ``frequency`` rules).
        severity: severity threshold (``frequency`` counts only events at or
            above this level).
        threshold: number of matching events required to fire.
        window_s: sliding window size in seconds (``frequency``).
        message: template string for the alert message.
        cooldown_s: minimum interval between successive firings of the same rule.
    """

    id: str = ""
    name: str = ""
    kind: str = "frequency"
    action_pattern: str = "*"
    severity: str = "medium"
    threshold: int = 5
    window_s: float = 300.0
    message: str = "Alert triggered"
    cooldown_s: float = 60.0


class AuditAlertEngine:
    """Evaluate audit events against alert rules and dispatch notifications."""

    def __init__(self, rules: Optional[Sequence[AlertRule]] = None) -> None:
        self._rules: List[AlertRule] = list(rules or [])
        self._notifiers: List[Notifier] = []
        self._lock = threading.Lock()
        self._frequency_windows: Dict[str, Deque[float]] = {}
        self._last_fired: Dict[str, float] = {}
        self._fired_count: int = 0

    def add_rule(self, rule: AlertRule) -> None:
        """Register a new alert rule."""
        with self._lock:
            self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by identifier.  Returns ``True`` if removed."""
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rule_id]
            return len(self._rules) < before

    def add_notifier(self, notifier: Notifier) -> None:
        """Register a callback invoked when a rule fires."""
        self._notifiers.append(notifier)

    def evaluate(self, event: AuditEventRecord) -> List[AlertFired]:
        """Evaluate a single event against all rules and fire as needed."""
        fired: List[AlertFired] = []
        with self._lock:
            rules = list(self._rules)
        for rule in rules:
            alert = self._check_rule(rule, event)
            if alert is not None:
                fired.append(alert)
                self._dispatch(alert)
        return fired

    def evaluate_batch(self, events: Sequence[AuditEventRecord]) -> List[AlertFired]:
        """Evaluate a batch of events in order, collecting all fired alerts."""
        alerts: List[AlertFired] = []
        for event in events:
            alerts.extend(self.evaluate(event))
        return alerts

    def report_chain_break(self, details: Dict[str, Any]) -> AlertFired:
        """Manually fire a ``chain_break`` alert."""
        alert = AlertFired(
            rule_id="chain_break",
            rule_name="Hash chain integrity failure",
            kind="chain_break",
            severity="critical",
            message=details.get("message", "Audit chain hash mismatch detected"),
            details=details,
        )
        self._dispatch(alert)
        return alert

    @property
    def fired_count(self) -> int:
        """Total number of alerts fired since engine creation."""
        return self._fired_count

    @property
    def rules(self) -> List[AlertRule]:
        """Return a snapshot of registered rules."""
        return list(self._rules)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _check_rule(self, rule: AlertRule, event: AuditEventRecord) -> Optional[AlertFired]:
        now = time.time()
        if rule.kind == "action":
            return self._check_action(rule, event, now)
        if rule.kind == "frequency":
            return self._check_frequency(rule, event, now)
        if rule.kind == "chain_break":
            return None  # chain_break rules fire via report_chain_break
        return None

    def _check_action(
        self, rule: AlertRule, event: AuditEventRecord, now: float
    ) -> Optional[AlertFired]:
        if not _glob_matches(event.action or "", rule.action_pattern):
            return None
        if self._in_cooldown(rule.id, now):
            return None
        return self._make_alert(rule, event)

    def _check_frequency(
        self, rule: AlertRule, event: AuditEventRecord, now: float
    ) -> Optional[AlertFired]:
        if not _glob_matches(event.action or "", rule.action_pattern):
            return None
        threshold_score = _severity_score(rule.severity)
        event_score = _severity_score(event.severity.value)
        if event_score < threshold_score:
            return None

        window = self._frequency_windows.setdefault(rule.id, deque())
        window.append(now)
        cutoff = now - rule.window_s
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= rule.threshold:
            if self._in_cooldown(rule.id, now):
                return None
            alert = AlertFired(
                rule_id=rule.id,
                rule_name=rule.name or rule.id,
                kind=rule.kind,
                severity=rule.severity,
                message=rule.message or f"Frequency threshold reached for {rule.action_pattern}",
                event_id=event.id,
                details={
                    "count": len(window),
                    "threshold": rule.threshold,
                    "window_s": rule.window_s,
                    "action": event.action,
                },
            )
            self._last_fired[rule.id] = now
            self._fired_count += 1
            return alert
        return None

    def _in_cooldown(self, rule_id: str, now: float) -> bool:
        last = self._last_fired.get(rule_id, 0.0)
        rule = next((r for r in self._rules if r.id == rule_id), None)
        cooldown = rule.cooldown_s if rule else 60.0
        return (now - last) < cooldown

    def _make_alert(self, rule: AlertRule, event: AuditEventRecord) -> AlertFired:
        alert = AlertFired(
            rule_id=rule.id,
            rule_name=rule.name or rule.id,
            kind=rule.kind,
            severity=rule.severity,
            message=rule.message or f"Action {event.action} triggered alert",
            event_id=event.id,
            details={
                "action": event.action,
                "actor": event.actor,
                "severity": event.severity.value,
            },
        )
        self._last_fired[rule.id] = time.time()
        self._fired_count += 1
        return alert

    def _dispatch(self, alert: AlertFired) -> None:
        _log.info("alert fired", fields={"rule_id": alert.rule_id, "kind": alert.kind})
        for notifier in self._notifiers:
            try:
                notifier(alert)
            except Exception:  # pragma: no cover - notifier must not break engine
                _log.exception("alert notifier failed", fields={"rule_id": alert.rule_id})


def _severity_score(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value.lower(), 0)


def _glob_matches(value: str, pattern: str) -> bool:
    """Case-insensitive glob match supporting ``*`` and ``**``."""
    if pattern in ("*", "**"):
        return True
    regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return bool(re.match(f"^{regex}$", value, re.IGNORECASE))
