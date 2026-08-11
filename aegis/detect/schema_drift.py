"""Schema-drift detector.

The "schema rug-pull" / "tool shadowing" attack changes a tool's declared schema
*after* the agent has trusted it - adding parameters, swapping the description or
renaming the tool so that previously-approved behaviour no longer matches what
actually runs.  This detector fingerprints each tool's declared surface and
raises an alert the moment it changes, supporting the ``mcp.pin_schemas`` policy.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.crypto import fingerprint
from ..core.logging import get_logger
from ..core.types import DetectorKind, EvaluationContext, Finding, Severity, ToolDescriptor
from .base import Detector

LOGGER = get_logger("detect.schema_drift")

#: Default minimum similarity below which a change is treated as a hard swap.
_HARD_SWAP_THRESHOLD = 0.6


def _surface_fingerprint(descriptor: ToolDescriptor) -> str:
    """Stable fingerprint of a tool's declared surface (name + docs + params)."""
    params = [
        (p.name, p.type, p.required, p.description)
        for p in (descriptor.parameters or [])
    ]
    payload = {
        "name": descriptor.name,
        "server": descriptor.server,
        "description": descriptor.description,
        "categories": sorted(c.value for c in (descriptor.categories or [])),
        "parameters": params,
        "version": descriptor.version,
    }
    return fingerprint(payload)


def _similarity(a: str, b: str) -> float:
    """Cheap Jaccard over character 4-grams of two fingerprints' source."""
    from ..core.utils import jaccard

    return jaccard(a, b)


class SchemaDriftDetector(Detector):
    """Flags live changes to a tool's declared schema after first sight."""

    name = "schema_drift"
    kind = DetectorKind.SCHEMA_DRIFT
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.5,
        pin_schemas: bool = True,
        **options: Any,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        pin_schemas: When ``True``, any drift is reported (hard pin).
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)
        self.pin_schemas = bool(pin_schemas)
        self._baselines: Dict[str, str] = {}
        self._lock = threading.Lock()

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        descriptor = ctx.descriptor
        if descriptor is None:
            return []
        key = descriptor.qualified_name
        current = _surface_fingerprint(descriptor)

        # A pin set through :meth:`pin` always wins over the implicit baseline.
        pinned = (ctx.extra or {}).get("baseline_schema_hash") or self._baselines.get(key)
        if pinned:
            if pinned != current:
                return [
                    self.make_finding(
                        "Schema drift vs pinned baseline",
                        description=(
                            "The tool's live schema hash differs from the pinned baseline. "
                            "Its behaviour may no longer match what was approved."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        evidence=[f"expected={pinned[:16]}", f"observed={current[:16]}"],
                        location="descriptor",
                        remediation="Block the tool; re-approve against the new schema before use.",
                        tags=["schema_drift", "pinned"],
                    )
                ]
            return []

        if not self.pin_schemas:
            return []

        with self._lock:
            baseline = self._baselines.get(key)
            if baseline is None:
                self._baselines[key] = current
                return []
            changed = baseline != current

        if not changed:
            return []

        sim = _similarity(baseline, current)
        hard = sim < _HARD_SWAP_THRESHOLD
        return [
            self.make_finding(
                "Tool schema changed since first sight",
                description=(
                    "The declared schema for this tool changed at runtime "
                    f"(similarity={sim:.2f}). This is the 'schema rug-pull' pattern."
                ),
                severity=Severity.CRITICAL if hard else Severity.HIGH,
                confidence=0.9 if hard else 0.7,
                evidence=[f"tool={key}", f"similarity={sim:.2f}"],
                location="descriptor",
                remediation="Reject until the new schema is reviewed and re-approved.",
                tags=["schema_drift", "rug_pull"],
            )
        ]

    # ------------------------------------------------------------------ #
    # Explicit pinning / persistence
    # ------------------------------------------------------------------ #
    def pin(self, descriptor: ToolDescriptor) -> None:
        """Pin the current schema of ``descriptor`` as the trusted baseline."""
        with self._lock:
            self._baselines[descriptor.qualified_name] = _surface_fingerprint(descriptor)

    def check(self, descriptor: ToolDescriptor) -> List[Finding]:
        """Compare ``descriptor`` against its pinned baseline.

        Unlike :meth:`analyze` (which also fingerprints on first sight), this
        method assumes the tool was already pinned and only reports drift.  It is
        the hook used at MCP connect time by ``mcp.scan_on_connect``.
        """
        key = descriptor.qualified_name
        current = _surface_fingerprint(descriptor)
        with self._lock:
            baseline = self._baselines.get(key)
        if baseline is None:
            return []
        if baseline == current:
            return []
        sim = _similarity(baseline, current)
        hard = sim < _HARD_SWAP_THRESHOLD
        return [
            self.make_finding(
                "Pinned schema drift detected",
                description=(
                    f"Tool '{key}' changed since it was pinned (similarity={sim:.2f})."
                ),
                severity=Severity.CRITICAL if hard else Severity.HIGH,
                confidence=0.95 if hard else 0.75,
                evidence=[f"tool={key}", f"similarity={sim:.2f}"],
                location="descriptor",
                remediation="Reject the tool until its new schema is reviewed and re-pinned.",
                tags=["schema_drift", "pinned", "rug_pull"],
            )
        ]

    def export_pins(self, path: Optional[str] = None) -> Dict[str, str]:
        """Return ``{qualified_name: fingerprint}``; write JSON when ``path`` set."""
        with self._lock:
            data = dict(self._baselines)
        if path:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return data

    def load_pins(self, path: str) -> int:
        """Load pinned baselines from a JSON file written by :meth:`export_pins`."""
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return 0
        with self._lock:
            for name, value in payload.items():
                if isinstance(name, str) and isinstance(value, str):
                    self._baselines[name] = value
        return len(payload)

    def reset_baseline(self, qualified_name: Optional[str] = None) -> None:
        """Forget a pinned baseline (or all of them)."""
        with self._lock:
            if qualified_name is None:
                self._baselines.clear()
            else:
                self._baselines.pop(qualified_name, None)
