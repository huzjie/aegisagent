"""Concrete sandbox drivers.

Import order matters only for readability; every driver is safe to import on
every platform because platform-specific work happens inside ``available()``
and ``run()``, never at module scope.
"""

from __future__ import annotations

from typing import Dict, List

from ...core.types import SandboxKind
from ..base import SandboxDriver
from .docker_driver import DockerDriver
from .firejail_driver import FirejailDriver
from .noop import NoopDriver
from .subprocess_driver import SubprocessDriver

__all__ = [
    "SubprocessDriver",
    "DockerDriver",
    "FirejailDriver",
    "NoopDriver",
    "DRIVER_REGISTRY",
    "available_drivers",
    "build_driver",
]

#: Kind -> driver class.  ``NONE`` is deliberately absent so it can only be
#: constructed through an explicit, logged opt-in.
DRIVER_REGISTRY: Dict[SandboxKind, type] = {
    SandboxKind.SUBPROCESS: SubprocessDriver,
    SandboxKind.DOCKER: DockerDriver,
    SandboxKind.FIREJAIL: FirejailDriver,
}


def build_driver(kind: SandboxKind, **kwargs: object) -> SandboxDriver:
    """Instantiate the driver registered for ``kind``.

    Raises:
        KeyError: When the kind has no registered driver.
    """
    factory = DRIVER_REGISTRY[kind]
    return factory(**kwargs)  # type: ignore[return-value]


def available_drivers() -> List[Dict[str, object]]:
    """Probe every registered driver and report whether it can run here."""
    report: List[Dict[str, object]] = []
    for kind, factory in DRIVER_REGISTRY.items():
        try:
            driver: SandboxDriver = factory()  # type: ignore[assignment]
            entry: Dict[str, object] = {
                "kind": kind.value,
                "name": driver.name,
                "available": driver.available(),
                "isolation_strength": driver.isolation_strength,
            }
            reason = getattr(driver, "unavailable_reason", None)
            if not entry["available"] and callable(reason):
                entry["reason"] = reason()
            report.append(entry)
        except Exception as exc:  # pragma: no cover - construction failure
            report.append(
                {"kind": kind.value, "available": False, "reason": f"{type(exc).__name__}: {exc}"}
            )
    return sorted(report, key=lambda e: int(e.get("isolation_strength", 0)), reverse=True)
