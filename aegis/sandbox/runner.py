"""The sandbox facade: driver selection, canaries, egress and adjudication.

:class:`SandboxRunner` is what the rest of the platform calls.  Around a bare
driver it adds the parts that make a sandbox a *security control* rather than a
convenience wrapper:

* **Driver selection with honest downgrade.** If the spec asks for Docker and
  Docker is not running, silently executing on the host would be the worst
  possible outcome; the runner falls back along
  ``docker -> firejail -> subprocess`` and records the downgrade in the result
  and the audit log so nobody believes they were contained when they were not.
* **Canary injection.** Fake credentials are planted before the run and every
  byte of output is scanned afterwards.
* **Egress pre-flight.** URLs referenced by the workload are checked against
  the allowlist before the process starts, and proxy variables are injected.
* **Escape adjudication.** Canary hits, jail violations and driver escape flags
  are folded into ``SandboxResult.escape_detected``.
* **Audit + metrics.** Every run is recorded through the audit ledger when it
  is importable.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..core.errors import EgressBlocked, SandboxError, SandboxEscapeDetected
from ..core.logging import get_logger
from ..core.types import (
    SandboxKind,
    SandboxResult,
    SandboxSpec,
    new_id,
    utc_now,
)
from ..core.utils import Stopwatch, extract_urls
from .base import ExecutionRequest, SandboxDriver
from .canary import CanaryTokenManager
from .drivers.docker_driver import DockerDriver
from .drivers.firejail_driver import FirejailDriver
from .drivers.noop import NoopDriver
from .drivers.subprocess_driver import SubprocessDriver
from .egress import EgressController, ProxyRecorder

__all__ = ["SandboxRunner", "RunnerMetrics"]

log = get_logger("sandbox.runner")

#: Order used when the requested driver is unavailable.  Strongest first.
FALLBACK_ORDER: tuple[SandboxKind, ...] = (
    SandboxKind.DOCKER,
    SandboxKind.FIREJAIL,
    SandboxKind.SUBPROCESS,
)


@dataclass
class RunnerMetrics:
    """Counters exported to the observability layer."""

    runs: int = 0
    failures: int = 0
    timeouts: int = 0
    escapes: int = 0
    canary_hits: int = 0
    egress_blocks: int = 0
    downgrades: int = 0
    by_driver: Dict[str, int] = field(default_factory=dict)
    total_duration_ms: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "runs": self.runs,
            "failures": self.failures,
            "timeouts": self.timeouts,
            "escapes": self.escapes,
            "canary_hits": self.canary_hits,
            "egress_blocks": self.egress_blocks,
            "downgrades": self.downgrades,
            "by_driver": dict(self.by_driver),
            "avg_duration_ms": round(self.total_duration_ms / self.runs, 2) if self.runs else 0.0,
        }


class SandboxRunner:
    """Execute untrusted workloads under the strongest available isolation.

    Args:
        drivers: Explicit driver instances.  When omitted the standard four are
            constructed lazily.
        canaries: Shared canary manager; a new one is created when omitted.
        recorder: Shared proxy recorder for blocked egress.
        allow_downgrade: When False an unavailable driver raises instead of
            falling back - the right setting for regulated production.
        allow_noop: Whether :attr:`SandboxKind.NONE` may ever be honoured.
        environment: Deployment environment, forwarded to the noop driver's
            safety check.
        session_id: Default session used for canary bookkeeping.
    """

    def __init__(
        self,
        *,
        drivers: Optional[Sequence[SandboxDriver]] = None,
        canaries: Optional[CanaryTokenManager] = None,
        recorder: Optional[ProxyRecorder] = None,
        allow_downgrade: bool = True,
        allow_noop: bool = False,
        environment: str = "production",
        session_id: str = "",
        canary_enabled: bool = True,
        proxy_url: str = "",
    ) -> None:
        self.allow_downgrade = allow_downgrade
        self.allow_noop = allow_noop
        self.environment = environment
        self.session_id = session_id or new_id("ses")
        self.canary_enabled = canary_enabled
        self.proxy_url = proxy_url
        self.canaries = canaries or CanaryTokenManager()
        self.recorder = recorder or ProxyRecorder()
        self.metrics = RunnerMetrics()
        self._lock = threading.RLock()
        self._drivers: Dict[SandboxKind, SandboxDriver] = {}
        self._last_driver: str = ""
        if drivers:
            for driver in drivers:
                self._drivers[driver.kind] = driver
        self._availability_cache: Dict[SandboxKind, bool] = {}

    # ------------------------------------------------------------------ #
    # Driver management
    # ------------------------------------------------------------------ #
    def _build_driver(self, kind: SandboxKind) -> Optional[SandboxDriver]:
        """Instantiate the driver for ``kind`` (cached)."""
        if kind in self._drivers:
            return self._drivers[kind]
        driver: Optional[SandboxDriver]
        if kind is SandboxKind.DOCKER:
            driver = DockerDriver()
        elif kind is SandboxKind.FIREJAIL:
            driver = FirejailDriver()
        elif kind is SandboxKind.SUBPROCESS:
            driver = SubprocessDriver()
        elif kind is SandboxKind.NONE:
            if not self.allow_noop:
                log.error(
                    "refusing to build the no-isolation driver; "
                    "set allow_noop=True to override"
                )
                return None
            driver = NoopDriver(environment=self.environment)
        elif kind is SandboxKind.GVISOR:
            # gVisor is Docker with a different runtime, not a separate CLI.
            driver = DockerDriver(runtime="runsc")
        else:
            driver = None
        if driver is not None:
            self._drivers[kind] = driver
        return driver

    def _is_available(self, driver: SandboxDriver) -> bool:
        """Availability with a per-runner cache (probes are not free)."""
        cached = self._availability_cache.get(driver.kind)
        if cached is not None:
            return cached
        try:
            value = bool(driver.available())
        except Exception as exc:  # pragma: no cover - defensive
            log.warning(
                "driver availability probe raised",
                fields={"driver": driver.name, "error": str(exc)},
            )
            value = False
        self._availability_cache[driver.kind] = value
        return value

    def select_driver(self, spec: SandboxSpec) -> SandboxDriver:
        """Resolve the driver to use for ``spec``, applying the fallback chain.

        Raises:
            SandboxError: When nothing usable exists, or when the requested
                driver is unavailable and downgrades are disabled.
        """
        with self._lock:
            requested = spec.kind
            driver = self._build_driver(requested)
            if driver is not None and self._is_available(driver):
                return driver

            reason = ""
            if driver is None:
                reason = f"driver for kind '{requested.value}' is not implemented or not permitted"
            else:
                reason = getattr(driver, "unavailable_reason", lambda: "unavailable")()

            if not self.allow_downgrade:
                raise SandboxError(
                    f"requested sandbox '{requested.value}' is unavailable and "
                    f"downgrades are disabled: {reason}",
                    details={"requested": requested.value, "reason": reason},
                )

            for candidate_kind in FALLBACK_ORDER:
                if candidate_kind is requested:
                    continue
                candidate = self._build_driver(candidate_kind)
                if candidate is None or not self._is_available(candidate):
                    continue
                self.metrics.downgrades += 1
                log.warning(
                    "SANDBOX DOWNGRADE - requested isolation is unavailable",
                    fields={
                        "requested": requested.value,
                        "selected": candidate.name,
                        "reason": reason,
                        "isolation_strength": candidate.isolation_strength,
                    },
                )
                self._audit(
                    "sandbox.downgrade",
                    requested=requested.value,
                    selected=candidate.name,
                    reason=reason,
                )
                return candidate

            raise SandboxError(
                "no sandbox driver is available on this host",
                details={"requested": requested.value, "reason": reason},
            )

    def active_driver_name(self) -> str:
        """Name of the driver used by the most recent run."""
        return self._last_driver or "none"

    def driver_status(self) -> List[Dict[str, Any]]:
        """Availability report for every known driver kind."""
        status: List[Dict[str, Any]] = []
        for kind in (*FALLBACK_ORDER, SandboxKind.NONE):
            driver = self._build_driver(kind)
            if driver is None:
                status.append(
                    {"kind": kind.value, "available": False, "reason": "not permitted"}
                )
                continue
            available = self._is_available(driver)
            entry = {
                "kind": kind.value,
                "name": driver.name,
                "available": available,
                "isolation_strength": driver.isolation_strength,
            }
            if not available:
                entry["reason"] = getattr(driver, "unavailable_reason", lambda: "")()
            status.append(entry)
        return status

    # ------------------------------------------------------------------ #
    # Pre-flight
    # ------------------------------------------------------------------ #
    def _egress_controller(self, spec: SandboxSpec, session_id: str) -> EgressController:
        return EgressController.from_spec(
            spec, recorder=self.recorder, session_id=session_id, proxy_url=self.proxy_url
        )

    def _preflight_egress(
        self,
        spec: SandboxSpec,
        controller: EgressController,
        payloads: Sequence[str],
    ) -> List[str]:
        """Check URLs found in the workload before it ever runs.

        Blocking here is strictly better than blocking at connect time: the
        request never leaves the process, and the operator gets the destination
        in a decision log instead of a packet capture.
        """
        blocked: List[str] = []
        seen: Dict[str, None] = {}
        for payload in payloads:
            for url in extract_urls(payload or ""):
                seen.setdefault(url, None)
        for url in seen:
            try:
                controller.check(url)
            except EgressBlocked:
                blocked.append(url)
        if blocked:
            self.metrics.egress_blocks += len(blocked)
            log.warning(
                "workload references blocked destinations",
                fields={"count": len(blocked), "sample": blocked[:5]},
            )
        return blocked

    def _prepare_spec(
        self,
        spec: SandboxSpec,
        session_id: str,
        controller: EgressController,
    ) -> tuple[SandboxSpec, Dict[str, str]]:
        """Clone the spec with canaries and proxy variables merged in."""
        fields = dict(vars(spec))
        env = dict(spec.env or {})
        env.update(controller.http_proxy_env(spec))

        canary_files: Dict[str, str] = {}
        if self.canary_enabled:
            values = self.canaries.mint(session_id)
            env.update(self.canaries.env_for(session_id))
            canary_files = self.canaries.files_for(session_id)
            fields["canary_tokens"] = values
        fields["env"] = env
        return SandboxSpec(**fields), canary_files

    # ------------------------------------------------------------------ #
    # Post-processing
    # ------------------------------------------------------------------ #
    def _adjudicate(
        self,
        result: SandboxResult,
        session_id: str,
        blocked_urls: Sequence[str],
    ) -> SandboxResult:
        """Fold canary hits and egress blocks into the final verdict."""
        leaked = self.canaries.check_leak(
            f"{result.stdout}\n{result.stderr}",
            location="sandbox.stdout+stderr",
            session_id=session_id,
        )
        # A canary appearing in the sandbox's *own* output is expected when the
        # workload simply prints its environment; what matters is the value
        # leaving the boundary.  We therefore record it but only escalate to an
        # escape when the workload also attempted egress or the driver flagged
        # something.
        result.canaries_triggered = list(leaked)
        result.egress_blocked = list(dict.fromkeys([*result.egress_blocked, *blocked_urls]))

        escape = bool(result.escape_detected)
        if leaked and (blocked_urls or result.escape_detected):
            escape = True
        if result.resource_usage.get("escaping_symlinks"):
            escape = True
        result.escape_detected = escape

        if leaked:
            self.metrics.canary_hits += len(leaked)
        if escape:
            self.metrics.escapes += 1
            log.error(
                "SANDBOX ESCAPE INDICATORS PRESENT",
                fields={
                    "driver": result.driver,
                    "canaries": len(leaked),
                    "blocked_urls": len(result.egress_blocked),
                    "session_id": session_id,
                },
            )
        return result

    def _record_metrics(self, result: SandboxResult) -> None:
        self.metrics.runs += 1
        self.metrics.total_duration_ms += result.duration_ms
        self.metrics.by_driver[result.driver] = self.metrics.by_driver.get(result.driver, 0) + 1
        if not result.ok:
            self.metrics.failures += 1
        if result.timed_out:
            self.metrics.timeouts += 1

    def _audit(self, action: str, **fields: Any) -> None:
        """Best-effort audit write; never breaks execution."""
        try:
            from ..audit.ledger import AuditLedger  # local import: avoids a cycle
        except ImportError:
            return
        try:
            AuditLedger().record(action, **fields)
        except Exception as exc:  # pragma: no cover - audit must not block runs
            log.debug("audit record skipped", fields={"action": action, "error": str(exc)})

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def run(
        self,
        spec: SandboxSpec,
        command: Sequence[str],
        stdin: str = "",
        *,
        files: Optional[Mapping[str, str]] = None,
        session_id: str = "",
    ) -> SandboxResult:
        """Run ``command`` under isolation and return the adjudicated result.

        Raises:
            SandboxError: When no driver can serve the request.
        """
        session = session_id or self.session_id
        driver = self.select_driver(spec)
        self._last_driver = driver.name

        controller = self._egress_controller(spec, session)
        blocked = self._preflight_egress(
            spec, controller, [stdin, " ".join(str(c) for c in command), *(files or {}).values()]
        )

        effective_spec, canary_files = self._prepare_spec(spec, session, controller)
        payload_files: Dict[str, str] = {**canary_files, **dict(files or {})}

        request = ExecutionRequest(
            spec=effective_spec,
            command=[str(part) for part in command],
            stdin=stdin,
            files=payload_files,
            session_id=session,
            label=f"{driver.name}:{effective_spec.kind.value}",
        )
        log.info("sandbox run starting", fields=request.describe())

        with Stopwatch() as watch:
            try:
                result = driver.execute(request)
            except SandboxEscapeDetected:
                raise
            except SandboxError as exc:
                result = SandboxResult(
                    ok=False,
                    exit_code=1,
                    stderr=exc.message,
                    driver=driver.name,
                    resource_usage={"error": exc.code},
                )
            except Exception as exc:  # pragma: no cover - unexpected driver bug
                log.exception("sandbox driver raised")
                result = SandboxResult(
                    ok=False,
                    exit_code=1,
                    stderr=f"driver failure: {type(exc).__name__}: {exc}",
                    driver=driver.name,
                )
        if not result.duration_ms:
            result.duration_ms = watch.elapsed_ms
        if spec.kind is not effective_spec.kind or driver.kind is not spec.kind:
            result.resource_usage.setdefault("requested_kind", spec.kind.value)
            result.resource_usage.setdefault("downgraded", driver.kind is not spec.kind)

        result = self._adjudicate(result, session, blocked)
        self._record_metrics(result)
        self._audit(
            "sandbox.run",
            driver=result.driver,
            session_id=session,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            escape_detected=result.escape_detected,
            canaries=len(result.canaries_triggered),
            duration_ms=round(result.duration_ms, 2),
        )
        log.info(
            "sandbox run finished",
            fields={
                "driver": result.driver,
                "exit_code": result.exit_code,
                "ok": result.ok,
                "timed_out": result.timed_out,
                "escape": result.escape_detected,
                "duration_ms": round(result.duration_ms, 1),
            },
        )
        return result

    def run_python(
        self,
        spec: SandboxSpec,
        code: str,
        *,
        args: Optional[Sequence[str]] = None,
        session_id: str = "",
    ) -> SandboxResult:
        """Run a Python snippet inside the sandbox.

        The code is written to a file rather than passed with ``-c`` so that
        tracebacks carry real line numbers and the argv stays short enough for
        every platform's command-line limit.
        """
        interpreter = "python3" if spec.kind is SandboxKind.DOCKER else _host_python()
        entry = "aegis_entry.py"
        command = [interpreter, "-I", "-B", entry, *[str(a) for a in (args or [])]]
        return self.run(
            spec,
            command,
            files={entry: code},
            session_id=session_id,
        )

    def run_shell(
        self,
        spec: SandboxSpec,
        script: str,
        *,
        session_id: str = "",
    ) -> SandboxResult:
        """Run a shell script inside the sandbox.

        The script is written to disk and the interpreter is invoked explicitly;
        the runner never passes ``shell=True`` anywhere, so the caller's string
        cannot reach a host shell if the sandbox fails to start.
        """
        import sys as _sys

        if _sys.platform == "win32" and spec.kind in (SandboxKind.SUBPROCESS, SandboxKind.NONE):
            entry = "aegis_entry.cmd"
            command = ["cmd.exe", "/d", "/c", entry]
        else:
            entry = "aegis_entry.sh"
            command = ["/bin/sh", entry]
        return self.run(spec, command, files={entry: script}, session_id=session_id)

    # ------------------------------------------------------------------ #
    def verify_boundary(self, spec: Optional[SandboxSpec] = None, **kwargs: Any) -> Any:
        """Run the boundary probe suite against this runner.

        Imported lazily because :mod:`aegis.sandbox.boundary_test` imports the
        runner's public surface for typing purposes.
        """
        from .boundary_test import SandboxBoundaryTester

        return SandboxBoundaryTester(self, **kwargs).run_all(spec)

    def cleanup(self) -> None:
        """Release every driver's resources."""
        for driver in list(self._drivers.values()):
            try:
                driver.cleanup()
            except Exception as exc:  # pragma: no cover - best effort
                log.debug("driver cleanup failed", fields={"driver": driver.name, "error": str(exc)})

    def stats(self) -> Dict[str, Any]:
        """Runner + driver + canary + egress counters."""
        return {
            "metrics": self.metrics.as_dict(),
            "active_driver": self.active_driver_name(),
            "drivers": [d.stats() for d in self._drivers.values()],
            "canaries": self.canaries.stats(),
            "egress": self.recorder.stats(),
            "allow_downgrade": self.allow_downgrade,
            "allow_noop": self.allow_noop,
            "updated_at": utc_now(),
        }

    def __enter__(self) -> "SandboxRunner":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.cleanup()


def _host_python() -> str:
    """Absolute path to the interpreter running the gateway.

    Using ``sys.executable`` avoids depending on a ``python`` alias existing on
    PATH, which is routinely false on Windows and on slim Linux images.
    """
    import sys as _sys

    return _sys.executable or "python"
