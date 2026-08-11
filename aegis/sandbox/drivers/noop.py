"""No-isolation driver.

Exists for exactly two situations:

* a developer explicitly disabling isolation on a trusted local machine, and
* differential testing - running the same workload with and without isolation
  so :mod:`aegis.sandbox.boundary_test` can prove the other drivers are doing
  something.

It is deliberately loud: constructing it emits a WARNING, every run emits a
WARNING, and the result carries ``resource_usage["isolated"] = False`` so
downstream audit records can never claim the workload was contained.
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Mapping, Optional, Sequence

from ...core.errors import SandboxError
from ...core.logging import get_logger
from ...core.types import SandboxKind, SandboxResult, SandboxSpec
from ..base import DEFAULT_MAX_OUTPUT_BYTES, SandboxDriver, clip_output, sanitise_env

__all__ = ["NoopDriver"]

log = get_logger("sandbox.driver.noop")


class NoopDriver(SandboxDriver):
    """Runs the command directly on the host with no isolation at all.

    Args:
        acknowledge_risk: Must be True in any environment other than
            ``development``; the runner passes this only when the operator has
            explicitly selected :attr:`SandboxKind.NONE`.
        environment: Deployment environment name, used for the safety check.
    """

    kind = SandboxKind.NONE
    isolation_strength = 0

    def __init__(self, *, acknowledge_risk: bool = True, environment: str = "development") -> None:
        super().__init__()
        self.environment = environment
        self.acknowledge_risk = acknowledge_risk
        if environment.lower() in ("production", "prod") and not acknowledge_risk:
            raise SandboxError(
                "NoopDriver refuses to initialise in production without an "
                "explicit risk acknowledgement",
                details={"environment": environment},
            )
        log.warning(
            "NoopDriver constructed - SANDBOX ISOLATION IS DISABLED. "
            "Commands run with the full privileges of the gateway process.",
            fields={"environment": environment, "acknowledged": acknowledge_risk},
        )

    @property
    def name(self) -> str:
        return "noop"

    def available(self) -> bool:
        """Always available - there is nothing to check."""
        return True

    def run(
        self,
        spec: SandboxSpec,
        command: Sequence[str],
        stdin: str = "",
        files: Optional[Mapping[str, str]] = None,
    ) -> SandboxResult:
        """Execute ``command`` on the host, honouring only the wall-clock timeout."""
        argv = [str(part) for part in command]
        if not argv:
            return SandboxResult(
                ok=False, exit_code=2, stderr="empty command", driver=self.name
            )

        log.warning(
            "executing WITHOUT isolation",
            fields={"program": argv[0], "argc": len(argv)},
        )

        workdir = spec.workdir if spec.workdir and os.path.isdir(spec.workdir) else os.getcwd()
        if files:
            for relative, content in files.items():
                target = os.path.join(workdir, relative)
                os.makedirs(os.path.dirname(target) or workdir, exist_ok=True)
                with open(target, "w", encoding="utf-8") as handle:
                    handle.write(content)

        env = sanitise_env(spec)
        started = time.perf_counter()
        timed_out = False
        try:
            completed = subprocess.run(  # noqa: S603 - argv list, never shell=True
                argv,
                input=stdin,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(0.1, spec.timeout_s),
                cwd=workdir,
                env=env,
                shell=False,
            )
            stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            stderr += f"\n[aegis] wall-clock timeout after {spec.timeout_s}s"
            code = 124
        except (OSError, ValueError) as exc:
            return SandboxResult(
                ok=False,
                exit_code=127,
                stderr=f"failed to launch: {exc}",
                driver=self.name,
                duration_ms=(time.perf_counter() - started) * 1000.0,
            )

        duration_ms = (time.perf_counter() - started) * 1000.0
        stdout, out_trunc = clip_output(stdout, DEFAULT_MAX_OUTPUT_BYTES)
        stderr, err_trunc = clip_output(stderr, DEFAULT_MAX_OUTPUT_BYTES)
        return SandboxResult(
            ok=code == 0 and not timed_out,
            exit_code=code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            killed=timed_out,
            driver=self.name,
            resource_usage={
                "isolated": False,
                "warning": "no isolation applied - host filesystem, network and "
                           "credentials were fully reachable",
                "workdir": workdir,
                "truncated": out_trunc or err_trunc,
            },
        )
