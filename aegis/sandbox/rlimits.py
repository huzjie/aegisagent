"""POSIX resource limits and their Docker equivalents.

Wall-clock timeouts alone are not isolation: a workload can exhaust memory,
spawn thousands of processes or open every file descriptor on the box long
before the timeout fires.  :class:`ResourceLimits` centralises the numeric
budget so the subprocess driver (``setrlimit``) and the container drivers
(``--memory`` / ``--pids-limit`` / ``--ulimit``) enforce *the same* numbers.

On Windows ``resource`` does not exist; :func:`apply_posix` degrades to a
no-op that reports which limits could not be enforced, and the caller is
expected to surface that in :class:`~aegis.core.types.SandboxResult`.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

try:  # pragma: no cover - POSIX only
    import resource as _resource
except ImportError:  # pragma: no cover - Windows
    _resource = None  # type: ignore[assignment]

from ..core.logging import get_logger
from ..core.types import SandboxSpec

__all__ = [
    "ResourceLimits",
    "apply_posix",
    "to_docker_flags",
    "posix_limits_supported",
    "limits_from_spec",
    "preexec_factory",
]

log = get_logger("sandbox.rlimits")

#: Bytes per megabyte, kept explicit so the conversion is auditable.
MB = 1024 * 1024


@dataclass
class ResourceLimits:
    """A single, driver-agnostic resource budget for one sandboxed run.

    Attributes:
        cpu_seconds: Hard CPU-time budget (``RLIMIT_CPU``).  A busy loop is
            killed by SIGKILL once it burns through this, independently of the
            wall-clock timeout, which a sleeping process could otherwise game.
        memory_mb: Address-space cap (``RLIMIT_AS``).  Blocks the classic
            "allocate until the host OOM-killer picks a victim" denial of
            service against the *host*, not just the sandbox.
        max_processes: ``RLIMIT_NPROC`` - the fork-bomb brake.
        max_open_files: ``RLIMIT_NOFILE`` - stops descriptor exhaustion.
        max_file_size_mb: ``RLIMIT_FSIZE`` - stops disk-filling writes.
        core_dump: When False, ``RLIMIT_CORE`` is zeroed so secrets held in
            memory never land on disk as a core file.
        stack_mb: ``RLIMIT_STACK``; 0 leaves the inherited value untouched.
    """

    cpu_seconds: int = 30
    memory_mb: int = 512
    max_processes: int = 64
    max_open_files: int = 256
    max_file_size_mb: int = 64
    core_dump: bool = False
    stack_mb: int = 0

    def as_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe view used in audit payloads."""
        return {
            "cpu_seconds": self.cpu_seconds,
            "memory_mb": self.memory_mb,
            "max_processes": self.max_processes,
            "max_open_files": self.max_open_files,
            "max_file_size_mb": self.max_file_size_mb,
            "core_dump": self.core_dump,
            "stack_mb": self.stack_mb,
        }

    def hardened(self) -> "ResourceLimits":
        """Return a stricter copy suitable for untrusted code."""
        return ResourceLimits(
            cpu_seconds=min(self.cpu_seconds, 10),
            memory_mb=min(self.memory_mb, 256),
            max_processes=min(self.max_processes, 16),
            max_open_files=min(self.max_open_files, 64),
            max_file_size_mb=min(self.max_file_size_mb, 8),
            core_dump=False,
            stack_mb=self.stack_mb,
        )


def limits_from_spec(spec: SandboxSpec) -> ResourceLimits:
    """Derive limits from a :class:`SandboxSpec`.

    The CPU budget is deliberately allowed to exceed the wall-clock timeout by
    a small margin: a process legitimately sleeping on IO should be killed by
    the wall clock (which reports ``timed_out``), while a spinning process
    should hit ``RLIMIT_CPU`` first so the result is attributable.
    """
    cpu = max(1, int(spec.timeout_s * max(0.25, spec.cpu_quota)) + 1)
    return ResourceLimits(
        cpu_seconds=cpu,
        memory_mb=max(32, int(spec.memory_mb)),
        max_processes=max(1, int(spec.pids_limit)),
        max_open_files=256,
        max_file_size_mb=max(1, int(spec.memory_mb) // 4),
        core_dump=False,
    )


def posix_limits_supported() -> bool:
    """True when ``resource.setrlimit`` is usable on this interpreter."""
    return _resource is not None and sys.platform != "win32"


def _set_one(name: str, soft: int, hard: Optional[int] = None) -> Optional[str]:
    """Apply one rlimit, returning an error description on failure."""
    if _resource is None:  # pragma: no cover - Windows
        return f"{name}: resource module unavailable"
    const = getattr(_resource, name, None)
    if const is None:
        return f"{name}: not supported on this platform"
    hard_value = soft if hard is None else hard
    try:
        current_soft, current_hard = _resource.getrlimit(const)
        # Never try to raise a hard limit - an unprivileged process cannot and
        # the resulting ValueError would abort the whole child bootstrap.
        if current_hard != _resource.RLIM_INFINITY:
            soft = min(soft, current_hard)
            hard_value = min(hard_value, current_hard)
        _resource.setrlimit(const, (soft, hard_value))
        return None
    except (ValueError, OSError) as exc:
        return f"{name}: {exc}"


def apply_posix(limits: ResourceLimits) -> List[str]:
    """Apply ``limits`` to the *current* process.

    Intended to run inside ``subprocess.Popen(preexec_fn=...)`` - i.e. in the
    forked child, after ``fork()`` and before ``exec()`` - so the limits are in
    force for the sandboxed program and never leak back into the gateway.

    Returns:
        A list of human-readable descriptions of limits that could **not** be
        applied.  An empty list means full enforcement.
    """
    problems: List[str] = []
    if not posix_limits_supported():
        return ["all: setrlimit unavailable (non-POSIX platform)"]

    checks = [
        ("RLIMIT_CPU", limits.cpu_seconds, limits.cpu_seconds + 1),
        ("RLIMIT_AS", limits.memory_mb * MB, None),
        ("RLIMIT_DATA", limits.memory_mb * MB, None),
        ("RLIMIT_NPROC", limits.max_processes, None),
        ("RLIMIT_NOFILE", limits.max_open_files, None),
        ("RLIMIT_FSIZE", limits.max_file_size_mb * MB, None),
    ]
    if not limits.core_dump:
        checks.append(("RLIMIT_CORE", 0, 0))
    if limits.stack_mb > 0:
        checks.append(("RLIMIT_STACK", limits.stack_mb * MB, None))

    for name, soft, hard in checks:
        problem = _set_one(name, int(soft), None if hard is None else int(hard))
        if problem:
            problems.append(problem)
    return problems


def preexec_factory(limits: ResourceLimits, *, new_session: bool = True) -> Optional[Callable[[], None]]:
    """Build a ``preexec_fn`` closure for :class:`subprocess.Popen`.

    The closure additionally calls ``os.setsid`` so the sandboxed program
    becomes a process-group leader.  That is what makes "kill the whole process
    tree" possible: a single ``killpg`` reaches every descendant, including the
    ones a fork bomb spawned.

    Returns:
        ``None`` on platforms without ``fork`` (Windows), where the caller must
        fall back to job-object / ``taskkill`` based teardown.
    """
    if not posix_limits_supported():
        return None

    import os

    def _preexec() -> None:  # pragma: no cover - runs in the forked child
        if new_session:
            try:
                os.setsid()
            except OSError:
                pass
        apply_posix(limits)

    return _preexec


def to_docker_flags(limits: ResourceLimits, *, cpu_quota: float = 1.0) -> List[str]:
    """Translate the same budget into ``docker run`` command-line flags."""
    flags: List[str] = [
        f"--memory={limits.memory_mb}m",
        # Deny swap entirely: without this a memory-capped container simply
        # swaps and the host pays the price.
        f"--memory-swap={limits.memory_mb}m",
        f"--pids-limit={limits.max_processes}",
        f"--cpus={max(0.05, float(cpu_quota)):.2f}",
        f"--ulimit=nofile={limits.max_open_files}:{limits.max_open_files}",
        f"--ulimit=nproc={limits.max_processes}:{limits.max_processes}",
        f"--ulimit=fsize={limits.max_file_size_mb * MB}",
        f"--ulimit=cpu={limits.cpu_seconds}:{limits.cpu_seconds + 1}",
    ]
    if not limits.core_dump:
        flags.append("--ulimit=core=0:0")
    return flags


def to_firejail_flags(limits: ResourceLimits) -> List[str]:
    """Translate the budget into firejail ``--rlimit-*`` flags."""
    return [
        f"--rlimit-cpu={limits.cpu_seconds}",
        f"--rlimit-as={limits.memory_mb * MB}",
        f"--rlimit-nproc={limits.max_processes}",
        f"--rlimit-nofile={limits.max_open_files}",
        f"--rlimit-fsize={limits.max_file_size_mb * MB}",
    ]


@dataclass
class LimitReport:
    """Diagnostic record describing how well limits were enforced."""

    requested: ResourceLimits = field(default_factory=ResourceLimits)
    enforced: bool = True
    degraded: List[str] = field(default_factory=list)
    platform: str = sys.platform

    def as_dict(self) -> Dict[str, Any]:
        return {
            "requested": self.requested.as_dict(),
            "enforced": self.enforced,
            "degraded": self.degraded,
            "platform": self.platform,
        }
