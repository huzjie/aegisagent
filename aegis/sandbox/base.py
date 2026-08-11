"""Sandbox driver contract shared by every isolation backend.

A driver's only job is to run a command under some isolation primitive and
return a :class:`~aegis.core.types.SandboxResult`.  Everything policy-shaped
(canaries, egress checks, escape adjudication) lives in
:mod:`aegis.sandbox.runner` so that adding a driver never means re-implementing
security logic.
"""

from __future__ import annotations

import abc
import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..core.logging import get_logger
from ..core.types import SandboxKind, SandboxResult, SandboxSpec
from ..core.utils import human_bytes, truncate

__all__ = [
    "SandboxDriver",
    "ExecutionRequest",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "ENV_ALLOWLIST",
    "sanitise_env",
    "clip_output",
]

log = get_logger("sandbox.base")

#: Hard cap on captured stdout/stderr.  Without it a `yes` loop turns a
#: sandboxed run into a memory exhaustion attack on the *gateway*.
DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024

#: The only host environment variables a sandboxed process may inherit.
#: Everything else - and in particular every ``*_TOKEN`` / ``*_KEY`` /
#: ``AWS_*`` / ``AEGIS_*`` variable - is dropped.  Inheriting the parent
#: environment is how a compromised agent reads the gateway's own credentials.
ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM",
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE", "TEMP", "TMP", "HOME", "USERPROFILE",
    "PYTHONIOENCODING", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE",
)

#: Variables that are stripped even if an operator adds them to a spec's env,
#: because they subvert the runtime from the outside.
ENV_DENYLIST_PREFIXES: tuple[str, ...] = (
    "AEGIS_",           # our own control-plane configuration and signing keys
    "AWS_", "AZURE_", "GOOGLE_", "GCP_", "ALIBABA_", "TENCENTCLOUD_",
    "KUBERNETES_", "DOCKER_",
)

ENV_DENYLIST_EXACT: tuple[str, ...] = (
    "LD_PRELOAD",       # arbitrary code injection into every child process
    "LD_LIBRARY_PATH",  # library hijacking
    "DYLD_INSERT_LIBRARIES",
    "PYTHONSTARTUP",    # executes attacker code on interpreter start
    "PYTHONPATH",       # module shadowing
    "NODE_OPTIONS",     # --require lets an attacker preload a module
    "BASH_ENV", "ENV",
    "SSH_AUTH_SOCK",    # agent forwarding = key use without key access
    "GIT_SSH_COMMAND",
)


def sanitise_env(
    spec: SandboxSpec,
    extra: Optional[Mapping[str, str]] = None,
    *,
    inherit: bool = True,
    allowlist: Sequence[str] = ENV_ALLOWLIST,
) -> Dict[str, str]:
    """Build the environment a sandboxed process will see.

    Args:
        spec: Provides ``spec.env`` overrides supplied by policy.
        extra: Additional variables (canaries, proxy settings) merged last.
        inherit: When False not even the allowlisted host variables are copied,
            which is the right default for stdio MCP servers.
        allowlist: Host variables that may be inherited.

    Returns:
        A fresh dict; the caller's ``os.environ`` is never mutated.
    """
    env: Dict[str, str] = {}
    if inherit:
        for name in allowlist:
            value = os.environ.get(name)
            if value is not None:
                env[name] = value
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")

    for source in (dict(spec.env or {}), dict(extra or {})):
        for key, value in source.items():
            name = str(key)
            if name in ENV_DENYLIST_EXACT:
                log.warning("dropped dangerous env var", fields={"name": name})
                continue
            if name.startswith(ENV_DENYLIST_PREFIXES) and not name.startswith("AEGIS_EGRESS"):
                log.debug("dropped host-scoped env var", fields={"name": name})
                continue
            env[name] = str(value)
    return env


def clip_output(data: str, limit: int = DEFAULT_MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    """Trim captured output to ``limit`` bytes.

    Returns:
        ``(text, truncated)``.
    """
    text = data or ""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    clipped = encoded[:limit].decode("utf-8", errors="ignore")
    note = f"\n...[aegis: output truncated at {human_bytes(limit)}]"
    return clipped + note, True


@dataclass
class ExecutionRequest:
    """Everything a driver needs for one run.

    Attributes:
        spec: Isolation parameters (limits, network mode, image).
        command: argv list.  Never a shell string - the drivers do not spawn a
            shell, which removes an entire class of injection.
        stdin: Text piped to the process.
        files: ``relative path -> content`` written into the working directory
            before execution.  Paths are validated by the filesystem jail.
        env: Extra environment variables merged after sanitisation.
        workdir: Host working directory.  When empty the driver allocates a
            fresh temporary directory and removes it afterwards.
        label: Free-form tag used in logs and container names.
        session_id: Correlates the run with canaries and audit events.
        max_output_bytes: Per-stream capture cap.
    """

    spec: SandboxSpec = field(default_factory=SandboxSpec)
    command: List[str] = field(default_factory=list)
    stdin: str = ""
    files: Dict[str, str] = field(default_factory=dict)
    env: Dict[str, str] = field(default_factory=dict)
    workdir: str = ""
    label: str = "run"
    session_id: str = ""
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        if isinstance(self.command, str):
            # Accepting a string would silently invite shell semantics; split
            # it explicitly so the behaviour is visible and quoting-aware.
            import shlex

            self.command = shlex.split(self.command, posix=sys.platform != "win32")

    @property
    def program(self) -> str:
        """The executable being launched, for logging and allowlist checks."""
        return self.command[0] if self.command else ""

    def describe(self) -> Dict[str, Any]:
        """Loggable summary that never includes file contents or stdin."""
        return {
            "program": self.program,
            "argc": len(self.command),
            "command_preview": truncate(" ".join(self.command), 240),
            "files": sorted(self.files),
            "stdin_bytes": len(self.stdin.encode("utf-8", errors="replace")),
            "kind": self.spec.kind.value,
            "timeout_s": self.spec.timeout_s,
            "network": self.spec.network,
            "label": self.label,
            "session_id": self.session_id,
        }


class SandboxDriver(abc.ABC):
    """Abstract isolation backend.

    Implementations must be safe to reuse across threads: :meth:`run` should not
    mutate shared state beyond metrics counters.
    """

    #: Which :class:`SandboxKind` this driver satisfies.
    kind: SandboxKind = SandboxKind.NONE

    #: Rough ordering used by the runner when falling back; higher is stronger.
    isolation_strength: int = 0

    def __init__(self) -> None:
        self._prepared = False
        self.runs = 0
        self.failures = 0

    # ------------------------------------------------------------------ #
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Stable driver identifier recorded in :attr:`SandboxResult.driver`."""

    @abc.abstractmethod
    def available(self) -> bool:
        """True when this driver can actually run on the current host.

        Must never raise: the runner calls it while choosing a fallback chain.
        """

    @abc.abstractmethod
    def run(
        self,
        spec: SandboxSpec,
        command: Sequence[str],
        stdin: str = "",
        files: Optional[Mapping[str, str]] = None,
    ) -> SandboxResult:
        """Execute ``command`` under isolation and return the result.

        Implementations should populate ``timed_out``, ``killed``,
        ``resource_usage`` and ``driver``; they must **not** raise on a non-zero
        exit code - that is a normal outcome, reported via ``exit_code``.
        """

    # ------------------------------------------------------------------ #
    def prepare(self) -> None:
        """Idempotent one-off setup (pull image, materialise seccomp profile)."""
        self._prepared = True

    def cleanup(self) -> None:
        """Release long-lived resources.  Safe to call more than once."""
        self._prepared = False

    def execute(self, request: ExecutionRequest) -> SandboxResult:
        """Convenience wrapper around :meth:`run` taking an :class:`ExecutionRequest`."""
        if not self._prepared:
            self.prepare()
        merged = SandboxSpec(**{**vars(request.spec), "env": {**request.spec.env, **request.env}})
        self.runs += 1
        result = self.run(merged, request.command, request.stdin, request.files)
        if not result.ok:
            self.failures += 1
        return result

    # ------------------------------------------------------------------ #
    # Shared helpers for concrete drivers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _which(program: str) -> Optional[str]:
        """Locate an executable, honouring PATHEXT on Windows."""
        return shutil.which(program)

    def unavailable_result(self, reason: str) -> SandboxResult:
        """Build the standard result for "this driver cannot run here"."""
        return SandboxResult(
            ok=False,
            exit_code=126,
            stderr=f"sandbox driver '{self.name}' unavailable: {reason}",
            driver=self.name,
            resource_usage={"unavailable_reason": reason},
        )

    def stats(self) -> Dict[str, Any]:
        """Driver level counters."""
        return {
            "name": self.name,
            "kind": self.kind.value,
            "available": self.available(),
            "isolation_strength": self.isolation_strength,
            "runs": self.runs,
            "failures": self.failures,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<{self.__class__.__name__} name={self.name} kind={self.kind.value}>"
