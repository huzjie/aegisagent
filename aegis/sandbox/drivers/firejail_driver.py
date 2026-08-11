"""Firejail sandbox (Linux only).

Firejail sits between "just a subprocess" and "a whole container": it uses the
same kernel primitives Docker does - namespaces, seccomp, capability dropping -
but needs no daemon, no image and no root.  On a Linux CI runner where Docker
is unavailable (the exact situation that made CVE-2026-12537 exploitable), this
is the strongest isolation still reachable.

Flags used, and why:

``--net=none``
    New empty network namespace: no interfaces, no metadata endpoint, no DNS.
``--private``
    Fresh tmpfs ``$HOME``; the real home directory - SSH keys, cloud config,
    shell history - simply is not there.
``--private-tmp`` / ``--private-dev``
    Isolated ``/tmp`` and a minimal ``/dev`` without ``/dev/mem`` or loop
    devices.
``--seccomp``
    Blocks the escape-primitive syscalls (mount, ptrace, kexec, ...).
``--caps.drop=all`` / ``--nogroups`` / ``--noroot``
    No capabilities, no supplementary groups, and a user namespace where uid 0
    does not exist - so a setuid binary has nothing to escalate to.
``--nonewprivs``
    Same guarantee as Docker's ``no-new-privileges``.
``--rlimit-*``
    The shared resource budget.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ...core.logging import get_logger
from ...core.types import SandboxKind, SandboxResult, SandboxSpec
from ..base import DEFAULT_MAX_OUTPUT_BYTES, SandboxDriver, clip_output, sanitise_env
from ..rlimits import limits_from_spec, to_firejail_flags

__all__ = ["FirejailDriver"]

log = get_logger("sandbox.driver.firejail")

IS_LINUX = sys.platform.startswith("linux")


class FirejailDriver(SandboxDriver):
    """Run a command under ``firejail``.

    Args:
        binary: Path to the firejail executable.
        profile: Optional firejail profile file to layer on top of the flags.
        allow_network_allowlist: When the spec asks for allowlisted egress,
            firejail cannot express per-host rules, so the driver keeps
            ``--net=none`` and relies on the HTTP proxy environment instead.
            Set this False to refuse such specs outright.
    """

    kind = SandboxKind.FIREJAIL
    isolation_strength = 60

    def __init__(
        self,
        *,
        binary: str = "firejail",
        profile: str = "",
        allow_network_allowlist: bool = True,
        probe_timeout_s: float = 10.0,
    ) -> None:
        super().__init__()
        self.binary = binary
        self.profile = profile
        self.allow_network_allowlist = allow_network_allowlist
        self.probe_timeout_s = probe_timeout_s
        self._available: Optional[bool] = None
        self._unavailable_reason = ""
        self._version = ""

    @property
    def name(self) -> str:
        return "firejail"

    # ------------------------------------------------------------------ #
    def available(self) -> bool:
        """True only on Linux with a working firejail binary."""
        if self._available is not None:
            return self._available
        if not IS_LINUX:
            self._available = False
            self._unavailable_reason = f"firejail requires Linux (running on {sys.platform})"
            return False
        if shutil.which(self.binary) is None:
            self._available = False
            self._unavailable_reason = f"'{self.binary}' not found on PATH"
            return False
        try:
            probe = subprocess.run(  # noqa: S603 - fixed argv
                [self.binary, "--version"],
                capture_output=True,
                text=True,
                timeout=self.probe_timeout_s,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self._available = False
            self._unavailable_reason = f"probe failed: {exc}"
            return False
        if probe.returncode != 0:
            self._available = False
            self._unavailable_reason = (probe.stderr or "firejail --version failed").strip()
            return False
        self._version = (probe.stdout or "").strip().splitlines()[0] if probe.stdout else ""
        self._available = True
        return True

    def unavailable_reason(self) -> str:
        """Explanation for an unavailable driver."""
        self.available()
        return self._unavailable_reason

    # ------------------------------------------------------------------ #
    def build_command(
        self,
        spec: SandboxSpec,
        command: Sequence[str],
        *,
        workdir: str,
    ) -> List[str]:
        """Assemble the firejail argv, exposed for inspection and tests."""
        limits = limits_from_spec(spec)
        argv: List[str] = [
            self.binary,
            "--quiet",
            "--net=none",
            "--private",
            f"--private-cwd={workdir}",
            "--private-tmp",
            "--private-dev",
            "--seccomp",
            "--caps.drop=all",
            "--nogroups",
            "--noroot",
            "--nonewprivs",
            "--noprofile" if not self.profile else f"--profile={self.profile}",
            "--disable-mnt",
            "--shell=none",
            "--x11=none",
            "--nodbus",
            "--machine-id",
        ]
        if spec.read_only_root:
            argv += ["--read-only=/", f"--read-write={workdir}"]
        for writable in spec.writable_paths or []:
            argv.append(f"--read-write={writable}")
        argv += to_firejail_flags(limits)
        argv += ["--timeout=" + _hhmmss(spec.timeout_s)]
        argv += ["--"]
        argv += [str(part) for part in command]
        return argv

    # ------------------------------------------------------------------ #
    def run(
        self,
        spec: SandboxSpec,
        command: Sequence[str],
        stdin: str = "",
        files: Optional[Mapping[str, str]] = None,
    ) -> SandboxResult:
        """Run ``command`` under firejail in a throwaway directory."""
        if not self.available():
            return self.unavailable_result(self._unavailable_reason or "firejail unavailable")
        if not command:
            return SandboxResult(ok=False, exit_code=2, stderr="empty command", driver=self.name)
        if (spec.network or "deny").lower() != "deny" and not self.allow_network_allowlist:
            return self.unavailable_result(
                "firejail cannot express a per-host egress allowlist; "
                "use the docker driver with a proxy network"
            )

        workdir = tempfile.mkdtemp(prefix="aegis-firejail-")
        try:
            for relative, content in (files or {}).items():
                safe = os.path.normpath(str(relative)).lstrip("/")
                if safe.startswith(".."):
                    log.warning("refusing file outside workdir", fields={"path": relative})
                    continue
                target = os.path.join(workdir, safe)
                os.makedirs(os.path.dirname(target) or workdir, exist_ok=True)
                with open(target, "w", encoding="utf-8") as handle:
                    handle.write(str(content))

            argv = self.build_command(spec, command, workdir=workdir)
            env = sanitise_env(spec)
            env["HOME"] = workdir

            started = time.perf_counter()
            timed_out = False
            killed = False
            try:
                completed = subprocess.run(  # noqa: S603 - argv list, shell=False
                    argv,
                    input=stdin,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    # Firejail enforces its own --timeout; this outer deadline
                    # only catches firejail itself wedging.
                    timeout=max(1.0, float(spec.timeout_s)) + 10.0,
                    cwd=workdir,
                    env=env,
                    shell=False,
                )
                stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                killed = True
                stdout = _as_text(exc.stdout)
                stderr = _as_text(exc.stderr) + f"\n[aegis] firejail exceeded {spec.timeout_s}s"
                code = 124
            except (OSError, subprocess.SubprocessError) as exc:
                return SandboxResult(
                    ok=False,
                    exit_code=127,
                    stderr=f"firejail launch failed: {exc}",
                    driver=self.name,
                )

            duration_ms = (time.perf_counter() - started) * 1000.0
            stdout, out_trunc = clip_output(stdout or "", DEFAULT_MAX_OUTPUT_BYTES)
            stderr, err_trunc = clip_output(stderr or "", DEFAULT_MAX_OUTPUT_BYTES)
            usage: Dict[str, Any] = {
                "driver": self.name,
                "isolated": True,
                "firejail_version": self._version,
                "resource_limits": limits_from_spec(spec).as_dict(),
                "resource_limits_enforced": True,
                "network": "none",
                "flags": [a for a in argv if a.startswith("--")],
                "truncated": out_trunc or err_trunc,
            }
            return SandboxResult(
                ok=code == 0 and not timed_out,
                exit_code=code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                timed_out=timed_out,
                killed=killed,
                driver=self.name,
                resource_usage=usage,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


def _hhmmss(seconds: float) -> str:
    """Render seconds as firejail's ``hh:mm:ss`` timeout format."""
    total = max(1, int(seconds))
    return f"{total // 3600:02d}:{(total % 3600) // 60:02d}:{total % 60:02d}"


def _as_text(value: Any) -> str:
    """Normalise bytes/str/None captured from a timed-out process."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)
