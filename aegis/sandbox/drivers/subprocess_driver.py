"""Cross-platform process-level sandbox.

This is the always-available fallback: no daemon, no kernel features beyond
what the platform already offers.  What it does provide:

* a fresh temporary working directory per run, guarded by
  :class:`~aegis.sandbox.fsjail.FilesystemJail`;
* an environment built from an allowlist, so the gateway's own credentials are
  never inherited;
* wall-clock timeout with **process-tree** teardown - killing only the direct
  child leaves orphaned grandchildren still holding the network and the CPU;
* output truncation, so a runaway writer cannot exhaust gateway memory;
* on POSIX, ``resource.setrlimit`` for CPU / address space / process count /
  file descriptors / file size, applied in the forked child via ``preexec_fn``.

On Windows ``setrlimit`` does not exist.  The driver degrades explicitly: it
records ``resource_limits_enforced=False`` plus the list of limits it could not
apply, and it uses ``taskkill /T`` for tree teardown.  Callers that need hard
memory/CPU caps on Windows must use the Docker driver - the honest answer is
that a bare Win32 process cannot be capped without a Job Object, which the
standard library does not expose.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ...core.errors import SandboxEscapeDetected
from ...core.logging import get_logger
from ...core.types import SandboxKind, SandboxResult, SandboxSpec
from ..base import DEFAULT_MAX_OUTPUT_BYTES, SandboxDriver, clip_output, sanitise_env
from ..fsjail import FilesystemJail
from ..rlimits import (
    ResourceLimits,
    limits_from_spec,
    posix_limits_supported,
    preexec_factory,
)

__all__ = ["SubprocessDriver"]

log = get_logger("sandbox.driver.subprocess")

IS_WINDOWS = sys.platform == "win32"


class SubprocessDriver(SandboxDriver):
    """Run a command as an isolated child process.

    Args:
        base_dir: Parent directory for per-run temporary workspaces.
        keep_workdir: Leave the workspace on disk after the run (debugging).
        interpreter_allowlist: When non-empty, only these program basenames may
            be launched.  Defence in depth against a policy bug letting an
            arbitrary host binary through.
    """

    kind = SandboxKind.SUBPROCESS
    isolation_strength = 20

    def __init__(
        self,
        *,
        base_dir: str = "",
        keep_workdir: bool = False,
        interpreter_allowlist: Optional[Sequence[str]] = None,
    ) -> None:
        super().__init__()
        self.base_dir = base_dir or os.path.join(tempfile.gettempdir(), "aegis-sandbox")
        self.keep_workdir = keep_workdir
        self.interpreter_allowlist = {str(p).lower() for p in (interpreter_allowlist or [])}
        self._created_dirs: List[str] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    @property
    def name(self) -> str:
        return "subprocess"

    def available(self) -> bool:
        """Always true - the standard library can always spawn a process."""
        return True

    def prepare(self) -> None:
        """Ensure the workspace parent directory exists."""
        os.makedirs(self.base_dir, exist_ok=True)
        super().prepare()

    def cleanup(self) -> None:
        """Remove any workspaces still on disk."""
        with self._lock:
            pending, self._created_dirs = list(self._created_dirs), []
        for path in pending:
            shutil.rmtree(path, ignore_errors=True)
        super().cleanup()

    # ------------------------------------------------------------------ #
    def _check_program(self, program: str) -> Optional[str]:
        """Validate the executable, returning an error string when refused."""
        if not program:
            return "empty command"
        if self.interpreter_allowlist:
            base = os.path.basename(program).lower()
            stem = base[:-4] if base.endswith(".exe") else base
            if base not in self.interpreter_allowlist and stem not in self.interpreter_allowlist:
                return f"program '{program}' is not in the interpreter allowlist"
        if os.path.isabs(program) and not os.path.exists(program):
            return f"program '{program}' does not exist"
        if not os.path.isabs(program) and shutil.which(program) is None:
            return f"program '{program}' not found on PATH"
        return None

    def _make_workdir(self, spec: SandboxSpec) -> FilesystemJail:
        """Allocate the per-run jail."""
        os.makedirs(self.base_dir, exist_ok=True)
        path = tempfile.mkdtemp(prefix="run-", dir=self.base_dir)
        with self._lock:
            self._created_dirs.append(path)
        jail = FilesystemJail(
            path,
            writable_paths=[],
            follow_symlinks=True,
        )
        for relative in spec.writable_paths or []:
            try:
                jail.add_writable(relative)
            except SandboxEscapeDetected:
                log.warning(
                    "ignoring writable path that escapes the jail",
                    fields={"path": relative},
                )
        return jail

    @staticmethod
    def _terminate_tree(process: "subprocess.Popen[str]") -> bool:
        """Kill the child *and every descendant*.

        Returns:
            True when a kill was actually issued.
        """
        if process.poll() is not None:
            return False
        try:
            if IS_WINDOWS:
                # taskkill /T walks the child tree; /F is SIGKILL-equivalent.
                subprocess.run(  # noqa: S603 - fixed argv
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    capture_output=True,
                    timeout=10,
                    shell=False,
                )
            else:
                # preexec_fn called setsid(), so the child leads its own group
                # and one killpg reaches every descendant, fork bombs included.
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    process.kill()
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("process tree teardown failed", fields={"error": str(exc)})
            try:
                process.kill()
            except OSError:
                return False
        return True

    # ------------------------------------------------------------------ #
    def run(
        self,
        spec: SandboxSpec,
        command: Sequence[str],
        stdin: str = "",
        files: Optional[Mapping[str, str]] = None,
    ) -> SandboxResult:
        """Execute ``command`` in a throwaway workspace under resource limits."""
        argv = [str(part) for part in command]
        problem = self._check_program(argv[0] if argv else "")
        if problem:
            return SandboxResult(
                ok=False, exit_code=127, stderr=problem, driver=self.name,
                resource_usage={"rejected": problem},
            )

        jail = self._make_workdir(spec)
        limits = limits_from_spec(spec)
        degraded: List[str] = []

        try:
            self._materialise_files(jail, files, degraded)
            env = self._build_env(spec, jail)
            return self._spawn(argv, stdin, spec, jail, limits, env, degraded)
        finally:
            if not self.keep_workdir:
                shutil.rmtree(jail.root, ignore_errors=True)
                with self._lock:
                    if jail.root in self._created_dirs:
                        self._created_dirs.remove(jail.root)

    # ------------------------------------------------------------------ #
    def _materialise_files(
        self,
        jail: FilesystemJail,
        files: Optional[Mapping[str, str]],
        degraded: List[str],
    ) -> None:
        """Write caller-supplied files through the jail."""
        for relative, content in (files or {}).items():
            try:
                target = jail.resolve(relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(str(content), encoding="utf-8")
            except SandboxEscapeDetected as exc:
                degraded.append(f"file '{relative}' rejected: {exc.message}")
                log.warning(
                    "refused to materialise file outside the jail",
                    fields={"path": relative},
                )
            except OSError as exc:
                degraded.append(f"file '{relative}' write failed: {exc}")

    def _build_env(self, spec: SandboxSpec, jail: FilesystemJail) -> Dict[str, str]:
        """Environment for the child, with the workspace as HOME and TEMP."""
        env = sanitise_env(spec)
        env["HOME"] = jail.root
        env["USERPROFILE"] = jail.root
        env["TMPDIR"] = jail.root
        env["TEMP"] = jail.root
        env["TMP"] = jail.root
        env["PWD"] = jail.root
        return env

    def _spawn(
        self,
        argv: List[str],
        stdin: str,
        spec: SandboxSpec,
        jail: FilesystemJail,
        limits: ResourceLimits,
        env: Dict[str, str],
        degraded: List[str],
    ) -> SandboxResult:
        """Launch the process and collect its result."""
        preexec = preexec_factory(limits) if not IS_WINDOWS else None
        if IS_WINDOWS:
            degraded.append(
                "resource limits (CPU/memory/nproc/nofile) are not enforceable on "
                "Windows without a Job Object; only the wall-clock timeout and "
                "process-tree teardown apply. Use the docker driver for hard caps."
            )
        elif not posix_limits_supported():  # pragma: no cover - exotic platforms
            degraded.append("resource module unavailable; rlimits not applied")

        creationflags = 0
        if IS_WINDOWS:
            # A new process group makes taskkill /T reliable and stops Ctrl-C in
            # the parent console from reaching the sandboxed child.
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)

        started = time.perf_counter()
        try:
            process = subprocess.Popen(  # noqa: S603 - argv list, shell=False
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=jail.root,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                preexec_fn=preexec,  # noqa: PLW1509 - intentional, POSIX only
                creationflags=creationflags,
                close_fds=True,
            )
        except (OSError, ValueError) as exc:
            return SandboxResult(
                ok=False,
                exit_code=127,
                stderr=f"failed to launch '{argv[0]}': {exc}",
                driver=self.name,
                duration_ms=(time.perf_counter() - started) * 1000.0,
                resource_usage={"degraded": degraded},
            )

        timed_out = False
        killed = False
        try:
            stdout, stderr = process.communicate(
                input=stdin, timeout=max(0.1, float(spec.timeout_s))
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            killed = self._terminate_tree(process)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except (subprocess.TimeoutExpired, ValueError):  # pragma: no cover
                stdout, stderr = "", ""
            stderr = (stderr or "") + (
                f"\n[aegis] killed after wall-clock timeout of {spec.timeout_s}s"
            )
        except (OSError, ValueError) as exc:  # pragma: no cover - pipe teardown
            self._terminate_tree(process)
            stdout, stderr = "", f"communication failure: {exc}"

        duration_ms = (time.perf_counter() - started) * 1000.0
        exit_code = process.returncode if process.returncode is not None else -1
        stdout, out_trunc = clip_output(stdout or "", DEFAULT_MAX_OUTPUT_BYTES)
        stderr, err_trunc = clip_output(stderr or "", DEFAULT_MAX_OUTPUT_BYTES)

        escaping_links = jail.scan_for_links()
        usage = self._collect_usage(limits, degraded, jail, escaping_links)
        usage["truncated"] = out_trunc or err_trunc
        usage["exit_signal"] = self._signal_name(exit_code)

        return SandboxResult(
            ok=(exit_code == 0) and not timed_out and not escaping_links,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            killed=killed,
            escape_detected=bool(escaping_links) or bool(jail.violations),
            driver=self.name,
            resource_usage=usage,
        )

    @staticmethod
    def _signal_name(exit_code: int) -> str:
        """Map a negative POSIX exit code back to its signal name."""
        if exit_code >= 0 or IS_WINDOWS:
            return ""
        try:
            return signal.Signals(-exit_code).name
        except (ValueError, AttributeError):  # pragma: no cover
            return f"signal-{-exit_code}"

    def _collect_usage(
        self,
        limits: ResourceLimits,
        degraded: List[str],
        jail: FilesystemJail,
        escaping_links: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Assemble the resource-usage payload attached to the result."""
        usage: Dict[str, Any] = {
            "driver": self.name,
            "platform": sys.platform,
            "isolated": True,
            "resource_limits": limits.as_dict(),
            "resource_limits_enforced": posix_limits_supported() and not IS_WINDOWS,
            "degraded": degraded,
            "jail": jail.stats(),
        }
        if escaping_links:
            usage["escaping_symlinks"] = escaping_links
        if not IS_WINDOWS:  # pragma: no cover - POSIX only
            try:
                import resource as _resource

                children = _resource.getrusage(_resource.RUSAGE_CHILDREN)
                usage["cpu_user_s"] = round(children.ru_utime, 4)
                usage["cpu_system_s"] = round(children.ru_stime, 4)
                usage["max_rss_kb"] = int(children.ru_maxrss)
            except (ImportError, OSError, ValueError):
                pass
        return usage
