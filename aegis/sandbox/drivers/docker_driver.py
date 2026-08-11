"""Container-based sandbox built on the ``docker`` CLI.

No Docker SDK dependency: the driver assembles an argv for ``docker run`` and
shells out.  The flag set is the point of this module, so each group is
justified inline:

``--rm``
    No forensic residue and no disk growth from abandoned containers.
``--network=none``
    Default-deny egress at the kernel level.  An agent cannot exfiltrate over a
    network interface that does not exist.  Allowlisted egress is expressed by
    attaching a dedicated proxy network instead of by opening this up.
``--read-only`` + ``--tmpfs /tmp``
    Immutable root filesystem; the workload gets a small in-memory scratch area
    that vanishes with the container.
``--cap-drop=ALL``
    Removes CAP_SYS_ADMIN, CAP_NET_RAW, CAP_SYS_PTRACE and friends - the
    capabilities every container escape needs.
``--security-opt=no-new-privileges``
    A setuid binary inside the image can no longer raise privileges, which
    neutralises the "drop a setuid shell then re-exec" pattern.
``--security-opt seccomp=<file>``
    Allowlist syscall filter from :mod:`aegis.sandbox.seccomp`.
``--user 10001:10001``
    Never uid 0.  Even if something else fails, the workload is unprivileged
    and cannot write to root-owned paths in the image.
``--pids-limit`` / ``--memory`` / ``--cpus``
    Resource ceilings shared with the subprocess driver.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ...core.errors import SandboxError
from ...core.logging import get_logger
from ...core.types import SandboxKind, SandboxResult, SandboxSpec
from ..base import DEFAULT_MAX_OUTPUT_BYTES, SandboxDriver, clip_output, sanitise_env
from ..rlimits import limits_from_spec, to_docker_flags
from ..seccomp import SeccompProfileBuilder

__all__ = ["DockerDriver"]

log = get_logger("sandbox.driver.docker")

#: Where the caller's files are mounted inside the container.
CONTAINER_WORKDIR = "/workspace"


class DockerDriver(SandboxDriver):
    """Execute a command inside a hardened, throwaway container.

    Args:
        binary: ``docker`` or a drop-in replacement (``podman``, ``nerdctl``).
        seccomp_dir: Where generated seccomp JSON profiles are cached.
        pull_missing: Attempt ``docker pull`` when the image is absent.
        runtime: Optional ``--runtime`` value, e.g. ``runsc`` for gVisor, which
            adds a user-space kernel between the workload and the host.
        extra_flags: Operator supplied flags appended verbatim.
    """

    kind = SandboxKind.DOCKER
    isolation_strength = 80

    def __init__(
        self,
        *,
        binary: str = "docker",
        seccomp_dir: str = "",
        pull_missing: bool = False,
        runtime: str = "",
        extra_flags: Optional[Sequence[str]] = None,
        probe_timeout_s: float = 10.0,
    ) -> None:
        super().__init__()
        self.binary = binary
        self.seccomp_dir = seccomp_dir or os.path.join(tempfile.gettempdir(), "aegis-seccomp")
        self.pull_missing = pull_missing
        self.runtime = runtime
        self.extra_flags = list(extra_flags or [])
        self.probe_timeout_s = probe_timeout_s
        self._available: Optional[bool] = None
        self._unavailable_reason = ""
        self._profiles: Dict[str, str] = {}
        self._known_images: Dict[str, bool] = {}

    # ------------------------------------------------------------------ #
    @property
    def name(self) -> str:
        return f"docker[{self.binary}]" if self.binary != "docker" else "docker"

    def _run_cli(self, args: Sequence[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
        """Invoke the container CLI, never through a shell."""
        return subprocess.run(  # noqa: S603 - argv list, shell=False
            [self.binary, *[str(a) for a in args]],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout or self.probe_timeout_s,
            shell=False,
        )

    def available(self) -> bool:
        """True when the CLI exists *and* the daemon answers.

        A present binary is not enough: a stopped Docker Desktop leaves the
        client installed, and discovering that only at run time turns a
        fallback decision into a hard failure.
        """
        if self._available is not None:
            return self._available
        if shutil.which(self.binary) is None:
            self._available, self._unavailable_reason = False, f"'{self.binary}' not found on PATH"
            return False
        try:
            probe = self._run_cli(["version", "--format", "{{.Server.Version}}"])
        except (OSError, subprocess.SubprocessError) as exc:
            self._available, self._unavailable_reason = False, f"probe failed: {exc}"
            return False
        if probe.returncode != 0:
            self._available = False
            self._unavailable_reason = (
                (probe.stderr or probe.stdout or "daemon unreachable").strip().splitlines()[0]
            )
            return False
        self._available = True
        log.info(
            "container runtime detected",
            fields={"binary": self.binary, "server": (probe.stdout or "").strip()},
        )
        return True

    def unavailable_reason(self) -> str:
        """Human-readable explanation for :meth:`available` returning False."""
        self.available()
        return self._unavailable_reason

    # ------------------------------------------------------------------ #
    def prepare(self) -> None:
        """Materialise the seccomp profiles this driver may reference."""
        builder = SeccompProfileBuilder()
        os.makedirs(self.seccomp_dir, exist_ok=True)
        for profile in ("strict", "default", "network"):
            try:
                path = builder.write(os.path.join(self.seccomp_dir, f"{profile}.json"), profile)
                self._profiles[profile] = str(path)
            except (OSError, SandboxError) as exc:  # pragma: no cover - disk issues
                log.warning(
                    "could not write seccomp profile",
                    fields={"profile": profile, "error": str(exc)},
                )
        super().prepare()

    def image_exists(self, image: str) -> bool:
        """Check the local image cache, optionally pulling."""
        cached = self._known_images.get(image)
        if cached is not None:
            return cached
        try:
            probe = self._run_cli(["image", "inspect", image])
        except (OSError, subprocess.SubprocessError):
            self._known_images[image] = False
            return False
        if probe.returncode == 0:
            self._known_images[image] = True
            return True
        if not self.pull_missing:
            self._known_images[image] = False
            return False
        log.info("pulling sandbox image", fields={"image": image})
        try:
            pull = self._run_cli(["pull", image], timeout=600)
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("image pull failed", fields={"image": image, "error": str(exc)})
            self._known_images[image] = False
            return False
        ok = pull.returncode == 0
        self._known_images[image] = ok
        return ok

    # ------------------------------------------------------------------ #
    def _seccomp_path(self, profile: str) -> str:
        """Return a filesystem path for ``profile``, generating it on demand."""
        name = profile if profile in ("strict", "default", "network") else "default"
        path = self._profiles.get(name)
        if path and os.path.isfile(path):
            return path
        try:
            written = SeccompProfileBuilder().write(
                os.path.join(self.seccomp_dir, f"{name}.json"), name
            )
            self._profiles[name] = str(written)
            return str(written)
        except OSError:  # pragma: no cover - read-only temp dir
            return ""

    def build_command(
        self,
        spec: SandboxSpec,
        command: Sequence[str],
        *,
        container_name: str,
        host_workdir: str,
    ) -> List[str]:
        """Assemble the full ``docker run`` argv.

        Exposed separately so tests and the boundary tester can assert on the
        hardening flags without actually starting a container.
        """
        limits = limits_from_spec(spec)
        argv: List[str] = [self.binary, "run", "--rm", "--name", container_name]

        # --- isolation -------------------------------------------------- #
        network = (spec.network or "deny").lower()
        if network == "deny":
            argv.append("--network=none")
        else:
            # Allowlisted egress is enforced by an out-of-band proxy on a
            # dedicated bridge; the container still cannot see the host LAN.
            argv.append("--network=aegis-egress")
        if spec.read_only_root:
            argv.append("--read-only")
        argv += [
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--tmpfs", "/run:rw,noexec,nosuid,nodev,size=8m",
        ]
        for capability in spec.drop_capabilities or ["ALL"]:
            argv.append(f"--cap-drop={capability}")
        if spec.no_new_privileges:
            argv.append("--security-opt=no-new-privileges")
        seccomp = self._seccomp_path(spec.seccomp_profile or "default")
        if seccomp:
            argv += ["--security-opt", f"seccomp={seccomp}"]
        else:  # pragma: no cover - only when the temp dir is unwritable
            log.warning("running without a custom seccomp profile")
        argv += ["--security-opt", "apparmor=docker-default"]
        argv += ["--user", spec.user or "10001:10001"]
        argv += ["--ipc=none", "--uts=private", "--cgroupns=private"]
        if self.runtime:
            argv += ["--runtime", self.runtime]

        # --- resources -------------------------------------------------- #
        argv += to_docker_flags(limits, cpu_quota=spec.cpu_quota)
        argv += ["--oom-kill-disable=false"]

        # --- workspace -------------------------------------------------- #
        argv += ["-v", f"{host_workdir}:{CONTAINER_WORKDIR}:rw"]
        argv += ["-w", CONTAINER_WORKDIR]
        for extra in spec.writable_paths or []:
            argv += ["--tmpfs", f"{extra}:rw,noexec,nosuid,nodev,size=32m"]

        # --- environment ------------------------------------------------ #
        for key, value in sanitise_env(spec, inherit=False).items():
            argv += ["-e", f"{key}={value}"]

        argv += ["--label", "aegis.sandbox=true", "--label", f"aegis.profile={spec.seccomp_profile}"]
        argv += [str(flag) for flag in self.extra_flags]
        argv += ["-i", spec.image]
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
        """Run ``command`` in a hardened container."""
        if not self.available():
            return self.unavailable_result(self._unavailable_reason or "docker unavailable")
        if not command:
            return SandboxResult(ok=False, exit_code=2, stderr="empty command", driver=self.name)
        if not self.image_exists(spec.image):
            return SandboxResult(
                ok=False,
                exit_code=125,
                stderr=(
                    f"image '{spec.image}' is not present locally"
                    + ("" if self.pull_missing else " and pull_missing is disabled")
                ),
                driver=self.name,
                resource_usage={"image": spec.image, "missing": True},
            )

        host_workdir = tempfile.mkdtemp(prefix="aegis-docker-")
        # Container name collisions abort the run, so make it unique per attempt.
        container_name = f"aegis-{uuid.uuid4().hex[:16]}"
        try:
            self._write_files(host_workdir, files)
            argv = self.build_command(
                spec, command, container_name=container_name, host_workdir=host_workdir
            )
            return self._execute(argv, stdin, spec, container_name, host_workdir)
        finally:
            shutil.rmtree(host_workdir, ignore_errors=True)

    def _write_files(self, host_workdir: str, files: Optional[Mapping[str, str]]) -> None:
        """Materialise inputs into the bind-mounted directory."""
        for relative, content in (files or {}).items():
            safe = os.path.normpath(str(relative)).replace("\\", "/").lstrip("/")
            if safe.startswith("..") or os.path.isabs(safe):
                log.warning("refusing to write file outside the mount", fields={"path": relative})
                continue
            target = os.path.join(host_workdir, safe)
            os.makedirs(os.path.dirname(target) or host_workdir, exist_ok=True)
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(str(content))

    def _execute(
        self,
        argv: List[str],
        stdin: str,
        spec: SandboxSpec,
        container_name: str,
        host_workdir: str,
    ) -> SandboxResult:
        """Start the container and enforce the wall-clock deadline."""
        started = time.perf_counter()
        timed_out = False
        killed = False
        try:
            process = subprocess.Popen(  # noqa: S603 - argv list, shell=False
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return SandboxResult(
                ok=False,
                exit_code=127,
                stderr=f"failed to start container: {exc}",
                driver=self.name,
                duration_ms=(time.perf_counter() - started) * 1000.0,
            )

        # Give docker a small grace period on top of the workload budget so the
        # image start-up cost is not charged against the user's timeout.
        deadline = max(1.0, float(spec.timeout_s)) + 5.0
        try:
            stdout, stderr = process.communicate(input=stdin, timeout=deadline)
        except subprocess.TimeoutExpired:
            timed_out = True
            killed = self._kill_container(container_name)
            try:
                process.kill()
                stdout, stderr = process.communicate(timeout=10)
            except (subprocess.TimeoutExpired, ValueError, OSError):  # pragma: no cover
                stdout, stderr = "", ""
            stderr = (stderr or "") + f"\n[aegis] container killed after {spec.timeout_s}s"

        duration_ms = (time.perf_counter() - started) * 1000.0
        exit_code = process.returncode if process.returncode is not None else -1
        stdout, out_trunc = clip_output(stdout or "", DEFAULT_MAX_OUTPUT_BYTES)
        stderr, err_trunc = clip_output(stderr or "", DEFAULT_MAX_OUTPUT_BYTES)

        usage: Dict[str, Any] = {
            "driver": self.name,
            "image": spec.image,
            "container": container_name,
            "isolated": True,
            "network": spec.network,
            "seccomp_profile": spec.seccomp_profile,
            "user": spec.user,
            "read_only_root": spec.read_only_root,
            "resource_limits": limits_from_spec(spec).as_dict(),
            "resource_limits_enforced": True,
            "flags": [a for a in argv if a.startswith("--")],
            "truncated": out_trunc or err_trunc,
            "host_workdir": host_workdir,
            "platform": sys.platform,
        }
        if exit_code == 137:
            usage["oom_killed_or_sigkill"] = True

        return SandboxResult(
            ok=exit_code == 0 and not timed_out,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            killed=killed,
            driver=self.name,
            resource_usage=usage,
        )

    def _kill_container(self, container_name: str) -> bool:
        """``docker kill`` the container; SIGKILL, not a polite stop."""
        try:
            killed = self._run_cli(["kill", container_name], timeout=30)
            if killed.returncode != 0:
                self._run_cli(["rm", "-f", container_name], timeout=30)
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning(
                "failed to kill container",
                fields={"container": container_name, "error": str(exc)},
            )
            return False

    # ------------------------------------------------------------------ #
    def inspect_hardening(self, spec: SandboxSpec) -> Dict[str, Any]:
        """Report the hardening flags a run with ``spec`` would use."""
        argv = self.build_command(
            spec, ["true"], container_name="aegis-inspect", host_workdir=tempfile.gettempdir()
        )
        flags = [a for a in argv if a.startswith("-")]
        return {
            "network_none": "--network=none" in argv,
            "read_only": "--read-only" in argv,
            "cap_drop_all": "--cap-drop=ALL" in argv,
            "no_new_privileges": "--security-opt=no-new-privileges" in argv,
            "seccomp": any("seccomp=" in a for a in argv),
            "non_root_user": "0:0" not in " ".join(argv),
            "pids_limited": any(a.startswith("--pids-limit") for a in argv),
            "memory_limited": any(a.startswith("--memory=") for a in argv),
            "flags": flags,
        }

    def cleanup(self) -> None:
        """Remove any stray containers this driver labelled."""
        if not self.available():
            super().cleanup()
            return
        try:
            listing = self._run_cli(["ps", "-aq", "--filter", "label=aegis.sandbox=true"])
            for container_id in (listing.stdout or "").split():
                self._run_cli(["rm", "-f", container_id], timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
            log.debug("container cleanup skipped", fields={"error": str(exc)})
        super().cleanup()

    def runtime_info(self) -> Dict[str, Any]:
        """Structured runtime details for the health endpoint."""
        if not self.available():
            return {"available": False, "reason": self._unavailable_reason}
        try:
            info = self._run_cli(["info", "--format", "{{json .}}"])
            parsed = json.loads(info.stdout) if info.returncode == 0 and info.stdout else {}
        except (OSError, subprocess.SubprocessError, ValueError):  # pragma: no cover
            parsed = {}
        return {
            "available": True,
            "binary": self.binary,
            "runtime": self.runtime or parsed.get("DefaultRuntime", ""),
            "security_options": parsed.get("SecurityOptions", []),
            "server_version": parsed.get("ServerVersion", ""),
        }
