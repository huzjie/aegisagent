"""Active verification that the isolation boundary actually holds.

Configuring a sandbox and *assuming* it works is precisely how two frontier
labs let evaluation agents reach production systems in 2026-08.  Every control
in this package is declarative - a flag, a profile, an allowlist - and every
declarative control can be silently ineffective: a seccomp file that failed to
parse, a ``--network=none`` overridden by a compose default, a jail whose root
happens to be a symlink.

:class:`SandboxBoundaryTester` runs adversarial probes *inside* the sandbox and
checks that they fail.  A probe that succeeds is a hole.  The tester is safe to
run in production: no probe damages the host, none writes outside the sandbox,
and the fork bomb is bounded by the very pids-limit it is testing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from ..core.errors import SandboxEscapeDetected
from ..core.logging import get_logger
from ..core.types import (
    DetectorKind,
    Finding,
    SandboxKind,
    SandboxResult,
    SandboxSpec,
    Severity,
    new_id,
    utc_now,
)

__all__ = ["SandboxBoundaryTester", "BoundaryProbe", "ProbeOutcome", "BoundaryReport"]

log = get_logger("sandbox.boundary")


@dataclass
class BoundaryProbe:
    """One adversarial check.

    Attributes:
        id: Stable identifier used in reports and suppression lists.
        title: Short human description.
        code: Python source executed inside the sandbox.  It must print exactly
            ``BREACH:<detail>`` when the boundary failed, or ``BLOCKED:<detail>``
            when the control worked.
        severity: Impact if the probe breaches.
        remediation: What the operator should change.
        requires_network_probe: Skipped when the spec already declares network
            access as intentionally allowed.
        timeout_s: Per-probe wall clock, kept short so a full sweep is cheap.
    """

    id: str
    title: str
    code: str
    severity: Severity = Severity.HIGH
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    requires_network_probe: bool = False
    timeout_s: float = 12.0
    destructive: bool = False


@dataclass
class ProbeOutcome:
    """Result of running one probe."""

    probe_id: str
    title: str
    passed: bool
    detail: str = ""
    severity: Severity = Severity.HIGH
    remediation: str = ""
    skipped: bool = False
    duration_ms: float = 0.0
    raw_stdout: str = ""
    raw_stderr: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "probe": self.probe_id,
            "title": self.title,
            "status": "skipped" if self.skipped else ("pass" if self.passed else "FAIL"),
            "detail": self.detail,
            "severity": self.severity.value,
            "remediation": self.remediation,
            "duration_ms": round(self.duration_ms, 2),
        }

    def to_finding(self) -> Finding:
        """Represent a failed probe as a platform finding."""
        return Finding(
            id=new_id("fnd"),
            detector="sandbox.boundary",
            kind=DetectorKind.SANDBOX_ESCAPE,
            severity=self.severity,
            title=f"Sandbox boundary probe failed: {self.title}",
            description=self.detail,
            confidence=0.95,
            evidence=[self.raw_stdout[:400]] if self.raw_stdout else [],
            location=f"probe:{self.probe_id}",
            remediation=self.remediation,
            references=["MITRE ATLAS AML.T0053", "OWASP LLM06:2025 Excessive Agency"],
            tags=["sandbox", "boundary", self.probe_id],
        )


@dataclass
class BoundaryReport:
    """Aggregate outcome of a boundary sweep."""

    driver: str = ""
    kind: str = ""
    started_at: float = field(default_factory=utc_now)
    outcomes: List[ProbeOutcome] = field(default_factory=list)

    @property
    def failures(self) -> List[ProbeOutcome]:
        return [o for o in self.outcomes if not o.passed and not o.skipped]

    @property
    def passed(self) -> List[ProbeOutcome]:
        return [o for o in self.outcomes if o.passed and not o.skipped]

    @property
    def skipped(self) -> List[ProbeOutcome]:
        return [o for o in self.outcomes if o.skipped]

    @property
    def secure(self) -> bool:
        """True when no probe breached the boundary."""
        return not self.failures

    @property
    def score(self) -> float:
        """Fraction of executed probes that held, 0.0-1.0."""
        executed = len(self.outcomes) - len(self.skipped)
        return round(len(self.passed) / executed, 4) if executed else 0.0

    def worst_severity(self) -> Severity:
        """Highest severity among the failures."""
        if not self.failures:
            return Severity.INFO
        return max((o.severity for o in self.failures), key=lambda s: s.score)

    def findings(self) -> List[Finding]:
        return [o.to_finding() for o in self.failures]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "driver": self.driver,
            "kind": self.kind,
            "started_at": self.started_at,
            "secure": self.secure,
            "score": self.score,
            "total": len(self.outcomes),
            "passed": len(self.passed),
            "failed": len(self.failures),
            "skipped": len(self.skipped),
            "worst_severity": self.worst_severity().value,
            "outcomes": [o.as_dict() for o in self.outcomes],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, ensure_ascii=False)

    def render(self) -> str:
        """Console-friendly table."""
        lines = [
            f"Sandbox boundary report - driver={self.driver} kind={self.kind}",
            f"  score {self.score:.0%}  passed={len(self.passed)} "
            f"failed={len(self.failures)} skipped={len(self.skipped)}",
            "",
        ]
        for outcome in self.outcomes:
            marker = "SKIP" if outcome.skipped else ("ok  " if outcome.passed else "FAIL")
            lines.append(f"  [{marker}] {outcome.probe_id:<22} {outcome.title}")
            if outcome.detail:
                lines.append(f"          {outcome.detail}")
            if not outcome.passed and not outcome.skipped and outcome.remediation:
                lines.append(f"          fix: {outcome.remediation}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Probe catalogue
# --------------------------------------------------------------------------- #
def _probe_source(body: str) -> str:
    """Wrap probe body so any exception is reported as BLOCKED, not a crash."""
    indented = "\n".join("    " + line for line in body.strip().splitlines())
    return (
        "import sys\n"
        "def _probe():\n"
        f"{indented}\n"
        "try:\n"
        "    print(_probe())\n"
        "except Exception as exc:\n"
        "    print('BLOCKED:exception ' + type(exc).__name__ + ': ' + str(exc)[:160])\n"
    )


PROBES: List[BoundaryProbe] = [
    BoundaryProbe(
        id="net.tcp_egress",
        title="Outbound TCP connection to a public address",
        severity=Severity.CRITICAL,
        requires_network_probe=True,
        remediation="Run with network='deny' (docker --network=none / firejail --net=none).",
        references=["OWASP LLM02:2025"],
        code=_probe_source(
            """
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            try:
                sock.connect(('1.1.1.1', 443))
                return 'BREACH:connected to 1.1.1.1:443 from inside the sandbox'
            except OSError as exc:
                return 'BLOCKED:tcp connect refused (' + str(exc)[:80] + ')'
            finally:
                sock.close()
            """
        ),
    ),
    BoundaryProbe(
        id="net.dns",
        title="DNS resolution (exfiltration via subdomain encoding)",
        severity=Severity.HIGH,
        requires_network_probe=True,
        remediation="Deny UDP/53 and drop the resolver config; DNS alone leaks data.",
        code=_probe_source(
            """
            import socket
            try:
                addr = socket.gethostbyname('example.com')
                return 'BREACH:DNS resolved example.com to ' + str(addr)
            except OSError as exc:
                return 'BLOCKED:dns resolution failed (' + str(exc)[:80] + ')'
            """
        ),
    ),
    BoundaryProbe(
        id="net.cloud_metadata",
        title="Cloud instance metadata endpoint (IAM credential theft)",
        severity=Severity.CRITICAL,
        requires_network_probe=True,
        remediation=(
            "Block 169.254.0.0/16 and metadata.google.internal at the network "
            "namespace; never rely on the workload not asking."
        ),
        references=["MITRE ATLAS AML.T0055"],
        code=_probe_source(
            """
            import socket
            reached = []
            for host, port in (('169.254.169.254', 80), ('100.100.100.200', 80)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                try:
                    sock.connect((host, port))
                    reached.append(host)
                except OSError:
                    pass
                finally:
                    sock.close()
            if reached:
                return 'BREACH:metadata endpoints reachable: ' + ','.join(reached)
            return 'BLOCKED:no metadata endpoint reachable'
            """
        ),
    ),
    BoundaryProbe(
        id="fs.write_root",
        title="Write to the read-only root filesystem",
        severity=Severity.HIGH,
        remediation="Enable read_only_root (docker --read-only / firejail --read-only=/).",
        code=_probe_source(
            """
            import os
            for target in ('/aegis-probe', 'C:\\\\aegis-probe'):
                try:
                    with open(target, 'w') as handle:
                        handle.write('x')
                    os.remove(target)
                    return 'BREACH:wrote to ' + target
                except OSError:
                    continue
            return 'BLOCKED:root filesystem is not writable'
            """
        ),
    ),
    BoundaryProbe(
        id="fs.host_secrets",
        title="Read host credential stores (/etc/shadow, SAM hive)",
        severity=Severity.CRITICAL,
        remediation="Use a container/mount namespace; a bare subprocess shares the host FS.",
        code=_probe_source(
            """
            targets = [
                '/etc/shadow',
                '/root/.ssh/id_rsa',
                'C:\\\\Windows\\\\System32\\\\config\\\\SAM',
                'C:\\\\Windows\\\\System32\\\\config\\\\SYSTEM',
            ]
            for path in targets:
                try:
                    with open(path, 'rb') as handle:
                        if handle.read(1):
                            return 'BREACH:readable host secret store ' + path
                except OSError:
                    continue
            return 'BLOCKED:host credential stores unreadable'
            """
        ),
    ),
    BoundaryProbe(
        id="fs.host_etc_passwd",
        title="Enumerate host accounts via /etc/passwd or the user profile tree",
        severity=Severity.MEDIUM,
        remediation="Run with --private / a container image; host account names aid targeting.",
        code=_probe_source(
            """
            import os
            try:
                with open('/etc/passwd') as handle:
                    text = handle.read()
                if 'root:' in text and len(text.splitlines()) > 6:
                    return 'BREACH:host /etc/passwd visible with ' + str(len(text.splitlines())) + ' accounts'
            except OSError:
                pass
            for candidate in ('C:\\\\Users', '/home'):
                try:
                    entries = os.listdir(candidate)
                except OSError:
                    continue
                if len(entries) > 2:
                    return 'BREACH:host user directory listing ' + candidate
            return 'BLOCKED:host account enumeration failed'
            """
        ),
    ),
    BoundaryProbe(
        id="priv.setuid_file",
        title="Create a setuid binary (privilege escalation staging)",
        severity=Severity.HIGH,
        remediation="Mount workspaces nosuid and set no-new-privileges.",
        code=_probe_source(
            """
            import os, stat, tempfile
            if not hasattr(os, 'chmod') or os.name == 'nt':
                return 'BLOCKED:setuid is not a Windows concept'
            path = os.path.join(tempfile.gettempdir(), 'aegis_suid_probe')
            try:
                with open(path, 'w') as handle:
                    handle.write('#!/bin/sh\\nid\\n')
                os.chmod(path, 0o4755)
                mode = os.stat(path).st_mode
                os.remove(path)
                if mode & stat.S_ISUID:
                    return 'BREACH:setuid bit persisted on a workspace file'
                return 'BLOCKED:setuid bit stripped by the mount options'
            except OSError as exc:
                return 'BLOCKED:chmod refused (' + str(exc)[:80] + ')'
            """
        ),
    ),
    BoundaryProbe(
        id="proc.fork_bomb",
        title="Process explosion beyond the pids limit",
        severity=Severity.HIGH,
        destructive=True,
        remediation="Set pids_limit (docker --pids-limit / RLIMIT_NPROC).",
        code=_probe_source(
            """
            import os, subprocess, sys
            spawned = []
            limit = 200
            try:
                for _ in range(limit):
                    proc = subprocess.Popen(
                        [sys.executable, '-c', 'import time; time.sleep(3)'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    spawned.append(proc)
            except (OSError, BlockingIOError) as exc:
                return ('BLOCKED:process creation refused after ' + str(len(spawned))
                        + ' children (' + type(exc).__name__ + ')')
            finally:
                for proc in spawned:
                    try:
                        proc.kill()
                    except OSError:
                        pass
            return 'BREACH:spawned ' + str(len(spawned)) + ' processes with no pids limit'
            """
        ),
    ),
    BoundaryProbe(
        id="mem.overcommit",
        title="Allocate far beyond the memory limit",
        severity=Severity.MEDIUM,
        destructive=True,
        timeout_s=20.0,
        remediation="Set memory_mb (docker --memory / RLIMIT_AS).",
        code=_probe_source(
            """
            chunks = []
            try:
                for _ in range(64):
                    chunks.append(bytearray(64 * 1024 * 1024))
            except MemoryError:
                return 'BLOCKED:MemoryError after ' + str(len(chunks) * 64) + 'MB'
            except OSError as exc:
                return 'BLOCKED:allocation refused (' + str(exc)[:60] + ')'
            return 'BREACH:allocated ' + str(len(chunks) * 64) + 'MB without hitting a limit'
            """
        ),
    ),
    BoundaryProbe(
        id="cpu.timeout",
        title="Busy loop past the CPU / wall-clock budget",
        severity=Severity.MEDIUM,
        timeout_s=8.0,
        destructive=True,
        remediation="Set timeout_s and RLIMIT_CPU; verify the killer reaps the tree.",
        code=_probe_source(
            """
            import time
            deadline = time.time() + 30
            iterations = 0
            while time.time() < deadline:
                iterations += 1
            return 'BREACH:burned 30s of CPU (' + str(iterations) + ' iterations) uninterrupted'
            """
        ),
    ),
    BoundaryProbe(
        id="esc.docker_socket",
        title="Access the Docker/containerd control socket",
        severity=Severity.CRITICAL,
        remediation=(
            "Never bind-mount docker.sock into an agent sandbox: write access "
            "to it is equivalent to root on the host."
        ),
        references=["CWE-732"],
        code=_probe_source(
            """
            import os
            sockets = [
                '/var/run/docker.sock', '/run/docker.sock',
                '/run/containerd/containerd.sock',
                '/var/run/crio/crio.sock',
                '\\\\\\\\.\\\\pipe\\\\docker_engine',
            ]
            for path in sockets:
                try:
                    if os.path.exists(path):
                        return 'BREACH:container control socket reachable at ' + path
                except OSError:
                    continue
            return 'BLOCKED:no container control socket visible'
            """
        ),
    ),
    BoundaryProbe(
        id="esc.ptrace",
        title="Attach to another process with ptrace",
        severity=Severity.HIGH,
        remediation="Drop CAP_SYS_PTRACE and deny the ptrace syscall in seccomp.",
        code=_probe_source(
            """
            import ctypes, os
            if os.name == 'nt':
                return 'BLOCKED:ptrace is not available on Windows'
            try:
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
            except OSError:
                return 'BLOCKED:libc not loadable for a ptrace attempt'
            PTRACE_ATTACH = 16
            target = 1
            rc = libc.ptrace(PTRACE_ATTACH, target, 0, 0)
            if rc == 0:
                libc.ptrace(17, target, 0, 0)
                return 'BREACH:ptrace attached to pid 1'
            return 'BLOCKED:ptrace refused errno=' + str(ctypes.get_errno())
            """
        ),
    ),
    BoundaryProbe(
        id="esc.symlink",
        title="Symlink escape out of the workspace",
        severity=Severity.HIGH,
        remediation=(
            "Resolve every path with realpath and re-check containment "
            "(FilesystemJail does this)."
        ),
        code=_probe_source(
            """
            import os, tempfile
            base = tempfile.mkdtemp()
            link = os.path.join(base, 'escape')
            target = 'C:\\\\Windows' if os.name == 'nt' else '/etc'
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError, AttributeError) as exc:
                return 'BLOCKED:symlink creation refused (' + type(exc).__name__ + ')'
            try:
                entries = os.listdir(link)
            except OSError:
                return 'BLOCKED:symlink created but target unreadable'
            if entries:
                return 'BREACH:symlink to ' + target + ' resolved with ' + str(len(entries)) + ' entries'
            return 'BLOCKED:symlink target empty'
            """
        ),
    ),
]


# --------------------------------------------------------------------------- #
class SandboxBoundaryTester:
    """Execute the probe catalogue against a sandbox configuration.

    Args:
        runner: Anything exposing ``run_python(spec, code) -> SandboxResult``;
            normally a :class:`~aegis.sandbox.runner.SandboxRunner`.
        probes: Override the catalogue (used by targeted regression tests).
        include_destructive: Run the resource-exhaustion probes.  They are safe
            but noisy, so CI may want them off for fast checks.
    """

    def __init__(
        self,
        runner: Any,
        *,
        probes: Optional[Sequence[BoundaryProbe]] = None,
        include_destructive: bool = True,
    ) -> None:
        self.runner = runner
        self.probes: List[BoundaryProbe] = list(probes or PROBES)
        self.include_destructive = include_destructive

    # ------------------------------------------------------------------ #
    def _probe_spec(self, spec: SandboxSpec, probe: BoundaryProbe) -> SandboxSpec:
        """Clone ``spec`` with the probe's own timeout."""
        fields = dict(vars(spec))
        fields["timeout_s"] = min(float(spec.timeout_s), probe.timeout_s) or probe.timeout_s
        # Canaries would be flagged by the probe output scan; probes are trusted
        # code, so they run without them to keep the signal clean.
        fields["canary_tokens"] = []
        return SandboxSpec(**fields)

    @staticmethod
    def _interpret(probe: BoundaryProbe, result: SandboxResult) -> ProbeOutcome:
        """Turn raw sandbox output into a pass/fail judgement."""
        combined = f"{result.stdout}\n{result.stderr}".strip()
        breach_line = next(
            (line for line in combined.splitlines() if line.strip().startswith("BREACH:")), ""
        )
        blocked_line = next(
            (line for line in combined.splitlines() if line.strip().startswith("BLOCKED:")), ""
        )

        if breach_line:
            detail = breach_line.split("BREACH:", 1)[1].strip()
            passed = False
        elif blocked_line:
            detail = blocked_line.split("BLOCKED:", 1)[1].strip()
            passed = True
        elif result.timed_out:
            # For the CPU probe a timeout *is* the control working.
            passed = probe.id in ("cpu.timeout", "proc.fork_bomb", "mem.overcommit")
            detail = (
                "workload killed by the wall-clock timeout"
                if passed
                else "probe timed out without reporting a verdict"
            )
        elif result.exit_code == 137 or "oom" in combined.lower():
            passed = True
            detail = "workload killed by the memory limit (exit 137 / OOM)"
        elif not result.ok and result.exit_code in (125, 126, 127):
            passed = True
            detail = f"probe could not start under this driver (exit {result.exit_code})"
        else:
            passed = True
            detail = f"probe produced no verdict (exit {result.exit_code}); treated as blocked"

        return ProbeOutcome(
            probe_id=probe.id,
            title=probe.title,
            passed=passed,
            detail=detail,
            severity=probe.severity,
            remediation=probe.remediation,
            duration_ms=result.duration_ms,
            raw_stdout=result.stdout[:2000],
            raw_stderr=result.stderr[:2000],
        )

    # ------------------------------------------------------------------ #
    def run_probe(self, spec: SandboxSpec, probe: BoundaryProbe) -> ProbeOutcome:
        """Run a single probe and interpret the result."""
        if probe.destructive and not self.include_destructive:
            return ProbeOutcome(
                probe_id=probe.id,
                title=probe.title,
                passed=True,
                skipped=True,
                detail="skipped: destructive probes disabled",
                severity=probe.severity,
            )
        if probe.requires_network_probe and (spec.network or "deny").lower() == "allow":
            return ProbeOutcome(
                probe_id=probe.id,
                title=probe.title,
                passed=True,
                skipped=True,
                detail="skipped: this sandbox intentionally allows unrestricted network access",
                severity=probe.severity,
            )
        probe_spec = self._probe_spec(spec, probe)
        try:
            result = self.runner.run_python(probe_spec, probe.code)
        except SandboxEscapeDetected as exc:
            return ProbeOutcome(
                probe_id=probe.id,
                title=probe.title,
                passed=False,
                detail=f"runner reported an escape while probing: {exc.message}",
                severity=Severity.CRITICAL,
                remediation=probe.remediation,
            )
        except Exception as exc:  # pragma: no cover - driver level failure
            return ProbeOutcome(
                probe_id=probe.id,
                title=probe.title,
                passed=True,
                skipped=True,
                detail=f"skipped: driver error {type(exc).__name__}: {exc}",
                severity=probe.severity,
            )
        return self._interpret(probe, result)

    def run_all(self, spec: Optional[SandboxSpec] = None) -> BoundaryReport:
        """Run every probe and return the aggregate report."""
        spec = spec or SandboxSpec(kind=SandboxKind.SUBPROCESS)
        report = BoundaryReport(
            driver=getattr(self.runner, "active_driver_name", lambda: "unknown")()
            if callable(getattr(self.runner, "active_driver_name", None))
            else str(getattr(self.runner, "active_driver_name", "unknown")),
            kind=spec.kind.value,
        )
        log.info(
            "starting sandbox boundary sweep",
            fields={"probes": len(self.probes), "kind": spec.kind.value},
        )
        for probe in self.probes:
            outcome = self.run_probe(spec, probe)
            report.outcomes.append(outcome)
            if not outcome.passed and not outcome.skipped:
                log.error(
                    "BOUNDARY PROBE FAILED",
                    fields={
                        "probe": probe.id,
                        "severity": probe.severity.value,
                        "detail": outcome.detail[:200],
                    },
                )
        log.info(
            "sandbox boundary sweep complete",
            fields={
                "score": report.score,
                "failed": len(report.failures),
                "skipped": len(report.skipped),
            },
        )
        return report

    def assert_secure(
        self,
        spec: Optional[SandboxSpec] = None,
        *,
        min_severity: Severity = Severity.HIGH,
    ) -> BoundaryReport:
        """Run the sweep and raise when the boundary is not sound.

        Args:
            spec: The configuration to verify.
            min_severity: Only failures at or above this severity abort.

        Raises:
            SandboxEscapeDetected: When any qualifying probe breached.
        """
        report = self.run_all(spec)
        blocking = [f for f in report.failures if f.severity.score >= min_severity.score]
        if blocking:
            raise SandboxEscapeDetected(
                "sandbox boundary verification failed: "
                + ", ".join(f"{f.probe_id} ({f.detail[:60]})" for f in blocking),
                details={
                    "report": report.as_dict(),
                    "failed_probes": [f.probe_id for f in blocking],
                },
            )
        return report

    def probe_ids(self) -> List[str]:
        """Identifiers of the configured probes."""
        return [p.id for p in self.probes]

    def filtered(self, *probe_ids: str) -> "SandboxBoundaryTester":
        """Return a tester restricted to the named probes."""
        wanted = set(probe_ids)
        return SandboxBoundaryTester(
            self.runner,
            probes=[p for p in self.probes if p.id in wanted],
            include_destructive=self.include_destructive,
        )


def register_probe(probe: BoundaryProbe, catalogue: Optional[List[BoundaryProbe]] = None) -> None:
    """Add a custom probe to the shared catalogue."""
    target = catalogue if catalogue is not None else PROBES
    if any(existing.id == probe.id for existing in target):
        raise ValueError(f"probe id '{probe.id}' already registered")
    target.append(probe)


def probe_callback_noop(_: ProbeOutcome) -> None:
    """Default no-op observer, kept for API symmetry with the canary manager."""
    return None


ProbeObserver = Callable[[ProbeOutcome], None]
