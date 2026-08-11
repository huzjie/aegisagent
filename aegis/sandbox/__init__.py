"""Isolated execution layer.

Public entry point is :class:`~aegis.sandbox.runner.SandboxRunner`; everything
else is available for operators who need finer control (custom drivers, direct
seccomp profile generation, standalone boundary verification).

Typical use::

    from aegis.core.types import SandboxKind, SandboxSpec
    from aegis.sandbox import SandboxRunner

    runner = SandboxRunner()
    spec = SandboxSpec(kind=SandboxKind.DOCKER, network="deny", timeout_s=15)
    result = runner.run_python(spec, "print('hello from jail')")
    assert not result.escape_detected
"""

from __future__ import annotations

from .base import ExecutionRequest, SandboxDriver, sanitise_env
from .boundary_test import (
    BoundaryProbe,
    BoundaryReport,
    ProbeOutcome,
    SandboxBoundaryTester,
)
from .canary import CanaryHit, CanaryToken, CanaryTokenManager
from .drivers import (
    DockerDriver,
    FirejailDriver,
    NoopDriver,
    SubprocessDriver,
    available_drivers,
)
from .egress import BlockedAttempt, EgressController, ProxyRecorder
from .fsjail import FilesystemJail, MountPoint, PathVerdict
from .policy_bridge import PolicyBridge, SandboxObligation, spec_from_obligations
from .rlimits import ResourceLimits, apply_posix, to_docker_flags
from .runner import RunnerMetrics, SandboxRunner
from .seccomp import DENY_LIST, PROFILES, SeccompProfileBuilder

__all__ = [
    # runner
    "SandboxRunner",
    "RunnerMetrics",
    # drivers
    "SandboxDriver",
    "ExecutionRequest",
    "SubprocessDriver",
    "DockerDriver",
    "FirejailDriver",
    "NoopDriver",
    "available_drivers",
    "sanitise_env",
    # controls
    "FilesystemJail",
    "MountPoint",
    "PathVerdict",
    "EgressController",
    "ProxyRecorder",
    "BlockedAttempt",
    "CanaryTokenManager",
    "CanaryToken",
    "CanaryHit",
    "ResourceLimits",
    "apply_posix",
    "to_docker_flags",
    "SeccompProfileBuilder",
    "PROFILES",
    "DENY_LIST",
    # verification
    "SandboxBoundaryTester",
    "BoundaryReport",
    "BoundaryProbe",
    "ProbeOutcome",
    # policy
    "PolicyBridge",
    "SandboxObligation",
    "spec_from_obligations",
]
