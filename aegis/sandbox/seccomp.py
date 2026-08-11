"""Seccomp-BPF profile generation for container sandboxes.

Docker's default seccomp profile still permits roughly 300 syscalls, several of
which are stepping stones out of a container (``unshare``, ``setns``,
``mount``, ``bpf``).  The 2026-08 frontier-lab escapes were *not* kernel
exploits - they were agents calling perfectly ordinary syscalls that nobody had
thought to deny.

This module therefore builds **allowlist** profiles: the default action is
``SCMP_ACT_ERRNO`` (return EPERM) and only an explicitly enumerated set of
syscalls is permitted.  Three tiers ship in the box:

``strict``
    Basic IO only - enough to read stdin, write stdout and exit.
``default``
    A general purpose interpreter runtime (Python/Node): threads, memory
    mapping, filesystem metadata, process spawn.
``network``
    ``default`` plus the socket syscalls, for workloads that legitimately need
    egress through the proxy.

Every entry in :data:`DENY_LIST` carries the reason it is dangerous, so the
generated profile doubles as documentation during a security review.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..core.errors import SandboxError
from ..core.logging import get_logger

__all__ = [
    "SeccompProfileBuilder",
    "PROFILES",
    "DENY_LIST",
    "DeniedSyscall",
    "default_profile_path",
]

log = get_logger("sandbox.seccomp")


# --------------------------------------------------------------------------- #
# Explicitly dangerous syscalls
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DeniedSyscall:
    """A syscall that is never allowed, plus the reason why."""

    name: str
    reason: str
    technique: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {"syscall": self.name, "reason": self.reason, "technique": self.technique}


#: Syscalls denied in *every* profile, including ``network``.
DENY_LIST: Tuple[DeniedSyscall, ...] = (
    DeniedSyscall(
        "ptrace",
        "Attaches to and rewrites the memory of another process; lets sandboxed "
        "code hijack a more privileged sibling and read its credentials.",
        "MITRE ATLAS AML.T0051 / process injection",
    ),
    DeniedSyscall(
        "process_vm_readv",
        "Reads another process's address space directly - API keys held in the "
        "gateway's memory would be readable without any file access.",
        "credential theft",
    ),
    DeniedSyscall(
        "process_vm_writev",
        "Writes into another process's address space; equivalent to code "
        "injection without ptrace.",
        "process injection",
    ),
    DeniedSyscall(
        "mount",
        "Mounting a filesystem (notably proc, or a bind mount of the host root) "
        "is the single most common container-escape primitive.",
        "container escape",
    ),
    DeniedSyscall(
        "umount",
        "Unmounting a read-only overlay can expose the writable layer beneath it.",
        "container escape",
    ),
    DeniedSyscall(
        "umount2",
        "Same as umount, with flags that allow lazy/forced detach.",
        "container escape",
    ),
    DeniedSyscall(
        "pivot_root",
        "Swaps the root filesystem; the classic escape from a chroot-style jail.",
        "container escape",
    ),
    DeniedSyscall(
        "chroot",
        "A second chroot can be used to break out of the first one (the "
        "double-chroot trick) when a directory handle is still held open.",
        "jail escape",
    ),
    DeniedSyscall(
        "unshare",
        "Creates new namespaces; combined with a user namespace it hands the "
        "workload CAP_SYS_ADMIN inside that namespace, re-enabling mount.",
        "privilege escalation",
    ),
    DeniedSyscall(
        "setns",
        "Joins an existing namespace - e.g. the host PID or network namespace "
        "reachable through /proc/1/ns/*.",
        "container escape",
    ),
    DeniedSyscall(
        "clone3",
        "Newer clone variant that seccomp filters written against clone() miss "
        "entirely; used to create namespaces past an incomplete filter.",
        "seccomp bypass",
    ),
    DeniedSyscall(
        "bpf",
        "Loads eBPF programs into the kernel; historically a rich source of "
        "local privilege escalation and a way to tap all host traffic.",
        "privilege escalation",
    ),
    DeniedSyscall(
        "perf_event_open",
        "Kernel performance counters; repeatedly exploitable and usable as a "
        "side channel against co-tenant workloads.",
        "privilege escalation / side channel",
    ),
    DeniedSyscall(
        "kexec_load",
        "Loads a new kernel image for the next boot - total host compromise.",
        "host takeover",
    ),
    DeniedSyscall(
        "kexec_file_load",
        "File-descriptor based variant of kexec_load.",
        "host takeover",
    ),
    DeniedSyscall(
        "init_module",
        "Inserts a kernel module; arbitrary ring-0 code.",
        "host takeover",
    ),
    DeniedSyscall(
        "finit_module",
        "File-descriptor based variant of init_module.",
        "host takeover",
    ),
    DeniedSyscall(
        "delete_module",
        "Unloading a security module (LSM/AppArmor helper) disarms the host.",
        "defence evasion",
    ),
    DeniedSyscall(
        "reboot",
        "Restarts or halts the host from inside the sandbox - denial of service.",
        "availability",
    ),
    DeniedSyscall(
        "swapon",
        "Activating attacker-chosen swap can spill other tenants' memory to a "
        "readable device.",
        "information disclosure",
    ),
    DeniedSyscall(
        "swapoff",
        "Forces memory pressure on the host.",
        "availability",
    ),
    DeniedSyscall(
        "settimeofday",
        "Moving the clock invalidates attestation freshness windows and TOTP "
        "step-up codes - it attacks the approval layer, not the kernel.",
        "control bypass",
    ),
    DeniedSyscall(
        "clock_settime",
        "Same clock-rollback attack against provenance expiry checks.",
        "control bypass",
    ),
    DeniedSyscall(
        "adjtimex",
        "Slews the clock to achieve the same effect gradually.",
        "control bypass",
    ),
    DeniedSyscall(
        "add_key",
        "Kernel keyring writes; the keyring is shared across containers by "
        "default on some kernels.",
        "credential theft",
    ),
    DeniedSyscall(
        "request_key",
        "Reads from the shared kernel keyring.",
        "credential theft",
    ),
    DeniedSyscall(
        "keyctl",
        "Manipulates keyring permissions to reach other tenants' keys.",
        "credential theft",
    ),
    DeniedSyscall(
        "quotactl",
        "Filesystem quota administration; requires and exercises CAP_SYS_ADMIN.",
        "privilege escalation",
    ),
    DeniedSyscall(
        "open_by_handle_at",
        "The Shocker escape: resolves a file handle that points outside the "
        "mount namespace, reading arbitrary host files.",
        "container escape",
    ),
    DeniedSyscall(
        "name_to_handle_at",
        "Produces the handle that open_by_handle_at consumes.",
        "container escape",
    ),
    DeniedSyscall(
        "iopl",
        "Grants direct IO port access - ring-0 equivalent power.",
        "host takeover",
    ),
    DeniedSyscall(
        "ioperm",
        "Per-port variant of iopl.",
        "host takeover",
    ),
    DeniedSyscall(
        "personality",
        "Can disable ASLR for a child process, easing memory-corruption chains.",
        "exploit enablement",
    ),
    DeniedSyscall(
        "userfaultfd",
        "Lets user space stall kernel page faults, a standard primitive for "
        "widening kernel race windows.",
        "exploit enablement",
    ),
    DeniedSyscall(
        "move_pages",
        "NUMA page migration has been used to build cross-tenant side channels "
        "and to probe host memory layout.",
        "side channel",
    ),
    DeniedSyscall(
        "fsopen",
        "New-style mount API; reaches the same escape surface as mount() while "
        "bypassing filters that only name the legacy syscall.",
        "container escape",
    ),
    DeniedSyscall(
        "fsmount",
        "Attaches a filesystem created by fsopen into the namespace.",
        "container escape",
    ),
    DeniedSyscall(
        "move_mount",
        "Relocates a mount tree - the modern pivot_root equivalent.",
        "container escape",
    ),
    DeniedSyscall(
        "open_tree",
        "Clones a mount tree by descriptor, enabling move_mount escapes.",
        "container escape",
    ),
)


# --------------------------------------------------------------------------- #
# Allow lists
# --------------------------------------------------------------------------- #
#: Minimal IO: read a script from stdin, print to stdout, exit cleanly.
_STRICT_ALLOW: Tuple[str, ...] = (
    "read", "write", "readv", "writev", "close", "fstat", "fstat64", "lseek",
    "exit", "exit_group", "rt_sigreturn", "rt_sigaction", "rt_sigprocmask",
    "sigaltstack", "brk", "mmap", "mmap2", "munmap", "mprotect", "mremap",
    "futex", "futex_time64", "getpid", "gettid", "getuid", "geteuid", "getgid",
    "getegid", "arch_prctl", "set_tid_address", "set_robust_list",
    "get_robust_list", "clock_gettime", "clock_gettime64", "clock_getres",
    "gettimeofday", "nanosleep", "clock_nanosleep", "restart_syscall",
    "madvise", "prlimit64", "getrandom", "getrlimit", "ugetrlimit",
    "rseq", "membarrier", "sched_yield", "pread64", "pwrite64",
)

#: Everything a normal interpreter needs: files, directories, subprocess, TTY.
_RUNTIME_ALLOW: Tuple[str, ...] = (
    "open", "openat", "openat2", "creat", "stat", "stat64", "lstat", "lstat64",
    "newfstatat", "statx", "access", "faccessat", "faccessat2", "readlink",
    "readlinkat", "getcwd", "chdir", "fchdir", "getdents", "getdents64",
    "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat", "rename", "renameat",
    "renameat2", "link", "linkat", "symlink", "symlinkat", "chmod", "fchmod",
    "fchmodat", "truncate", "ftruncate", "fsync", "fdatasync", "dup", "dup2",
    "dup3", "pipe", "pipe2", "fcntl", "fcntl64", "ioctl", "poll", "ppoll",
    "select", "pselect6", "epoll_create", "epoll_create1", "epoll_ctl",
    "epoll_wait", "epoll_pwait", "eventfd", "eventfd2", "signalfd",
    "signalfd4", "timerfd_create", "timerfd_settime", "timerfd_gettime",
    "clone", "fork", "vfork", "execve", "execveat", "wait4", "waitid",
    "kill", "tgkill", "tkill", "getppid", "setpgid", "getpgid", "getpgrp",
    "setsid", "uname", "sysinfo", "times", "getrusage", "sched_getaffinity",
    "sched_setaffinity", "sched_getparam", "sched_get_priority_max",
    "sched_get_priority_min", "prctl", "umask", "utimensat", "utimes",
    "copy_file_range", "sendfile", "sendfile64", "splice", "statfs",
    "statfs64", "fstatfs", "fstatfs64", "flock", "sync", "io_setup",
    "io_destroy", "io_submit", "io_getevents", "setgroups", "setresuid",
    "setresgid", "setuid", "setgid",
)

#: Socket family - only enabled in the ``network`` tier.
_NETWORK_ALLOW: Tuple[str, ...] = (
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "sendmmsg", "recvmmsg", "shutdown", "setsockopt", "getsockopt",
)


PROFILES: Dict[str, Dict[str, Any]] = {
    "strict": {
        "description": "Basic IO only - read stdin, write stdout, exit.",
        "allow": _STRICT_ALLOW,
        "network": False,
    },
    "default": {
        "description": "General interpreter runtime without network access.",
        "allow": _STRICT_ALLOW + _RUNTIME_ALLOW,
        "network": False,
    },
    "network": {
        "description": "Interpreter runtime plus socket syscalls (proxy egress).",
        "allow": _STRICT_ALLOW + _RUNTIME_ALLOW + _NETWORK_ALLOW,
        "network": True,
    },
}


#: Architectures the profile applies to.  Docker requires the arch map or the
#: filter silently fails to load on multi-arch hosts.
_ARCH_MAP: Tuple[Dict[str, Any], ...] = (
    {
        "architecture": "SCMP_ARCH_X86_64",
        "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"],
    },
    {
        "architecture": "SCMP_ARCH_AARCH64",
        "subArchitectures": ["SCMP_ARCH_ARM"],
    },
)


_SYSCALL_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")


def _valid_syscall(name: str) -> bool:
    """Reject non-ASCII / malformed entries before they reach the JSON file."""
    return bool(name) and bool(_SYSCALL_RE.match(name))


@dataclass
class SeccompProfileBuilder:
    """Builds Docker/OCI-compatible seccomp JSON documents.

    Example:
        >>> builder = SeccompProfileBuilder()
        >>> doc = builder.build("strict")
        >>> doc["defaultAction"]
        'SCMP_ACT_ERRNO'
    """

    default_action: str = "SCMP_ACT_ERRNO"
    default_errno: int = 1  # EPERM
    extra_allow: List[str] = field(default_factory=list)
    extra_deny: List[str] = field(default_factory=list)
    include_arch_map: bool = True

    # ------------------------------------------------------------------ #
    def deny_list(self) -> List[DeniedSyscall]:
        """Return the annotated deny list, including caller supplied entries."""
        base = [d for d in DENY_LIST if _valid_syscall(d.name)]
        base.extend(
            DeniedSyscall(name, "Explicitly denied by operator configuration.")
            for name in self.extra_deny
            if _valid_syscall(name)
        )
        return base

    def allowed_syscalls(self, profile: str = "default") -> List[str]:
        """Resolve the effective allow list for ``profile``."""
        tier = PROFILES.get(profile)
        if tier is None:
            raise SandboxError(
                f"unknown seccomp profile '{profile}'",
                details={"available": sorted(PROFILES)},
            )
        denied = {d.name for d in self.deny_list()}
        names = list(tier["allow"]) + list(self.extra_allow)
        seen: Dict[str, None] = {}
        for name in names:
            if not _valid_syscall(name) or name in denied:
                continue
            seen.setdefault(name, None)
        return sorted(seen)

    # ------------------------------------------------------------------ #
    def build(self, profile: str = "default") -> Dict[str, Any]:
        """Produce the seccomp JSON document for ``profile``."""
        allowed = self.allowed_syscalls(profile)
        document: Dict[str, Any] = {
            "defaultAction": self.default_action,
            "defaultErrnoRet": self.default_errno,
            "syscalls": [
                {
                    "names": allowed,
                    "action": "SCMP_ACT_ALLOW",
                    "args": [],
                    "comment": f"aegis:{profile} allowlist",
                },
                {
                    # Explicit ERRNO entries are redundant against an ERRNO
                    # default, but they make the intent obvious to a reviewer
                    # and survive someone flipping the default to SCMP_ACT_LOG.
                    "names": [d.name for d in self.deny_list()],
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": self.default_errno,
                    "args": [],
                    "comment": "aegis:escape-primitives (never allowed)",
                },
            ],
            "x-aegis": {
                "profile": profile,
                "description": PROFILES[profile]["description"],
                "network": PROFILES[profile]["network"],
                "allow_count": len(allowed),
                "deny_reasons": [d.as_dict() for d in self.deny_list()],
            },
        }
        if self.include_arch_map:
            document["archMap"] = [dict(entry) for entry in _ARCH_MAP]
            document["architectures"] = [entry["architecture"] for entry in _ARCH_MAP]
        return document

    def write(self, path: str | os.PathLike[str], profile: str = "default") -> Path:
        """Serialise :meth:`build` to ``path`` and return the resolved path."""
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.build(profile), indent=2, ensure_ascii=True),
            encoding="utf-8",
        )
        log.info(
            "seccomp profile written",
            fields={"path": str(target), "profile": profile},
        )
        return target.resolve()

    def explain(self, profile: str = "default") -> str:
        """Human-readable summary used by the CLI and boundary reports."""
        allowed = self.allowed_syscalls(profile)
        lines = [
            f"seccomp profile '{profile}': {PROFILES[profile]['description']}",
            f"  default action : {self.default_action} (errno={self.default_errno})",
            f"  allowed        : {len(allowed)} syscalls",
            f"  network        : {'yes' if PROFILES[profile]['network'] else 'no'}",
            "  hard denials   :",
        ]
        for item in self.deny_list():
            lines.append(f"    - {item.name}: {item.reason}")
        return "\n".join(lines)

    def diff(self, profile_a: str, profile_b: str) -> Dict[str, List[str]]:
        """Show which syscalls one tier grants over another."""
        a, b = set(self.allowed_syscalls(profile_a)), set(self.allowed_syscalls(profile_b))
        return {
            "only_in_" + profile_a: sorted(a - b),
            "only_in_" + profile_b: sorted(b - a),
            "shared": sorted(a & b),
        }


def default_profile_path(profile: str = "default", base_dir: Optional[str] = None) -> Path:
    """Materialise a profile under ``base_dir`` (default: temp dir) once.

    Docker needs a *file path* for ``--security-opt seccomp=``; this helper
    keeps a stable, reusable location so repeated runs do not litter the disk.
    """
    import tempfile

    root = Path(base_dir) if base_dir else Path(tempfile.gettempdir()) / "aegis-seccomp"
    target = root / f"{profile}.json"
    if not target.is_file():
        SeccompProfileBuilder().write(target, profile)
    return target


def summarise_deny_list() -> List[Dict[str, str]]:
    """Return the annotated deny list for reports and documentation."""
    return [d.as_dict() for d in DENY_LIST if _valid_syscall(d.name)]


def iter_profiles() -> Iterable[Tuple[str, str]]:
    """Yield ``(name, description)`` for every built-in profile."""
    for name, tier in PROFILES.items():
        yield name, str(tier["description"])
