"""Filesystem containment with symlink-escape protection.

A jail that only checks the *textual* path is not a jail.  The recurring real
world failure - seen again in the 2026-08 agent sandbox escapes - is:

1. the agent creates ``work/notes`` as a symlink to ``/etc`` (or to
   ``C:\\Windows\\System32\\config``),
2. the runtime validates the string ``work/notes/passwd`` (still "inside"),
3. the OS resolves the link and the write lands on the host.

:class:`FilesystemJail` therefore resolves every path with ``os.path.realpath``
(which follows symlinks) *and* re-verifies containment on the resolved result.
Windows adds two extra traps handled here: drive-relative paths (``C:foo``) and
UNC / device paths (``\\\\?\\``, ``\\\\server\\share``) which bypass normal
prefix comparisons.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.errors import SandboxEscapeDetected
from ..core.logging import get_logger

__all__ = ["FilesystemJail", "MountPoint", "PathVerdict"]

log = get_logger("sandbox.fsjail")

IS_WINDOWS = sys.platform == "win32"

#: Path fragments that are never legal inside a jailed path, whatever the
#: platform.  ``..`` is obvious; the NUL byte truncates C strings and has been
#: used to smuggle a different suffix past validators.
_FORBIDDEN_FRAGMENTS: Tuple[str, ...] = ("\x00",)

#: Windows device namespaces / reserved names that must never be opened.
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

#: Host locations that are always off-limits even if someone mounts them in.
_ALWAYS_DENY_POSIX: Tuple[str, ...] = (
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/root/.ssh",
    "/proc/1", "/proc/sys", "/sys/kernel", "/dev/mem", "/dev/kmem",
    "/var/run/docker.sock", "/run/docker.sock", "/var/lib/kubelet",
)

_ALWAYS_DENY_WINDOWS: Tuple[str, ...] = (
    r"c:\windows\system32\config",
    r"c:\windows\system32\drivers\etc",
    r"c:\users\administrator\.ssh",
    r"c:\programdata\docker",
)


@dataclass
class MountPoint:
    """A directory grafted into the jail with explicit permissions."""

    source: str
    target: str
    read_only: bool = True

    def resolved_source(self) -> str:
        return os.path.realpath(os.path.abspath(os.path.expanduser(self.source)))


@dataclass
class PathVerdict:
    """Result of evaluating one path against the jail."""

    path: str
    resolved: str
    inside: bool
    writable: bool
    reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "resolved": self.resolved,
            "inside": self.inside,
            "writable": self.writable,
            "reason": self.reason,
        }


class FilesystemJail:
    """Confine every filesystem access to a root directory.

    Args:
        root: The jail root.  Created if missing.  Stored fully resolved so a
            symlinked root (e.g. ``/tmp`` -> ``/private/tmp`` on macOS) does not
            make every subsequent containment check fail.
        writable_paths: Sub-paths (relative to root, or absolute inside root)
            that may be written to.  When empty the whole jail is writable.
        read_only_mounts: Extra directories exposed read-only.
        follow_symlinks: When True (default) links are resolved and the target
            must also be inside the jail.  Setting it False makes the jail
            reject symlinks outright, which is stricter but breaks toolchains
            that legitimately use them.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        writable_paths: Optional[Sequence[str]] = None,
        read_only_mounts: Optional[Sequence[MountPoint]] = None,
        follow_symlinks: bool = True,
        create: bool = True,
    ) -> None:
        root_path = Path(os.path.expanduser(str(root))).absolute()
        if create:
            root_path.mkdir(parents=True, exist_ok=True)
        self.root: str = os.path.realpath(str(root_path))
        self.follow_symlinks = follow_symlinks
        self.mounts: List[MountPoint] = list(read_only_mounts or [])
        self._writable: List[str] = []
        for entry in writable_paths or []:
            try:
                self._writable.append(self._join(entry))
            except SandboxEscapeDetected:
                log.warning(
                    "writable path outside jail ignored",
                    fields={"path": entry, "root": self.root},
                )
        self.violations: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Normalisation helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalise_case(path: str) -> str:
        """Case-fold on platforms with case-insensitive filesystems."""
        return path.lower() if IS_WINDOWS else path

    def _reject(self, path: str, reason: str) -> "SandboxEscapeDetected":
        """Record and build the escape exception for ``path``."""
        record = {"path": str(path), "reason": reason, "root": self.root}
        self.violations.append(record)
        log.warning("filesystem jail violation", fields=record)
        return SandboxEscapeDetected(
            f"path escapes sandbox jail: {reason}",
            details=record,
        )

    def _pre_validate(self, raw: str) -> str:
        """Syntactic checks that must pass before touching the filesystem."""
        text = str(raw)
        if not text.strip():
            raise self._reject(text, "empty path")
        for fragment in _FORBIDDEN_FRAGMENTS:
            if fragment in text:
                raise self._reject(text, "path contains a forbidden byte sequence")

        pure = PurePath(text)
        if ".." in pure.parts:
            # Rejected up-front rather than relying on normalisation, because a
            # ``..`` that traverses through a symlink can land outside the jail
            # even when the normalised string still looks contained.
            raise self._reject(text, "parent-directory traversal ('..') is not permitted")

        if IS_WINDOWS:
            lowered = text.lower().replace("/", "\\")
            if lowered.startswith("\\\\"):
                raise self._reject(text, "UNC / device paths are not permitted")
            if lowered.startswith("\\\\?\\") or lowered.startswith("\\\\.\\"):
                raise self._reject(text, "Win32 device namespace is not permitted")
            # ``C:foo`` is drive-relative: it resolves against the *process*
            # current directory on that drive, not against the jail.
            if len(text) >= 2 and text[1] == ":" and (len(text) == 2 or text[2] not in "\\/"):
                raise self._reject(text, "drive-relative path is ambiguous")
            stem = PurePath(lowered).stem
            if stem in _WINDOWS_RESERVED:
                raise self._reject(text, f"reserved Windows device name '{stem}'")
        return text

    def _join(self, raw: str) -> str:
        """Resolve ``raw`` relative to the jail root and verify containment."""
        text = self._pre_validate(raw)
        candidate = Path(text)
        if candidate.is_absolute():
            absolute = os.path.abspath(str(candidate))
        else:
            absolute = os.path.abspath(os.path.join(self.root, text))

        resolved = os.path.realpath(absolute) if self.follow_symlinks else absolute

        if self.follow_symlinks and resolved != absolute and not self._contained(resolved):
            # The textual path was fine; the *link target* was not.  This is the
            # CVE-shaped case the module exists for.
            raise self._reject(
                raw,
                f"symlink resolves outside the jail ({resolved})",
            )
        if not self._contained(resolved):
            raise self._reject(raw, f"resolved path {resolved} is outside {self.root}")
        if self._is_always_denied(resolved):
            raise self._reject(raw, "target is a hard-denied host location")
        return resolved

    def _contained(self, resolved: str) -> bool:
        """True when ``resolved`` lies inside the jail root or a mount."""
        root = self._normalise_case(self.root)
        target = self._normalise_case(resolved)
        if target == root or target.startswith(root.rstrip(os.sep) + os.sep):
            return True
        for mount in self.mounts:
            source = self._normalise_case(mount.resolved_source())
            if target == source or target.startswith(source.rstrip(os.sep) + os.sep):
                return True
        return False

    @staticmethod
    def _is_always_denied(resolved: str) -> bool:
        """Belt-and-braces check against notorious host paths."""
        lowered = resolved.lower().replace("\\", "/")
        deny = _ALWAYS_DENY_WINDOWS if IS_WINDOWS else _ALWAYS_DENY_POSIX
        for entry in deny:
            normalised = entry.lower().replace("\\", "/")
            if lowered == normalised or lowered.startswith(normalised.rstrip("/") + "/"):
                return True
        return False

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def resolve(self, path: str) -> Path:
        """Resolve ``path`` inside the jail.

        Returns:
            The fully resolved absolute :class:`~pathlib.Path`.

        Raises:
            SandboxEscapeDetected: If the path traverses out of the jail, is a
                symlink pointing outside it, uses a Windows device namespace or
                targets a hard-denied host location.
        """
        return Path(self._join(path))

    def evaluate(self, path: str) -> PathVerdict:
        """Non-raising variant of :meth:`resolve` used by reports and probes."""
        try:
            resolved = self._join(path)
        except SandboxEscapeDetected as exc:
            return PathVerdict(
                path=str(path),
                resolved="",
                inside=False,
                writable=False,
                reason=exc.message,
            )
        return PathVerdict(
            path=str(path),
            resolved=resolved,
            inside=True,
            writable=self._writable_resolved(resolved),
            reason="",
        )

    def _writable_resolved(self, resolved: str) -> bool:
        target = self._normalise_case(resolved)
        for mount in self.mounts:
            source = self._normalise_case(mount.resolved_source())
            if target == source or target.startswith(source.rstrip(os.sep) + os.sep):
                return not mount.read_only
        if not self._writable:
            return True
        for allowed in self._writable:
            allowed_n = self._normalise_case(allowed)
            if target == allowed_n or target.startswith(allowed_n.rstrip(os.sep) + os.sep):
                return True
        return False

    def allow_write(self, path: str) -> bool:
        """True when ``path`` is inside the jail *and* in a writable area."""
        verdict = self.evaluate(path)
        return verdict.inside and verdict.writable

    def assert_write(self, path: str) -> Path:
        """Resolve ``path`` and raise unless it is writable."""
        resolved = self.resolve(path)
        if not self._writable_resolved(str(resolved)):
            raise self._reject(path, "target is inside a read-only area of the jail")
        return resolved

    def add_writable(self, path: str) -> Path:
        """Mark a sub-path writable, creating it if necessary."""
        resolved = self.resolve(path)
        resolved.mkdir(parents=True, exist_ok=True)
        self._writable.append(str(resolved))
        return resolved

    def add_mount(self, mount: MountPoint) -> None:
        """Expose an extra host directory to the jail."""
        source = mount.resolved_source()
        if not os.path.isdir(source):
            raise self._reject(mount.source, "mount source is not a directory")
        if self._is_always_denied(source):
            raise self._reject(mount.source, "refusing to mount a hard-denied host location")
        self.mounts.append(mount)
        log.info(
            "jail mount added",
            fields={"source": source, "target": mount.target, "read_only": mount.read_only},
        )

    def write_text(self, path: str, content: str, *, encoding: str = "utf-8") -> Path:
        """Safely materialise a file inside the jail."""
        target = self.assert_write(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding=encoding)
        return target

    def read_text(self, path: str, *, encoding: str = "utf-8", limit: int = 1 << 20) -> str:
        """Read a jailed file, capped at ``limit`` bytes."""
        target = self.resolve(path)
        with open(target, "r", encoding=encoding, errors="replace") as handle:
            return handle.read(limit)

    def scan_for_links(self) -> List[Dict[str, str]]:
        """Walk the jail and report symlinks whose target escapes it.

        Called after a sandboxed run: a workload that plants an escaping link is
        preparing an attack against the *next* run that reuses the directory.
        """
        found: List[Dict[str, str]] = []
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            for name in list(dirnames) + list(filenames):
                full = os.path.join(dirpath, name)
                if not os.path.islink(full):
                    continue
                target = os.path.realpath(full)
                if not self._contained(target):
                    found.append({"link": full, "target": target})
        if found:
            log.warning("escaping symlinks found in jail", fields={"count": len(found)})
        return found

    def docker_volume_flags(self) -> List[str]:
        """Render the jail + mounts as ``docker run -v`` arguments."""
        flags = [f"-v={self.root}:/workspace:rw"]
        for mount in self.mounts:
            mode = "ro" if mount.read_only else "rw"
            flags.append(f"-v={mount.resolved_source()}:{mount.target}:{mode}")
        return flags

    def stats(self) -> Dict[str, Any]:
        """Summary for audit records."""
        return {
            "root": self.root,
            "writable_areas": list(self._writable) or ["<entire jail>"],
            "mounts": [
                {"source": m.resolved_source(), "target": m.target, "read_only": m.read_only}
                for m in self.mounts
            ],
            "follow_symlinks": self.follow_symlinks,
            "violations": len(self.violations),
            "platform": sys.platform,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<FilesystemJail root={self.root!r} mounts={len(self.mounts)}>"


def iter_denied_locations() -> Iterable[str]:
    """Yield the hard-denied host paths for the current platform."""
    return _ALWAYS_DENY_WINDOWS if IS_WINDOWS else _ALWAYS_DENY_POSIX


@dataclass
class JailReport:
    """Aggregated jail state attached to a sandbox result."""

    root: str = ""
    violations: List[Dict[str, Any]] = field(default_factory=list)
    escaping_links: List[Dict[str, str]] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.violations and not self.escaping_links
