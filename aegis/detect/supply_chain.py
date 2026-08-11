"""Supply-chain detector.

Agents that can run ``pip install`` / ``npm i`` / ``curl | sh`` are one poisoned
package away from full compromise.  This detector inspects install and fetch
commands for:

* typosquats of popular packages (Levenshtein distance 1-2 from a known name),
* names on the published malicious-package list,
* installs pointed at an unofficial registry / index URL,
* ``curl | bash`` style remote-code execution one-liners,
* unpinned or ``--pre`` / ``@latest`` installs into production.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from ..core.logging import get_logger
from ..core.types import DetectorKind, EvaluationContext, Finding, Severity
from ..core.utils import levenshtein
from .base import Detector
from .indicators import (
    MALICIOUS_PACKAGE_NAMES,
    OFFICIAL_REGISTRIES,
    POPULAR_PACKAGES,
    UNOFFICIAL_REGISTRIES,
    registrable_domain,
    split_url,
)

LOGGER = get_logger("detect.supply_chain")

#: ``pip install foo bar``, ``npm i foo``, ``cargo add foo`` ...
_INSTALL_RE = re.compile(
    r"\b(?P<mgr>pip3?|pipx|uv|poetry|npm|pnpm|yarn|bun|cargo|gem|go|apt|apk|brew)\s+"
    r"(?:install|add|i|get)\b(?P<rest>[^\n;&|]*)",
    re.IGNORECASE,
)

#: Remote script execution: ``curl ... | sh``.
_PIPE_SHELL_RE = re.compile(
    r"\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n|;]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k|)sh\b",
    re.IGNORECASE,
)

#: ``--index-url`` / ``--registry`` overrides.
_REGISTRY_FLAG_RE = re.compile(
    r"(?:--index-url|--extra-index-url|--registry|-i)\s*[=\s]\s*(?P<url>\S+)",
    re.IGNORECASE,
)

#: Package specifier that has no pinned version.
_UNPINNED_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@/-]*$")

#: Mapping manager -> ecosystem key in POPULAR_PACKAGES.
_ECOSYSTEM: Dict[str, str] = {
    "pip": "pypi", "pip3": "pypi", "pipx": "pypi", "uv": "pypi", "poetry": "pypi",
    "npm": "npm", "pnpm": "npm", "yarn": "npm", "bun": "npm",
    "cargo": "crates", "gem": "gem",
}

#: Flags to ignore when extracting package names.
_FLAG_PREFIXES = ("-", "--")


class SupplyChainDetector(Detector):
    """Detects poisoned dependencies and remote-code-execution installs."""

    name = "supply_chain"
    kind = DetectorKind.SUPPLY_CHAIN
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        enabled: bool = True,
        min_confidence: float = 0.4,
        typosquat_distance: int = 2,
        flag_unpinned: bool = True,
        **options: Any,
    ) -> None:
        """Args:
        enabled: Registry enable flag.
        min_confidence: Drop findings below this confidence.
        typosquat_distance: Max edit distance to a popular name to alert on.
        flag_unpinned: Report unpinned installs in production environments.
        """
        super().__init__(enabled=enabled, **options)
        self.min_confidence = float(min_confidence)
        self.typosquat_distance = int(typosquat_distance)
        self.flag_unpinned = bool(flag_unpinned)

    def analyze(self, ctx: EvaluationContext) -> List[Finding]:
        from .text_sources import iter_argument_spans

        findings: List[Finding] = []
        production = (ctx.environment or "").lower().startswith("prod")
        for span in iter_argument_spans(ctx):
            findings.extend(self._scan(span.text, span.location, production=production))
        return findings

    def _scan(self, text: str, location: str, *, production: bool = False) -> List[Finding]:
        findings: List[Finding] = []
        if _PIPE_SHELL_RE.search(text):
            findings.append(
                self.make_finding(
                    "Remote script piped into a shell",
                    description=(
                        "Command downloads a remote script and executes it directly. "
                        "The content can change between review and execution (TOCTOU) and "
                        "gives the remote host arbitrary code execution."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    evidence=[_first(_PIPE_SHELL_RE, text)],
                    location=location,
                    remediation="Download, checksum and review the script before executing it.",
                    tags=["supply_chain", "rce", "curl_pipe_sh"],
                )
            )

        for match in _REGISTRY_FLAG_RE.finditer(text):
            url = match.group("url").strip("\"'")
            _, host, _, _ = split_url(url)
            if not host:
                continue
            domain = registrable_domain(host)
            known = host in OFFICIAL_REGISTRIES or domain in OFFICIAL_REGISTRIES
            hostile = host in UNOFFICIAL_REGISTRIES or domain in UNOFFICIAL_REGISTRIES
            if known and not hostile:
                continue
            findings.append(
                self.make_finding(
                    "Install redirected to a non-canonical registry",
                    description=(
                        f"Dependency install points at '{host}', which is not a canonical "
                        "package index. Dependency-confusion and poisoned-mirror attacks "
                        "start exactly here."
                    ),
                    severity=Severity.CRITICAL if hostile else Severity.HIGH,
                    confidence=0.85 if hostile else 0.65,
                    evidence=[f"registry={url}"],
                    location=location,
                    remediation="Pin installs to the approved registry and verify checksums.",
                    tags=["supply_chain", "registry", "dependency_confusion"],
                )
            )

        for match in _INSTALL_RE.finditer(text):
            manager = match.group("mgr").lower()
            ecosystem = _ECOSYSTEM.get(manager)
            packages = _packages(match.group("rest"))
            for package in packages:
                findings.extend(
                    self._judge_package(package, ecosystem, location, production=production)
                )
        return findings

    def _judge_package(
        self, package: str, ecosystem: Optional[str], location: str, *, production: bool
    ) -> List[Finding]:
        bare, pinned = _split_spec(package)
        low = bare.lower()
        out: List[Finding] = []
        if low in MALICIOUS_PACKAGE_NAMES:
            out.append(
                self.make_finding(
                    "Known malicious package requested",
                    description=(
                        f"'{bare}' appears on the published malicious-package list "
                        "(typosquat / trojaned release)."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    evidence=[f"package={package}"],
                    location=location,
                    remediation="Block the install and audit the environment for prior installs.",
                    tags=["supply_chain", "malicious_package"],
                )
            )
            return out

        near = self._typosquat(low, ecosystem)
        if near is not None:
            target, distance = near
            out.append(
                self.make_finding(
                    "Possible typosquat package",
                    description=(
                        f"'{bare}' is {distance} edit(s) from the popular package "
                        f"'{target}'. Typosquatting is the dominant delivery vector for "
                        "supply-chain malware."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.8 if distance == 1 else 0.6,
                    evidence=[f"requested={bare}", f"popular={target}", f"distance={distance}"],
                    location=location,
                    remediation="Confirm the intended package name before installing.",
                    tags=["supply_chain", "typosquat"],
                )
            )
            return out

        if self.flag_unpinned and production and not pinned and _UNPINNED_RE.match(bare):
            out.append(
                self.make_finding(
                    "Unpinned dependency install in production",
                    description=(
                        f"'{bare}' is installed without a version pin, so a compromised "
                        "release is picked up automatically."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.45,
                    evidence=[f"package={package}"],
                    location=location,
                    remediation="Pin exact versions and use a lockfile with hashes.",
                    tags=["supply_chain", "unpinned"],
                )
            )
        return out

    def _typosquat(self, name: str, ecosystem: Optional[str]) -> Optional[Tuple[str, int]]:
        """Return ``(popular_name, distance)`` when ``name`` is a near miss."""
        pools = (
            [POPULAR_PACKAGES[ecosystem]] if ecosystem in POPULAR_PACKAGES else list(POPULAR_PACKAGES.values())
        )
        best: Optional[Tuple[str, int]] = None
        for pool in pools:
            for popular in pool:
                if name == popular:
                    return None
                distance = levenshtein(name, popular, limit=8)
                if distance == 0 or distance > self.typosquat_distance:
                    continue
                # Very short names produce noisy near-misses.
                if len(popular) <= 4 and distance > 1:
                    continue
                if best is None or distance < best[1]:
                    best = (popular, distance)
        return best

    def analyze_text(self, text: str, location: str = "text") -> List[Finding]:
        return self._scan(text, location, production=False)


def _packages(rest: str) -> List[str]:
    """Extract package specifiers from the tail of an install command."""
    out: List[str] = []
    for token in rest.split():
        token = token.strip("\"'`,")
        if not token or token.startswith(_FLAG_PREFIXES):
            continue
        if token in ("install", "add", "get", "i"):
            continue
        if "/" in token and "://" in token:
            continue
        out.append(token)
    return out[:20]


def _split_spec(package: str) -> Tuple[str, bool]:
    """Split ``name==1.2.3`` / ``name@1.2`` into ``(name, is_pinned)``."""
    for separator in ("==", ">=", "<=", "~=", "!=", "@"):
        if separator in package[1:]:
            index = package.index(separator, 1)
            name = package[:index]
            version = package[index + len(separator):]
            pinned = bool(version) and version.lower() not in ("latest", "next", "*")
            return name, pinned
    return package, False


def _first(pattern: re.Pattern[str], text: str) -> str:
    """First match of ``pattern`` in ``text`` (empty string when absent)."""
    match = pattern.search(text)
    return match.group(0) if match else ""
