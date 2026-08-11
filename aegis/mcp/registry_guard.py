"""Guard the tool registry against shadowing and server spoofing.

When many MCP servers are connected, the registry becomes an attack surface:
a malicious server can register a tool named ``github::delete_repo`` that
*shadows* a trusted one, or choose a display name spelling-close to an
authoritative provider to trick operators.  The guard applies three
defences:

1. **Name shadowing** — two enabled servers may not both own the same bare
   tool name unless explicitly allowed; collisions are flagged.
2. **Spoofing** — a server whose name is confusably similar to a trusted
   provider (typosquat, homoglyph, prefix/suffix padding) is rejected or
   quarantined.
3. **Surface cloning** — a server offering an identical tool set to a trusted
   one, but with a different identity, is treated as a likely impersonator.

The guard is pure analysis: it returns verdicts, it does not itself mutate the
registry.  The proxy decides what to do with a negative verdict (block,
quarantine, or human-review).
"""

from __future__ import annotations

import difflib
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, List, Optional, Sequence

from ..core.logging import get_logger
from ..core.utils import levenshtein

__all__ = [
    "GuardVerdict",
    "ShadowingReport",
    "RegistryGuard",
    "RegistryGuardConfig",
    "TRUSTED_PROVIDERS",
]


class GuardVerdict(str, Enum):
    """Outcome of a registry-guard check."""

    ALLOW = "allow"
    FLAG_SHADOWING = "flag_shadowing"
    FLAG_SPOOFING = "flag_spoofing"
    REJECT = "reject"


#: Code points that render (near) identically to a Latin character.  Attackers
#: use these to register ``githуb`` (Cyrillic ``у``) or ``0penai`` and win name
#: resolution against the real provider.  Folding them before comparison turns
#: a visual attack into an exact-match detection.
_CONFUSABLES = {
    # Cyrillic look-alikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g", "м": "m",
    "т": "t", "в": "b", "к": "k", "н": "h",
    # Greek look-alikes
    "ο": "o", "α": "a", "ρ": "p", "τ": "t", "ν": "v", "κ": "k", "ι": "i",
    # digit / symbol substitutions
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}

#: Canonical provider names that must not be impersonated.
TRUSTED_PROVIDERS = (
    "github",
    "gitlab",
    "aws",
    "gcp",
    "azure",
    "openai",
    "anthropic",
    "google",
    "slack",
    "notion",
    "postgres",
    "mysql",
    "stripe",
    "datadog",
    "pagerduty",
    "terraform",
    "kubernetes",
)


@dataclass
class ShadowingReport:
    """Findings from a single guard evaluation."""

    verdict: GuardVerdict = GuardVerdict.ALLOW
    server_id: str = ""
    server_name: str = ""
    reasons: List[str] = field(default_factory=list)
    shadowed_tools: List[str] = field(default_factory=list)
    spoof_target: str = ""

    @property
    def clean(self) -> bool:
        """Whether the server passed without a flag."""
        return self.verdict is GuardVerdict.ALLOW

    def to_dict(self) -> dict:
        """Serialise the report."""
        return {
            "verdict": self.verdict.value,
            "server_id": self.server_id,
            "server_name": self.server_name,
            "reasons": list(self.reasons),
            "shadowed_tools": list(self.shadowed_tools),
            "spoof_target": self.spoof_target,
        }


@dataclass
class RegistryGuardConfig:
    """Tunables for the registry guard."""

    reject_spoofing: bool = True
    reject_shadowing: bool = False
    allow_explicit_shadowing: bool = True
    similarity_threshold: float = 0.85
    trusted_providers: Sequence[str] = field(default_factory=lambda: list(TRUSTED_PROVIDERS))

    def validate(self) -> None:
        """Clamp the similarity threshold into (0,1]."""
        self.similarity_threshold = max(0.01, min(1.0, float(self.similarity_threshold)))


class RegistryGuard:
    """Analyses server registrations for shadowing and spoofing."""

    def __init__(self, config: Optional[RegistryGuardConfig] = None) -> None:
        """Create the guard.

        Args:
            config: Guard tunables; defaults to rejecting spoofing only.
        """
        self._config = config or RegistryGuardConfig()
        self._config.validate()

    @property
    def config(self) -> RegistryGuardConfig:
        """Return the active config."""
        return self._config

    # -- public API ---------------------------------------------------------

    def evaluate(
        self,
        server_id: str,
        server_name: str,
        tool_names: Sequence[str],
        *,
        known_servers: Optional[Iterable["_KnownServer"]] = None,
    ) -> ShadowingReport:
        """Evaluate a candidate server against the registry.

        Args:
            server_id: Stable identifier of the candidate.
            server_name: Display name of the candidate.
            tool_names: Tool names the candidate will advertise.
            known_servers: Servers already registered (for shadowing/cloning
                checks).  Each must expose ``server_id``, ``name`` and
                ``tool_names``.

        Returns:
            A :class:`ShadowingReport` with the verdict and reasons.
        """
        report = ShadowingReport(server_id=server_id, server_name=server_name)
        known = list(known_servers or [])

        spoof = self.detect_spoofing(server_name)
        if spoof:
            report.spoof_target = spoof
            report.reasons.append(f"name is confusably similar to trusted provider '{spoof}'")
            report.verdict = GuardVerdict.REJECT if self._config.reject_spoofing else GuardVerdict.FLAG_SPOOFING
            return report

        shadowed = self.detect_shadowing(tool_names, known, exclude=server_id)
        if shadowed:
            report.shadowed_tools = shadowed
            report.reasons.append(f"{len(shadowed)} tool name(s) shadow a trusted server")
            if self._config.reject_shadowing and not self._config.allow_explicit_shadowing:
                report.verdict = GuardVerdict.REJECT
            else:
                report.verdict = GuardVerdict.FLAG_SHADOWING
            if report.verdict is GuardVerdict.ALLOW:
                report.verdict = GuardVerdict.FLAG_SHADOWING

        return report

    # -- spoofing -----------------------------------------------------------

    def detect_spoofing(self, name: str) -> str:
        """Return the trusted provider a name is impersonating, or ``""``.

        Four independent signals are tried, because each catches a different
        real-world trick and any one of them alone is evadable:

        1. **Homoglyph collapse** — after confusable folding the name is
           *identical* to a provider (``githуb`` with a Cyrillic ``у``).  This
           is the strongest signal and is always spoofing.
        2. **Typosquat** — small edit distance relative to name length
           (``githup``, ``anthropc``, ``opena1``).
        3. **Sequence similarity** — the configurable ratio threshold.
        4. **Padding** — a provider name wrapped in decoration
           (``aws-prod-1``, ``my-github``) that a human reads as the provider.

        Args:
            name: The candidate server display name.

        Returns:
            The impersonated trusted provider name, or an empty string when the
            candidate looks legitimate.
        """
        normalised = self._normalize(name)
        if not normalised:
            return ""
        raw_ascii = self._strip_to_alnum(name)

        for provider in self._config.trusted_providers:
            # 1. Homoglyph collapse: identical only *after* confusable folding
            #    means the raw name was deliberately disguised.
            if normalised == provider:
                if raw_ascii != provider:
                    return provider
                continue  # genuinely the provider's own name

            # 2. Typosquat via bounded edit distance.
            if self._is_typosquat(normalised, provider):
                return provider

            # 3. Configurable sequence similarity.
            if difflib.SequenceMatcher(None, normalised, provider).ratio() >= self._config.similarity_threshold:
                return provider

            # 4. Padding / separators around a provider name.
            if provider in normalised and len(normalised) - len(provider) <= max(4, len(provider) // 2):
                return provider
        return ""

    @staticmethod
    def _is_typosquat(candidate: str, provider: str) -> bool:
        """Whether ``candidate`` is within typo distance of ``provider``.

        Short names get a tighter budget so that genuinely distinct three or
        four letter names (``aws`` vs ``abs``) are not flagged wholesale.

        Args:
            candidate: Normalised candidate name.
            provider: Normalised trusted provider name.

        Returns:
            ``True`` when the names differ by at most the allowed edits.
        """
        if abs(len(candidate) - len(provider)) > 2:
            return False
        if len(provider) < 5:
            return False
        budget = 1 if len(provider) < 8 else 2
        return levenshtein(candidate, provider, limit=len(provider) + 4) <= budget

    @classmethod
    def _normalize(cls, name: str) -> str:
        """Fold a name to a comparable ASCII skeleton.

        Applies NFKD decomposition, strips combining marks, maps known
        confusable code points (Cyrillic/Greek look-alikes and digit
        substitutions) to their Latin counterparts, lowercases and drops every
        non-alphanumeric separator.

        Args:
            name: The raw display name.

        Returns:
            The folded skeleton used for all similarity comparisons.
        """
        folded = cls._strip_to_alnum(name)
        return "".join(_CONFUSABLES.get(ch, ch) for ch in folded)

    @staticmethod
    def _strip_to_alnum(name: str) -> str:
        """Lowercase, strip diacritics and remove separators/spaces."""
        decomposed = unicodedata.normalize("NFKD", str(name))
        without_marks = "".join(c for c in decomposed if not unicodedata.combining(c))
        return "".join(ch for ch in without_marks.lower() if ch.isalnum())

    # -- shadowing ----------------------------------------------------------

    def detect_shadowing(
        self,
        tool_names: Sequence[str],
        known_servers: Iterable["_KnownServer"],
        *,
        exclude: str = "",
    ) -> List[str]:
        """Find bare tool names already owned by another enabled server.

        Args:
            tool_names: Candidate tool names.
            known_servers: Already-registered servers.
            exclude: Server id to ignore (e.g. a re-registration).

        Returns:
            The subset of ``tool_names`` that collide with a *different*
            server.  Exact same-server collisions are ignored.
        """
        collisions: List[str] = []
        seen: dict = {}
        for server in known_servers:
            if getattr(server, "server_id", "") == exclude:
                continue
            if not getattr(server, "enabled", True):
                continue
            for tool in getattr(server, "tool_names", []) or []:
                seen.setdefault(tool, []).append(getattr(server, "server_id", ""))
        for tool in tool_names:
            owners = seen.get(tool)
            if owners:
                collisions.append(tool)
        return collisions

    def detect_surface_clone(self, tool_names: Sequence[str], reference: Sequence[str]) -> bool:
        """Whether ``tool_names`` is an identical set to ``reference``.

        Servers that clone a trusted server's entire tool surface but carry a
        different identity are treated as impersonators.

        Args:
            tool_names: Candidate tool names.
            reference: A trusted server's tool names.

        Returns:
            ``True`` when the sets are equal and non-empty.
        """
        a = set(tool_names)
        b = set(reference)
        return bool(a) and a == b
