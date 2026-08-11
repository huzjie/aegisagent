"""Blast-radius estimation for AegisAgent.

Detection tells us *what is wrong*; blast radius tells us *how far the damage
could spread if this call is malicious*.  A `rm -rf` scoped to a throwaway temp
directory is annoying; the same call as root on a production database host is a
company-ending event.  The estimator combines the action categories, the tool's
reversibility metadata, the caller's trust posture and the environment into a
single 0-100 radius score and a coarse ``scope`` label.

Scope ladder (narrowest -> widest)::

    local < host < tenant < multi_tenant < global

Each widening factor raises the ceiling, and the final score is the worst-case
reach, not an average.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.config import Settings
from ..core.logging import get_logger
from ..core.types import ActionCategory, EvaluationContext, Principal, RiskLevel
from .classifier import Classification

__all__ = ["BlastRadius", "BlastRadiusEstimator", "SCOPE_RANK"]

LOGGER = get_logger("classify.blast_radius")

#: Scope ladder ordering (see module docstring).
SCOPE_RANK = {
    "local": 1,
    "host": 2,
    "tenant": 3,
    "multi_tenant": 4,
    "global": 5,
}

_SCOPE_BY_RANK = {rank: name for name, rank in SCOPE_RANK.items()}


@dataclass
class BlastRadius:
    """Estimated reach of a tool call if it were hostile.

    Attributes:
        scope: Coarsest affected boundary (``local`` .. ``global``).
        score: 0-100 estimate of potential impact.
        affected: Concrete resource classes that could be touched.
        factors: Human-readable reasons that widened the radius.
    """

    scope: str = "local"
    score: float = 0.0
    affected: List[str] = field(default_factory=list)
    factors: List[str] = field(default_factory=list)

    def widen(self, scope: str, *, delta: float = 0.0, reason: str = "", affected: str = "") -> None:
        """Increase the scope/score if ``scope`` is wider than the current one."""
        if SCOPE_RANK.get(scope, 0) > SCOPE_RANK.get(self.scope, 0):
            self.scope = scope
        if delta:
            self.score = min(100.0, self.score + delta)
        if reason and reason not in self.factors:
            self.factors.append(reason)
        if affected and affected not in self.affected:
            self.affected.append(affected)

    @property
    def level(self) -> RiskLevel:
        """Map the radius score onto a :class:`RiskLevel` band."""
        return RiskLevel.from_score(self.score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope": self.scope,
            "score": round(self.score, 2),
            "level": self.level.value,
            "affected": list(self.affected),
            "factors": list(self.factors),
        }


class BlastRadiusEstimator:
    """Estimates blast radius from a call's categories and surrounding context."""

    #: Category -> (minimum scope, score contribution, affected label).
    _CATEGORY_IMPACT: Dict[ActionCategory, tuple[str, float, str]] = {
        ActionCategory.DESTRUCTIVE: ("host", 35.0, "data/state on the host"),
        ActionCategory.EXECUTE: ("host", 25.0, "process + filesystem on the host"),
        ActionCategory.SECRET: ("multi_tenant", 30.0, "credentials / key material"),
        ActionCategory.IDENTITY: ("tenant", 25.0, "identities / permissions"),
        ActionCategory.DEPLOY: ("tenant", 30.0, "infrastructure / releases"),
        ActionCategory.NETWORK: ("host", 15.0, "outbound connectivity"),
        ActionCategory.DATA_EXPORT: ("tenant", 25.0, "data leaving the boundary"),
        ActionCategory.PAYMENT: ("multi_tenant", 40.0, "financial instruments"),
        ActionCategory.COMMUNICATION: ("tenant", 15.0, "external messaging"),
        ActionCategory.WRITE: ("host", 12.0, "persisted state"),
        ActionCategory.READ: ("host", 6.0, "read access"),
        ActionCategory.CONFIG: ("tenant", 12.0, "configuration / control plane"),
        ActionCategory.UNKNOWN: ("host", 5.0, "unknown action"),
    }

    def __init__(
        self,
        *,
        production_multiplier: float = 1.25,
        untrusted_multiplier: float = 1.2,
    ) -> None:
        """Args:
        production_multiplier: Extra reach when ``environment == production``.
        untrusted_multiplier: Extra reach when the principal or provenance is
            untrusted.
        """
        self.production_multiplier = float(production_multiplier)
        self.untrusted_multiplier = float(untrusted_multiplier)

    @classmethod
    def from_settings(cls, settings: Optional[Settings] = None, **kwargs: Any) -> "BlastRadiusEstimator":
        """Build from the ``classification.blast_radius`` config section."""
        if settings is not None:
            section = getattr(settings, "section", lambda _: {}).__call__("classification")
            if isinstance(section, dict):
                br = section.get("blast_radius", {}) if isinstance(section, dict) else {}
                if isinstance(br, dict):
                    kwargs.setdefault("production_multiplier", float(br.get("production_multiplier", 1.25)))
                    kwargs.setdefault("untrusted_multiplier", float(br.get("untrusted_multiplier", 1.2)))
        return cls(**kwargs)

    # ------------------------------------------------------------------ #
    # Estimation
    # ------------------------------------------------------------------ #
    def estimate(self, classification: Classification, ctx: EvaluationContext) -> BlastRadius:
        """Estimate the blast radius of a classified call.

        Args:
            classification: The :class:`Classification` from
                :class:`ActionClassifier`.
            ctx: Full evaluation context (principal, provenance, environment).

        Returns:
            A :class:`BlastRadius` with scope, score and the factors that drove it.
        """
        radius = BlastRadius()
        descriptor = ctx.descriptor

        # 1. Category-driven base impact.
        for category in classification.categories:
            scope, delta, affected = self._CATEGORY_IMPACT.get(
                category, ("host", 5.0, "unknown action")
            )
            radius.widen(
                scope,
                delta=delta,
                reason=f"category={category.value}",
                affected=affected,
            )

        # 2. Irreversibility widens reach.
        if descriptor is not None and not descriptor.reversible:
            radius.widen("host", delta=10.0, reason="tool declared irreversible", affected="state")

        # 3. Trust posture of the caller.
        principal = ctx.principal
        if principal is not None and self._is_untrusted_principal(principal):
            radius.widen(
                "tenant",
                delta=10.0 * (self.untrusted_multiplier - 1.0) + 5.0,
                reason="untrusted principal (no MFA / low tier)",
                affected="principal scope",
            )

        # 4. Provenance status.
        provenance = ctx.provenance
        if provenance is not None and provenance.status.risk.at_least(RiskLevel.HIGH):
            radius.widen(
                "tenant",
                delta=provenance.status.risk.score * 0.15,
                reason=f"untrusted provenance={provenance.status.value}",
                affected="session",
            )

        # 5. Environment.
        if (ctx.environment or "production").lower() in ("production", "prod"):
            added = radius.score * (self.production_multiplier - 1.0) + 5.0
            radius.widen(radius.scope, delta=added, reason="production environment")

        radius.score = round(min(100.0, radius.score), 2)
        return radius

    @staticmethod
    def _is_untrusted_principal(principal: Principal) -> bool:
        """A principal is untrusted without MFA or outside the privileged tiers."""
        if not principal.mfa_verified:
            return True
        if not principal.has_role("admin", "operator", "service"):
            return True
        return False

    def describe(self) -> Dict[str, Any]:
        """Machine-readable summary for ``/v1/classifiers`` and the CLI."""
        return {
            "name": "blast_radius_estimator",
            "production_multiplier": self.production_multiplier,
            "untrusted_multiplier": self.untrusted_multiplier,
            "doc": (self.__class__.__doc__ or "").strip().splitlines()[0],
        }
