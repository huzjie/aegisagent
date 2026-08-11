"""Risk scoring for AegisAgent.

This is the aggregation layer that fuses every upstream signal into one verdict:

* **action categories** (what the call does) - :mod:`aegis.classify.classifier`
* **blast radius** (how far damage could spread) - :mod:`aegis.classify.blast_radius`
* **argument risks** (dangerous literals in the args) - :mod:`aegis.classify.argument_rules`
* **detection findings** (prompt injection, exfil, ...) - :mod:`aegis.detect`
* **provenance / principal / environment** posture

Each signal contributes a bounded amount so that no single weak signal dominates,
but a genuinely dangerous combination (destructive category *and* huge blast
radius *and* a firing argument rule *and* a detection finding) saturates quickly
to CRITICAL.  The output is a :class:`RiskLevel`, a 0-100 score and a concrete
recommended :class:`~aegis.core.types.Effect`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.config import Settings
from ..core.logging import get_logger
from ..core.types import (
    ActionCategory,
    Effect,
    EvaluationContext,
    Finding,
    ProvenanceRecord,
    RiskLevel,
    Severity,
)
from .argument_rules import ArgumentRisk
from .blast_radius import BlastRadius, BlastRadiusEstimator
from .classifier import ActionClassifier, Classification

__all__ = ["RiskAssessment", "RiskScorer", "recommend_effect"]

LOGGER = get_logger("classify.scoring")

#: Bounds on how much each signal can add to the score (keeps one weak signal
#: from dominating; the combination saturates at 100).
_CAP_CATEGORY = 100.0
_CAP_BLAST = 40.0
_CAP_ARGUMENT = 30.0
_CAP_FINDINGS = 35.0
_CAP_PROVENANCE = 12.0
_CAP_PRINCIPAL = 8.0

#: Score thresholds -> recommended enforcement effect.
_EFFECT_THRESHOLDS: List[Tuple[float, Effect]] = [
    (90.0, Effect.QUARANTINE),
    (75.0, Effect.DENY),
    (55.0, Effect.REQUIRE_APPROVAL),
    (35.0, Effect.SANDBOX),
    (15.0, Effect.OBSERVE),
    (0.0, Effect.ALLOW),
]


def recommend_effect(score: float) -> Effect:
    """Map a 0-100 risk score onto the most restrictive sensible effect."""
    for threshold, effect in _EFFECT_THRESHOLDS:
        if score >= threshold:
            return effect
    return Effect.ALLOW


@dataclass
class RiskAssessment:
    """The fused risk verdict for one tool call.

    Attributes:
        risk: Coarse :class:`RiskLevel` band.
        risk_score: Continuous 0-100 score.
        categories: Categories that contributed to the verdict.
        factors: ``(label, contribution)`` pairs, ordered by contribution.
        recommendation: Concrete :class:`Effect` the policy layer should apply.
        classification: The underlying action classification (compact form).
        blast_radius: The underlying blast-radius estimate (compact form).
    """

    risk: RiskLevel = RiskLevel.NONE
    risk_score: float = 0.0
    categories: List[ActionCategory] = field(default_factory=list)
    factors: List[Tuple[str, float]] = field(default_factory=list)
    recommendation: Effect = Effect.ALLOW
    classification: Dict[str, Any] = field(default_factory=dict)
    blast_radius: Dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        """True when the recommendation blocks execution by default."""
        return self.recommendation.blocks_execution

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk": self.risk.value,
            "risk_score": round(self.risk_score, 2),
            "categories": [c.value for c in self.categories],
            "factors": [(label, round(value, 2)) for label, value in self.factors],
            "recommendation": self.recommendation.value,
            "blocked": self.blocked,
            "classification": self.classification,
            "blast_radius": self.blast_radius,
        }


class RiskScorer:
    """Fuses classification, blast radius, argument risks and findings."""

    def __init__(
        self,
        *,
        classifier: Optional[ActionClassifier] = None,
        blast_estimator: Optional[BlastRadiusEstimator] = None,
        cap_blast: float = _CAP_BLAST,
        cap_argument: float = _CAP_ARGUMENT,
        cap_findings: float = _CAP_FINDINGS,
    ) -> None:
        """Args:
        classifier: Used by :meth:`assess`; built on demand if omitted.
        blast_estimator: Used by :meth:`assess`; built on demand if omitted.
        cap_blast/cap_argument/cap_findings: Upper contribution of each signal.
        """
        self.classifier = classifier or ActionClassifier()
        self.blast_estimator = blast_estimator or BlastRadiusEstimator()
        self.cap_blast = float(cap_blast)
        self.cap_argument = float(cap_argument)
        self.cap_findings = float(cap_findings)

    @classmethod
    def from_settings(cls, settings: Optional[Settings] = None, **kwargs: Any) -> "RiskScorer":
        """Build from the ``classification`` config section if present."""
        if settings is not None:
            section = getattr(settings, "section", lambda _: {}).__call__("classification")
            if isinstance(section, dict):
                caps = section.get("scoring", {}) if isinstance(section, dict) else {}
                if isinstance(caps, dict):
                    kwargs.setdefault("cap_blast", float(caps.get("cap_blast", _CAP_BLAST)))
                    kwargs.setdefault("cap_argument", float(caps.get("cap_argument", _CAP_ARGUMENT)))
                    kwargs.setdefault("cap_findings", float(caps.get("cap_findings", _CAP_FINDINGS)))
        return cls(**kwargs)

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def score(
        self,
        classification: Classification,
        blast_radius: BlastRadius,
        *,
        argument_risks: Sequence[ArgumentRisk] = (),
        findings: Sequence[Finding] = (),
        provenance: Optional[ProvenanceRecord] = None,
        ctx: Optional[EvaluationContext] = None,
    ) -> RiskAssessment:
        """Combine the upstream signals into a single risk verdict.

        Args:
            classification: The action classification.
            blast_radius: The blast-radius estimate.
            argument_risks: Argument-rule hits (category-advancing).
            findings: Detection findings from :mod:`aegis.detect`.
            provenance: Provenance verification result, if available.
            ctx: Optional full context for principal/agent posture adjustments.

        Returns:
            A :class:`RiskAssessment`.
        """
        factors: List[Tuple[str, float]] = []

        # 1. Base from the worst action category.
        base = max((c.default_risk.score for c in classification.categories), default=0)
        factors.append(("action_category", base))

        # 2. Blast radius contribution.
        blast = min(self.cap_blast, blast_radius.score * 0.45)
        if blast:
            factors.append(("blast_radius", blast))

        # 3. Argument rules.
        arg_sum = sum(r.weighted_score for r in argument_risks)
        arg_add = min(self.cap_argument, arg_sum)
        if arg_add:
            factors.append(("argument_rules", arg_add))

        # 4. Detection findings.
        find_sum = sum(f.weighted_score for f in findings)
        find_add = min(self.cap_findings, find_sum)
        if find_add:
            factors.append(("detection_findings", find_add))

        # 5. Provenance posture.
        if provenance is not None and provenance.status.risk.score > 0:
            prov_add = min(_CAP_PROVENANCE, provenance.status.risk.score * 0.15)
            if prov_add:
                factors.append((f"provenance_{provenance.status.value}", prov_add))

        # 6. Caller / agent posture.
        if ctx is not None:
            principal = ctx.principal
            if principal is not None and not principal.mfa_verified:
                factors.append(("no_mfa", min(_CAP_PRINCIPAL, 5.0)))
            if getattr(ctx.agent, "trust_tier", "standard") == "untrusted":
                factors.append(("untrusted_agent", min(_CAP_PRINCIPAL, 4.0)))

        total = min(100.0, sum(value for _, value in factors))
        total = round(total, 2)
        risk = RiskLevel.from_score(total)

        return RiskAssessment(
            risk=risk,
            risk_score=total,
            categories=list(classification.categories),
            factors=sorted(factors, key=lambda f: f[1], reverse=True),
            recommendation=recommend_effect(total),
            classification=classification.to_dict(),
            blast_radius=blast_radius.to_dict(),
        )

    def assess(
        self,
        ctx: EvaluationContext,
        *,
        argument_risks: Optional[Sequence[ArgumentRisk]] = None,
        findings: Optional[Sequence[Finding]] = None,
    ) -> Tuple[Classification, BlastRadius, RiskAssessment]:
        """Run classify -> blast-radius -> score in one call.

        Args:
            ctx: Full evaluation context.
            argument_risks: Pre-computed risks; computed via the bundled
                :class:`ArgumentRiskRules` when omitted.
            findings: Detection findings; pulled from ``ctx.findings`` when omitted.

        Returns:
            ``(classification, blast_radius, assessment)`` so callers can render
            each stage.
        """
        classification = self.classifier.classify(ctx)
        blast_radius = self.blast_estimator.estimate(classification, ctx)
        if argument_risks is None:
            from .argument_rules import ArgumentRiskRules

            argument_risks = ArgumentRiskRules().evaluate(ctx)
        if findings is None:
            findings = list(ctx.findings or [])
        assessment = self.score(
            classification,
            blast_radius,
            argument_risks=argument_risks,
            findings=findings,
            provenance=ctx.provenance,
            ctx=ctx,
        )
        return classification, blast_radius, assessment

    def describe(self) -> Dict[str, Any]:
        """Machine-readable summary for ``/v1/classifiers`` and the CLI."""
        return {
            "name": "risk_scorer",
            "cap_blast": self.cap_blast,
            "cap_argument": self.cap_argument,
            "cap_findings": self.cap_findings,
            "doc": (self.__class__.__doc__ or "").strip().splitlines()[0],
        }
