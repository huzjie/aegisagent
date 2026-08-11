"""Action classification and risk scoring for AegisAgent.

This package turns a raw :class:`~aegis.core.types.ToolCall` into a structured
:class:`Classification` (categories + risk score + blast radius).  It is a pure
function of the call and its declared descriptor; side-effecting subsystems
(provenance, policy, approval) consume its output.
"""

from __future__ import annotations

from .argument_rules import ArgumentRiskRules, RuleHit
from .blast_radius import BlastRadius, BlastRadiusEstimator, estimate_blast_radius
from .classifier import ActionClassifier, Classification, classify
from .scoring import RiskScorer
from .taxonomy import (
    ACTION_VERBS,
    ACTION_VERBS_ZH,
    CATEGORY_DESCRIPTIONS,
    infer_categories,
    infer_from_arguments,
    infer_from_description,
    infer_from_tool_name,
)

__all__ = [
    "ActionClassifier",
    "Classification",
    "classify",
    "BlastRadius",
    "BlastRadiusEstimator",
    "estimate_blast_radius",
    "ArgumentRiskRules",
    "RuleHit",
    "RiskScorer",
    "ACTION_VERBS",
    "ACTION_VERBS_ZH",
    "CATEGORY_DESCRIPTIONS",
    "infer_categories",
    "infer_from_tool_name",
    "infer_from_description",
    "infer_from_arguments",
]
