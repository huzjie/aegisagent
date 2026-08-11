"""Action classifier for AegisAgent.

Turns an :class:`~aegis.core.types.EvaluationContext` (or a bare tool call) into a
stable set of :class:`~aegis.core.types.ActionCategory` values plus a confidence
and the evidence that produced them.  This is the *what is the agent trying to
do* layer; the *how bad is it* reasoning lives in
:mod:`aegis.classify.scoring` and :mod:`aegis.classify.blast_radius`.

Classification is intentionally cheap and deterministic: it consults the declared
:class:`ToolDescriptor` first, then falls back to the verb heuristics in
:mod:`aegis.classify.taxonomy`.  Renaming a tool without changing its declared
categories therefore cannot lower its classification - a deliberate defence
against name-based evasion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..core.config import Settings
from ..core.logging import get_logger
from ..core.types import ActionCategory, EvaluationContext, ToolCall, ToolDescriptor
from .taxonomy import explain_categories, infer_categories

__all__ = ["Classification", "ActionClassifier"]

LOGGER = get_logger("classify.classifier")


@dataclass
class Classification:
    """The result of classifying one tool call.

    Attributes:
        categories: Ordered, de-duplicated action categories.
        confidence: Overall confidence in the classification, ``[0, 1]``.
        evidence: Short human-readable reasons (tool name, declared categories,
            matched verbs).
        tool: The qualified tool name that was classified.
        declared: Whether the descriptor already declared categories (vs inferred).
    """

    categories: List[ActionCategory] = field(default_factory=list)
    confidence: float = 0.5
    evidence: List[str] = field(default_factory=list)
    tool: str = ""
    declared: bool = False

    @property
    def worst(self) -> ActionCategory:
        """The highest-risk category present (``UNKNOWN`` when empty)."""
        from ..core.types import ActionCategory as _AC

        if not self.categories:
            return _AC.UNKNOWN
        return max(self.categories, key=lambda c: c.default_risk.score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "categories": [c.value for c in self.categories],
            "confidence": self.confidence,
            "declared": self.declared,
            "evidence": list(self.evidence),
        }


class ActionClassifier:
    """Infers action categories for a tool call."""

    def __init__(
        self,
        *,
        min_confidence: float = 0.3,
        include_argument_values: bool = True,
    ) -> None:
        """Args:
        min_confidence: Confidence floor used only for reporting; inference
            always returns a (possibly ``UNKNOWN``) classification.
        include_argument_values: Passed to :func:`infer_categories` so that
            command-like tool arguments contribute verbs.
        """
        self.min_confidence = float(min_confidence)
        self.include_argument_values = bool(include_argument_values)

    @classmethod
    def from_settings(cls, settings: Optional[Settings] = None, **kwargs: Any) -> "ActionClassifier":
        """Build from the ``classification`` config section if present."""
        if settings is not None:
            section = getattr(settings, "section", lambda _: {}).__call__("classification")
            if isinstance(section, dict):
                kwargs.setdefault("min_confidence", float(section.get("min_confidence", 0.3)))
        return cls(**kwargs)

    # ------------------------------------------------------------------ #
    # Classification
    # ------------------------------------------------------------------ #
    def classify_call(
        self,
        call: ToolCall,
        descriptor: Optional[ToolDescriptor] = None,
    ) -> Classification:
        """Classify a single tool call.

        Args:
            call: The tool call under judgement.
            descriptor: Declared capability surface, if known.

        Returns:
            A :class:`Classification` with categories, confidence and evidence.
        """
        declared = bool(descriptor and descriptor.categories)
        categories = infer_categories(
            call,
            descriptor,
            include_argument_values=self.include_argument_values,
        )
        evidence: List[str] = []
        if declared:
            evidence.append(f"declared categories: {explain_categories(categories)}")
        else:
            evidence.append(f"inferred from name/args: {explain_categories(categories)}")
        if call.qualified_name:
            evidence.append(f"tool={call.qualified_name}")

        # Confidence: declared categories are authoritative; inference is softer.
        confidence = 0.9 if declared else 0.6
        if ActionCategory.UNKNOWN in categories and len(categories) == 1:
            confidence = 0.35
            evidence.append("no strong verb signal; defaulted to unknown")

        return Classification(
            categories=categories,
            confidence=round(confidence, 4),
            evidence=evidence,
            tool=call.qualified_name or call.tool,
            declared=declared,
        )

    def classify(self, ctx: EvaluationContext) -> Classification:
        """Classify the call inside an evaluation context."""
        return self.classify_call(ctx.call, ctx.descriptor)

    def describe(self) -> Dict[str, Any]:
        """Machine-readable summary for ``/v1/classifiers`` and the CLI."""
        return {
            "name": "action_classifier",
            "min_confidence": self.min_confidence,
            "include_argument_values": self.include_argument_values,
            "doc": (self.__class__.__doc__ or "").strip().splitlines()[0],
        }
