"""AegisAgent detection layer.

The detection layer answers one question about a pending tool call: *is anything
about this call adversarial?*  It never decides what to do about it - that is the
policy engine's job.  Detectors emit :class:`~aegis.core.types.Finding` objects;
the pipeline aggregates them into a risk score the policy engine can reason over.

Layout
------

``base`` / ``registry`` / ``pipeline``
    Detector contract, parallel execution with timeout isolation, and the
    end-to-end pass used by the gateway and MCP proxy.
``signatures`` (+ ``signatures/*.yaml``)
    Declarative regex rule packs so operators can extend coverage without code.
``prompt_injection``
    Heuristic, Unicode, structural and LLM-judge sub-detectors plus their
    ensemble.
``exfiltration`` / ``egress`` / ``secrets`` / ``supply_chain``
    Data-loss, SSRF, credential and dependency-poisoning coverage.
``tool_poisoning`` / ``schema_drift``
    MCP-specific attacks on the declared tool surface.
``anomaly`` / ``content``
    Behavioural outliers and the operator-extensible catch-all pass.

Support modules (``normalizer``, ``entropy``, ``homoglyphs``, ``pii``,
``indicators``, ``text_sources``, ``dedupe``) are shared primitives that keep the
detectors small and consistent.
"""

from __future__ import annotations

from .anomaly import SEQUENCE_RULES, AnomalyDetector, BehaviorAnomalyDetector, SequenceRule
from .base import CompositeDetector, Detector, DetectorResult, clamp_confidence
from .content import ContentDetector, ContentPolicyDetector
from .dedupe import cap_findings, dedupe_findings, merge_findings, noisy_or, rank_findings, summarise
from .egress import EgressDetector
from .exfiltration import ExfiltrationDetector
from .pipeline import DetectionPipeline, DetectionReport, aggregate_risk, detect
from .prompt_injection import (
    EnsembleInjectionDetector,
    HeuristicInjectionDetector,
    LlmJudgeDetector,
    StructuralInjectionDetector,
    UnicodeAttackDetector,
)
from .registry import DetectorRegistry
from .schema_drift import SchemaDriftDetector
from .secrets import SecretHit, SecretLeakDetector, SecretScanner
from .signatures import Signature, SignatureHit, SignatureSet, default_signature_set
from .supply_chain import SupplyChainDetector
from .text_sources import TextSpan, iter_spans
from .tool_poisoning import ToolPoisoningDetector

__all__ = [
    # contract
    "Detector",
    "CompositeDetector",
    "DetectorResult",
    "clamp_confidence",
    # orchestration
    "DetectorRegistry",
    "DetectionPipeline",
    "DetectionReport",
    "aggregate_risk",
    "detect",
    # detectors
    "EnsembleInjectionDetector",
    "HeuristicInjectionDetector",
    "UnicodeAttackDetector",
    "StructuralInjectionDetector",
    "LlmJudgeDetector",
    "ExfiltrationDetector",
    "SecretLeakDetector",
    "ToolPoisoningDetector",
    "SchemaDriftDetector",
    "AnomalyDetector",
    "BehaviorAnomalyDetector",
    "SequenceRule",
    "SEQUENCE_RULES",
    "EgressDetector",
    "SupplyChainDetector",
    "ContentDetector",
    "ContentPolicyDetector",
    # signatures & helpers
    "Signature",
    "SignatureHit",
    "SignatureSet",
    "SecretScanner",
    "SecretHit",
    "default_signature_set",
    "TextSpan",
    "iter_spans",
    "merge_findings",
    "dedupe_findings",
    "rank_findings",
    "cap_findings",
    "noisy_or",
    "summarise",
]
