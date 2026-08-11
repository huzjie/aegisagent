"""Prompt-injection detection family.

Four independent views of the same question - "is someone trying to hijack the
model's instructions?" - plus an ensemble that fuses them:

``HeuristicInjectionDetector``
    Technique-pattern matching (override, role hijack, prompt leak ...) over the
    plaintext *and* over de-obfuscated variants.
``UnicodeAttackDetector``
    Invisible-character smuggling: zero-width channels, Unicode Tag block,
    BIDI overrides, homoglyphs.
``StructuralInjectionDetector``
    Markup-borne injection: HTML comments, hidden elements, markdown images
    whose URL carries the stolen data.
``LlmJudgeDetector``
    Optional model-based adjudication (off by default, with an offline mock).
``EnsembleInjectionDetector``
    Weighted fusion with a corroboration bonus - the registry entry.
"""

from __future__ import annotations

from .ensemble import DEFAULT_WEIGHTS, EnsembleInjectionDetector, EnsembleVote
from .heuristic import HeuristicInjectionDetector
from .llm_judge import (
    CallableJudge,
    JudgeProvider,
    JudgeVerdict,
    LlmJudgeDetector,
    MockJudge,
    build_judge_prompt,
)
from .patterns import TECHNIQUES, TECHNIQUES_BY_NAME, Technique, scan_techniques
from .structural import StructuralInjectionDetector
from .unicode_attack import UnicodeAttackDetector, decode_tag_characters, extract_hidden_text

__all__ = [
    "EnsembleInjectionDetector",
    "EnsembleVote",
    "DEFAULT_WEIGHTS",
    "HeuristicInjectionDetector",
    "UnicodeAttackDetector",
    "StructuralInjectionDetector",
    "LlmJudgeDetector",
    "MockJudge",
    "CallableJudge",
    "JudgeProvider",
    "JudgeVerdict",
    "build_judge_prompt",
    "Technique",
    "TECHNIQUES",
    "TECHNIQUES_BY_NAME",
    "scan_techniques",
    "decode_tag_characters",
    "extract_hidden_text",
]
