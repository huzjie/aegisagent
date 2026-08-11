"""Extraction of analysable text spans from an :class:`EvaluationContext`.

Detectors should never reach into the context by hand: attack surface is spread
across tool arguments, untrusted retrieved content, MCP tool descriptions and
parameter documentation.  Missing one of those is how real-world gateways get
bypassed (a poisoned *parameter description* is invisible to a detector that
only looks at ``call.arguments``).

This module centralises the traversal so every detector observes exactly the
same surface, each span carrying a stable dotted ``location`` used for
deduplication downstream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence

from ..core.types import EvaluationContext
from ..core.utils import truncate

__all__ = [
    "TextSpan",
    "MAX_SPAN_CHARS",
    "iter_spans",
    "iter_argument_spans",
    "iter_untrusted_spans",
    "iter_descriptor_spans",
    "collect_text",
    "flatten_value",
    "argument_string",
]

#: Hard cap on how much of a single value a detector will scan.  Prompt
#: injection payloads are small; a 4 MB CSV in an argument would otherwise turn
#: regex scanning into an accidental denial of service.
MAX_SPAN_CHARS = 65_536

#: Argument keys whose *content* is user/website supplied and therefore the
#: prime carrier for indirect prompt injection.
UNTRUSTED_ARGUMENT_HINTS = (
    "content", "text", "body", "html", "page", "document", "message", "email",
    "prompt", "input", "data", "payload", "snippet", "context", "description",
    "comment", "note", "summary", "transcript", "result", "output", "chunk",
)

#: Keys of ``ctx.extra`` conventionally used to carry retrieved third-party
#: content (web page, email body, RAG chunk, MCP tool result).
UNTRUSTED_EXTRA_KEYS = (
    "untrusted_content", "retrieved_content", "tool_result", "web_content",
    "email_body", "rag_context", "observation", "document",
)


@dataclass
class TextSpan:
    """A single scannable piece of text plus where it came from.

    Attributes:
        text: The raw (un-normalised) text to analyse.
        location: Dotted provenance path, e.g. ``arguments.body`` or
            ``descriptor.parameters.path.description``.
        trust: One of ``untrusted`` / ``semi_trusted`` / ``declared``.
            ``untrusted`` spans carry third-party content and warrant higher
            confidence when injection patterns are found; ``declared`` spans
            come from the tool vendor (descriptions) and matter for tool
            poisoning rather than prompt injection.
        weight: Multiplier applied to detector confidence for this span.
    """

    text: str
    location: str
    trust: str = "untrusted"
    weight: float = 1.0
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.text) > MAX_SPAN_CHARS:
            self.text = self.text[:MAX_SPAN_CHARS]
            self.meta["truncated"] = True

    @property
    def preview(self) -> str:
        """Short single-line rendering used in :class:`Finding` evidence."""
        return truncate(" ".join(self.text.split()), 200)

    def __len__(self) -> int:
        return len(self.text)


def flatten_value(value: Any, prefix: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    """Yield ``(path, text)`` pairs for every string reachable inside ``value``.

    Nested dicts and lists are walked (bounded to depth 6 / 200 items) because
    injection payloads are routinely hidden one level down, e.g.
    ``{"messages": [{"role": "user", "content": "<payload>"}]}``.
    """
    if depth > 6:
        return
    if isinstance(value, str):
        if value:
            yield prefix or "value", value
    elif isinstance(value, dict):
        for key, sub in list(value.items())[:200]:
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from flatten_value(sub, child, depth + 1)
    elif isinstance(value, (list, tuple)):
        for index, sub in enumerate(list(value)[:200]):
            child = f"{prefix}[{index}]" if prefix else f"[{index}]"
            yield from flatten_value(sub, child, depth + 1)
    elif isinstance(value, (int, float, bool)):
        yield prefix or "value", str(value)


def _trust_for_key(key: str) -> tuple[str, float]:
    """Classify an argument key into a trust bucket and confidence weight."""
    low = key.lower()
    if any(hint in low for hint in UNTRUSTED_ARGUMENT_HINTS):
        return "untrusted", 1.0
    return "semi_trusted", 0.9


def iter_argument_spans(ctx: EvaluationContext) -> Iterator[TextSpan]:
    """Yield spans for every string found inside ``ctx.call.arguments``."""
    for path, text in flatten_value(ctx.call.arguments or {}):
        root = path.split(".")[0].split("[")[0]
        trust, weight = _trust_for_key(root)
        yield TextSpan(text=text, location=f"arguments.{path}", trust=trust, weight=weight)


def iter_untrusted_spans(ctx: EvaluationContext) -> Iterator[TextSpan]:
    """Yield spans for third-party content stashed in ``ctx.extra``."""
    extra = ctx.extra or {}
    for key in UNTRUSTED_EXTRA_KEYS:
        if key not in extra:
            continue
        for path, text in flatten_value(extra[key]):
            location = f"extra.{key}" if path in ("", "value") else f"extra.{key}.{path}"
            yield TextSpan(text=text, location=location, trust="untrusted", weight=1.0)


def iter_descriptor_spans(ctx: EvaluationContext) -> Iterator[TextSpan]:
    """Yield spans for the declared tool surface (MCP tool poisoning surface)."""
    descriptor = ctx.descriptor
    if descriptor is None:
        return
    if descriptor.description:
        yield TextSpan(
            text=descriptor.description,
            location="descriptor.description",
            trust="declared",
            weight=1.0,
        )
    for parameter in descriptor.parameters or []:
        if parameter.description:
            yield TextSpan(
                text=parameter.description,
                location=f"descriptor.parameters.{parameter.name}.description",
                trust="declared",
                weight=0.95,
            )
    for key, value in (descriptor.metadata or {}).items():
        if isinstance(value, str) and value:
            yield TextSpan(
                text=value,
                location=f"descriptor.metadata.{key}",
                trust="declared",
                weight=0.8,
            )


def iter_spans(
    ctx: EvaluationContext,
    *,
    include_arguments: bool = True,
    include_untrusted: bool = True,
    include_descriptor: bool = True,
    min_length: int = 1,
) -> List[TextSpan]:
    """Collect every span a detector should look at, in a stable order.

    Args:
        ctx: Evaluation context under judgement.
        include_arguments: Scan ``call.arguments``.
        include_untrusted: Scan retrieved third-party content in ``extra``.
        include_descriptor: Scan the declared tool/parameter descriptions.
        min_length: Skip spans shorter than this many characters.

    Returns:
        Deduplicated list of spans (same text at the same location appears once).
    """
    seen: set[tuple[str, str]] = set()
    out: List[TextSpan] = []
    sources: List[Iterable[TextSpan]] = []
    if include_arguments:
        sources.append(iter_argument_spans(ctx))
    if include_untrusted:
        sources.append(iter_untrusted_spans(ctx))
    if include_descriptor:
        sources.append(iter_descriptor_spans(ctx))
    for source in sources:
        for span in source:
            if len(span.text) < min_length:
                continue
            key = (span.location, span.text[:512])
            if key in seen:
                continue
            seen.add(key)
            out.append(span)
    return out


def collect_text(ctx: EvaluationContext, **kwargs: Any) -> str:
    """Concatenate all spans into one blob - for detectors that scan globally."""
    return "\n".join(span.text for span in iter_spans(ctx, **kwargs))


def argument_string(arguments: Optional[Dict[str, Any]], limit: int = MAX_SPAN_CHARS) -> str:
    """Render arguments as compact JSON for pattern rules that need structure."""
    if not arguments:
        return "{}"
    try:
        rendered = json.dumps(arguments, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        rendered = str(arguments)
    return rendered[:limit]


def string_values(arguments: Optional[Dict[str, Any]]) -> Sequence[str]:
    """All string leaves of an argument mapping, order preserved."""
    return [text for _, text in flatten_value(arguments or {})]
