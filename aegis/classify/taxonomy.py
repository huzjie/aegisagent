"""Action taxonomy and category inference for AegisAgent.

The classifier needs to know *what a tool call fundamentally does to the world*
before it can reason about risk.  That "what" is captured by
:class:`~aegis.core.types.ActionCategory`.  This module owns the linguistic
heuristics that map a tool name, its declared descriptor and the shape of its
arguments onto a set of categories.

The mapping is deliberately conservative: a ``ToolDescriptor`` that already
declares ``categories`` is treated as authoritative, and the verb heuristics
only *add* candidates when the descriptor is silent.  This keeps categories
stable across re-runs and resistant to an attacker who simply renames a tool.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.types import ActionCategory, ToolCall, ToolDescriptor

__all__ = [
    "ACTION_VERBS",
    "CATEGORY_ALIASES",
    "infer_categories",
    "category_from_text",
]

#: Regex source -> category.  Order matters: earlier entries win on ties because
#: they are checked first.  Patterns are pre-compiled into :data:`_COMPILED_VERBS`.
ACTION_VERBS: Dict[str, ActionCategory] = {
    # Execution / code
    r"\b(exec|execute|run|shell|bash|sh|cmd|command|subprocess|popen|eval|spawn|invoke)\b": ActionCategory.EXECUTE,
    r"\b(os|sys|child_process|childprocess)\b": ActionCategory.EXECUTE,
    # Destructive
    r"\b(rm|remove|delete|del|drop|truncate|purge|wipe|destroy|erase|clear|reset|nuke)\b": ActionCategory.DESTRUCTIVE,
    r"\b(format|mkfs|fdisk|shred|unlink)\b": ActionCategory.DESTRUCTIVE,
    # Writing
    r"\b(write|save|store|upload|put|create|insert|add|append|set|update|patch|edit|modify)\b": ActionCategory.WRITE,
    # Reading
    r"\b(read|get|fetch|retrieve|load|open|show|list|ls|cat|head|tail|select|query|search|find|peek|inspect)\b": ActionCategory.READ,
    # Network
    r"\b(http|https|url|request|fetch|get_url|download|curl|wget|post|websocket|connect|send_request|call_api)\b": ActionCategory.NETWORK,
    # Secrets / credentials
    r"\b(secret|token|credential|password|api_key|apikey|private_key|passphrase|vault|kms|otp|session_key)\b": ActionCategory.SECRET,
    # Identity
    r"\b(login|auth|authenticate|identity|whoami|sudo|su|impersonate|assume_role|sts|iam)\b": ActionCategory.IDENTITY,
    # Deployment
    r"\b(deploy|release|rollout|apply|provision|terraform|helm|kubectl|cdk|cloudformation|publish)\b": ActionCategory.DEPLOY,
    # Communication
    r"\b(send|email|mail|smtp|notify|slack|message|chat|webhook|sms|push|post_message)\b": ActionCategory.COMMUNICATION,
    # Payment
    r"\b(pay|payment|charge|billing|invoice|refund|transaction|stripe|checkout|purchase|order)\b": ActionCategory.PAYMENT,
    # Data export
    r"\b(export|dump|backup|extract|scrape|csv|download_all|bulk|leak)\b": ActionCategory.DATA_EXPORT,
    # Configuration
    r"\b(config|configure|setting|env|environment|variable|flag|toggle|feature_flag|permission|policy|role|acl)\b": ActionCategory.CONFIG,
}

#: Friendly aliases accepted for the ``category`` field in rule YAMLs.
CATEGORY_ALIASES: Dict[str, ActionCategory] = {
    "read": ActionCategory.READ,
    "write": ActionCategory.WRITE,
    "execute": ActionCategory.EXECUTE,
    "exec": ActionCategory.EXECUTE,
    "network": ActionCategory.NETWORK,
    "net": ActionCategory.NETWORK,
    "secret": ActionCategory.SECRET,
    "secrets": ActionCategory.SECRET,
    "identity": ActionCategory.IDENTITY,
    "auth": ActionCategory.IDENTITY,
    "deploy": ActionCategory.DEPLOY,
    "destructive": ActionCategory.DESTRUCTIVE,
    "destroy": ActionCategory.DESTRUCTIVE,
    "communication": ActionCategory.COMMUNICATION,
    "comm": ActionCategory.COMMUNICATION,
    "payment": ActionCategory.PAYMENT,
    "pay": ActionCategory.PAYMENT,
    "data_export": ActionCategory.DATA_EXPORT,
    "export": ActionCategory.DATA_EXPORT,
    "config": ActionCategory.CONFIG,
    "configuration": ActionCategory.CONFIG,
    "unknown": ActionCategory.UNKNOWN,
}


#: Pre-compiled (pattern, category) pairs, derived from :data:`ACTION_VERBS`.
_COMPILED_VERBS: List[Tuple[re.Pattern[str], ActionCategory]] = [
    (re.compile(src, re.IGNORECASE), category) for src, category in ACTION_VERBS.items()
]


def _as_category(value: object) -> Optional[ActionCategory]:
    """Resolve a string or enum into an :class:`ActionCategory` (or ``None``)."""
    if isinstance(value, ActionCategory):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    return CATEGORY_ALIASES.get(text)


def category_from_text(
    text: str,
    *,
    verbs: Optional[Sequence[Tuple[re.Pattern[str], ActionCategory]]] = None,
) -> List[ActionCategory]:
    """Return categories implied by free text (tool name / command / value).

    Args:
        text: Text to inspect (a tool name, CLI command, argument value ...).
        verbs: Override the verb table; defaults to :data:`_COMPILED_VERBS`.

    Returns:
        Categories whose verb pattern matched, in declaration order.
    """
    if not text:
        return []
    pairs = list(verbs) if verbs is not None else _COMPILED_VERBS
    found: List[ActionCategory] = []
    for pattern, category in pairs:
        if pattern.search(text):
            if category not in found:
                found.append(category)
    return found


def infer_categories(
    call: ToolCall,
    descriptor: Optional[ToolDescriptor] = None,
    *,
    include_argument_values: bool = True,
) -> List[ActionCategory]:
    """Infer the action categories of a tool call.

    Resolution order (most to least authoritative):

    1. Categories declared on the :class:`ToolDescriptor`.
    2. Verb heuristics over the qualified tool name (``server::name``).
    3. Verb heuristics over the argument *keys* (``command``, ``query`` ...).
    4. Verb heuristics over short argument *values* when enabled.

    Args:
        call: The tool call under judgement.
        descriptor: Declared capability surface, if known.
        include_argument_values: Scan string argument values (bounded to 256
            chars each) for verbs - useful for ``exec``-style tools whose real
            action lives in the command string.

    Returns:
        A de-duplicated, order-preserving list of categories.  Never empty:
        ``UNKNOWN`` is the fallback so downstream scoring always has a band.
    """
    categories: List[ActionCategory] = []

    if descriptor is not None:
        for declared in descriptor.categories or []:
            category = _as_category(declared)
            if category and category not in categories:
                categories.append(category)

    # Tool name carries strong intent.
    name_blob = " ".join(part for part in (call.qualified_name, call.tool, call.server) if part)
    for category in category_from_text(name_blob):
        if category not in categories:
            categories.append(category)

    # Argument keys are a reliable signal of intent.
    arguments = call.arguments or {}
    for key in arguments:
        for category in category_from_text(str(key)):
            if category not in categories:
                categories.append(category)

    # Argument values (bounded) - only meaningful for command-like blobs.
    if include_argument_values:
        for value in arguments.values():
            if not isinstance(value, str):
                continue
            blob = value[:256]
            for category in category_from_text(blob):
                if category not in categories:
                    categories.append(category)

    if not categories:
        categories.append(ActionCategory.UNKNOWN)
    return categories


def explain_categories(categories: Iterable[ActionCategory]) -> str:
    """Render a category list as a stable comma-separated string for evidence."""
    return ",".join(c.value for c in categories)
