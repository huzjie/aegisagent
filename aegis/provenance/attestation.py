"""Attestation tokens: the cryptographic receipt for a model-authorised tool call.

An *attestation* is a compact, detached-signature token issued by the gateway at
the moment a model completion is recorded.  It binds five things together:

``session -> completion -> tool -> arguments -> single-use nonce``

Without such a binding an event loop cannot tell the difference between a tool
call the model actually emitted and one an attacker injected into the last
message of an API request.  That is precisely the root cause of the CoreBreak
family of vulnerabilities:

* ``CVE-2026-18830`` (AWS Bedrock AgentCore) - ``tool_use`` blocks appended to a
  request were dispatched without the model ever running.
* ``CVE-2026-18236`` (Google ADK for Python) - human-approval confirmation
  events were trusted without checking that the referenced tool belonged to the
  agent or that its arguments matched the recorded ones.
* ``CVE-2026-64650`` / ``CVE-2026-64651`` (Vercel ``@ai-sdk/harness-codex``).

Wire format (deliberately JWT-shaped but *not* a JWT - the payload is an Aegis
subject, and the ``typ`` header distinguishes it)::

    b64u(canonical_json(header)) "." b64u(canonical_json(subject)) "." signature

The signature covers the string ``"<header_b64>.<subject_b64>"`` so neither part
can be swapped independently.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..core.crypto import (
    Signer,
    b64u_decode,
    b64u_encode,
    canonical_json,
    random_nonce,
    sha256_hex,
)
from ..core.errors import ValidationError
from ..core.types import ModelCompletion, utc_now

__all__ = [
    "ATTESTATION_VERSION",
    "ATTESTATION_TYPE",
    "DELEGATION_TYPE",
    "Attestation",
    "attestation_subject",
    "encode_attestation",
    "decode_attestation",
    "hash_arguments",
    "args_hash_of",
    "normalize_tool_call",
    "iter_tool_calls",
    "encode_envelope",
    "decode_envelope",
]


ATTESTATION_VERSION = "1"
ATTESTATION_TYPE = "AEGIS-ATT"
DELEGATION_TYPE = "AEGIS-DEL"

DEFAULT_TTL_S = 300.0


# --------------------------------------------------------------------------- #
# Argument canonicalisation
# --------------------------------------------------------------------------- #
def hash_arguments(arguments: Any) -> str:
    """Return the stable SHA-256 hex digest of a tool-argument mapping.

    ``None`` is normalised to ``{}`` and JSON strings are decoded first so that
    a provider which serialises arguments (OpenAI style) and one which passes a
    native mapping (Anthropic style) produce an identical hash.
    """
    return sha256_hex(canonical_json(_normalise_arguments(arguments)))


#: Contract-named alias for :func:`hash_arguments`.
args_hash_of = hash_arguments


def _normalise_arguments(arguments: Any) -> Dict[str, Any]:
    """Coerce whatever the provider gave us into a plain dict."""
    if arguments is None:
        return {}
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        text = arguments.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return {"__raw__": arguments}
        return parsed if isinstance(parsed, dict) else {"__value__": parsed}
    return {"__value__": arguments}


def normalize_tool_call(raw: Any) -> Tuple[str, Dict[str, Any]]:
    """Extract ``(tool_name, arguments)`` from any provider tool-call shape.

    Understood shapes:

    * ``{"function": {"name": ..., "arguments": "{...}"}}`` - OpenAI
    * ``{"name": ..., "input": {...}}`` - Anthropic ``tool_use`` block
    * ``{"tool": ..., "arguments": {...}}`` - Aegis internal
    * ``ToolCall``-like objects exposing ``.tool`` / ``.arguments``
    """
    if raw is None:
        return "", {}
    if not isinstance(raw, dict):
        name = getattr(raw, "tool", None) or getattr(raw, "name", "") or ""
        return str(name), _normalise_arguments(getattr(raw, "arguments", None))

    function = raw.get("function")
    if isinstance(function, dict):
        name = function.get("name") or raw.get("name") or ""
        args = function.get("arguments", function.get("input"))
        return str(name), _normalise_arguments(args)

    name = raw.get("name") or raw.get("tool") or raw.get("tool_name") or ""
    for key in ("arguments", "input", "args", "parameters", "params"):
        if key in raw:
            return str(name), _normalise_arguments(raw[key])
    return str(name), {}


def iter_tool_calls(completion: ModelCompletion) -> List[Tuple[str, Dict[str, Any]]]:
    """Normalise every tool call recorded on a completion."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    for raw in completion.tool_calls or []:
        name, args = normalize_tool_call(raw)
        out.append((name, args))
    return out


# --------------------------------------------------------------------------- #
# Attestation
# --------------------------------------------------------------------------- #
@dataclass
class Attestation:
    """A signed statement that *this* model turn authorised *this* tool call."""

    version: str = ATTESTATION_VERSION
    issuer: str = "aegis-gateway"
    session_id: str = ""
    completion_id: str = ""
    tool: str = ""
    args_hash: str = ""
    nonce: str = field(default_factory=random_nonce)
    issued_at: float = field(default_factory=utc_now)
    expires_at: float = 0.0
    key_id: str = "default"
    agent_id: str = ""
    turn: int = 0

    def __post_init__(self) -> None:
        if self.expires_at <= 0:
            self.expires_at = self.issued_at + DEFAULT_TTL_S

    # -- lifecycle ---------------------------------------------------------- #
    @property
    def ttl_s(self) -> float:
        """Remaining validity window at issue time, in seconds."""
        return max(0.0, self.expires_at - self.issued_at)

    def age_s(self, now: Optional[float] = None) -> float:
        """Seconds elapsed since the attestation was issued."""
        return (now if now is not None else utc_now()) - self.issued_at

    def is_expired(self, now: Optional[float] = None, clock_skew_s: float = 0.0) -> bool:
        """True when the token is past ``expires_at`` beyond the skew tolerance."""
        return (now if now is not None else utc_now()) > self.expires_at + max(0.0, clock_skew_s)

    def matches_arguments(self, arguments: Any) -> bool:
        """True when ``arguments`` hash to the value bound at issue time."""
        return bool(self.args_hash) and self.args_hash == hash_arguments(arguments)

    # -- serialisation ------------------------------------------------------ #
    def to_subject(self) -> Dict[str, Any]:
        """The canonical dict that is actually signed."""
        return attestation_subject(self)

    @classmethod
    def from_subject(cls, subject: Dict[str, Any]) -> "Attestation":
        """Rebuild an attestation from a decoded token payload."""
        if not isinstance(subject, dict):
            raise ValidationError("attestation subject must be a mapping")
        try:
            return cls(
                version=str(subject.get("v", ATTESTATION_VERSION)),
                issuer=str(subject.get("iss", "")),
                session_id=str(subject.get("sid", "")),
                completion_id=str(subject.get("cid", "")),
                tool=str(subject.get("tool", "")),
                args_hash=str(subject.get("ah", "")),
                nonce=str(subject.get("nonce", "")),
                issued_at=float(subject.get("iat", 0.0)),
                expires_at=float(subject.get("exp", 0.0)),
                key_id=str(subject.get("kid", "default")),
                agent_id=str(subject.get("aid", "")),
                turn=int(subject.get("turn", 0) or 0),
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"malformed attestation subject: {exc}", cause=exc) from exc

    def summary(self) -> str:
        """One-line human readable description used in logs and audit trails."""
        return (
            f"att(iss={self.issuer} session={self.session_id} completion={self.completion_id} "
            f"tool={self.tool} ah={self.args_hash[:12]} nonce={self.nonce[:16]})"
        )


def attestation_subject(att: Attestation) -> Dict[str, Any]:
    """Return the canonical, signature-covered subject of an attestation.

    Short keys keep tokens compact; every security-relevant field is included so
    that flipping any one of them invalidates the signature.
    """
    return {
        "v": att.version,
        "iss": att.issuer,
        "sid": att.session_id,
        "cid": att.completion_id,
        "aid": att.agent_id,
        "turn": int(att.turn),
        "tool": att.tool,
        "ah": att.args_hash,
        "nonce": att.nonce,
        "iat": round(float(att.issued_at), 6),
        "exp": round(float(att.expires_at), 6),
        "kid": att.key_id,
    }


# --------------------------------------------------------------------------- #
# Generic signed envelope (shared by attestations and delegation links)
# --------------------------------------------------------------------------- #
def encode_envelope(payload: Dict[str, Any], signer: Signer, *, typ: str, key_id: str = "") -> str:
    """Encode ``payload`` as a compact three-segment signed token."""
    header = {
        "alg": signer.algorithm,
        "kid": key_id or signer.key_id,
        "typ": typ,
        "v": ATTESTATION_VERSION,
    }
    header_b64 = b64u_encode(canonical_json(header).encode("utf-8"))
    payload_b64 = b64u_encode(canonical_json(payload).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"
    signature = signer.sign(signing_input)
    return f"{signing_input}.{signature}"


def decode_envelope(token: str) -> Tuple[Dict[str, Any], str]:
    """Decode a signed token without verifying it.

    Returns ``({"header":..., "payload":..., "signing_input":...}, signature)``.
    Raises :class:`ValidationError` when the token is structurally broken - the
    caller is expected to translate that into ``ProvenanceStatus.FORGED``.
    """
    if not token or not isinstance(token, str):
        raise ValidationError("empty attestation token")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValidationError(f"attestation token must have 3 segments, got {len(parts)}")
    header_b64, payload_b64, signature = parts
    try:
        header = json.loads(b64u_decode(header_b64).decode("utf-8"))
        payload = json.loads(b64u_decode(payload_b64).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - any decode failure is a forgery signal
        raise ValidationError(f"attestation token is not decodable: {exc}", cause=exc) from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValidationError("attestation header and payload must both be objects")
    return (
        {
            "header": header,
            "payload": payload,
            "signing_input": f"{header_b64}.{payload_b64}",
        },
        signature,
    )


# --------------------------------------------------------------------------- #
# Attestation-specific codec
# --------------------------------------------------------------------------- #
def encode_attestation(att: Attestation, signer: Signer) -> str:
    """Sign an attestation and return its compact token representation."""
    if not att.args_hash:
        raise ValidationError("attestation requires a precomputed args_hash")
    if not att.nonce:
        raise ValidationError("attestation requires a nonce")
    return encode_envelope(
        attestation_subject(att), signer, typ=ATTESTATION_TYPE, key_id=att.key_id
    )


def decode_attestation(token: str) -> Tuple[Dict[str, Any], str]:
    """Decode an attestation token into ``(claims, signature)``.

    ``claims`` carries ``header``, ``payload`` and the exact ``signing_input``
    string so a verifier can re-check the signature byte-for-byte.
    """
    claims, signature = decode_envelope(token)
    typ = str(claims["header"].get("typ", ""))
    if typ not in (ATTESTATION_TYPE, DELEGATION_TYPE):
        raise ValidationError(f"unexpected token type: {typ!r}")
    return claims, signature
