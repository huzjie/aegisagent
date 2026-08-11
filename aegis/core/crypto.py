"""Cryptographic primitives shared by provenance, audit and auth.

Standard library only: HMAC-SHA256 for signing, PBKDF2 for passwords, a
canonical JSON serialiser for stable hashing and a constant-time comparison
helper.  An optional Ed25519 backend is used when ``cryptography`` is present.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional, Tuple

__all__ = [
    "canonical_json",
    "sha256_hex",
    "sha256_bytes",
    "hmac_sign",
    "hmac_verify",
    "b64u_encode",
    "b64u_decode",
    "random_token",
    "random_nonce",
    "hash_password",
    "verify_password",
    "constant_time_equals",
    "fingerprint",
    "chain_hash",
    "Signer",
    "HmacSigner",
    "Ed25519Signer",
    "build_signer",
]


# --------------------------------------------------------------------------- #
# Encoding & hashing
# --------------------------------------------------------------------------- #
def canonical_json(payload: Any) -> str:
    """Deterministic JSON encoding (sorted keys, no whitespace padding)."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256_hex(data: Any) -> str:
    """SHA-256 hex digest of a string, bytes or JSON-serialisable object."""
    if isinstance(data, bytes):
        raw = data
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = canonical_json(data).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(str(a), str(b))


def random_token(nbytes: int = 32) -> str:
    return b64u_encode(secrets.token_bytes(nbytes))


def random_nonce() -> str:
    return f"{int(time.time() * 1000):x}.{secrets.token_hex(12)}"


def fingerprint(payload: Any, length: int = 16) -> str:
    """Short stable identifier for schemas, prompts and tool descriptors."""
    return sha256_hex(payload)[:length]


def chain_hash(prev_hash: str, payload: Any) -> str:
    """Compute the next hash in a tamper-evident append-only chain."""
    return sha256_hex(f"{prev_hash}|{canonical_json(payload)}")


# --------------------------------------------------------------------------- #
# HMAC helpers
# --------------------------------------------------------------------------- #
def hmac_sign(key: str, message: str, algorithm: str = "sha256") -> str:
    digest = hmac.new(
        key.encode("utf-8"), message.encode("utf-8"), getattr(hashlib, algorithm)
    ).digest()
    return b64u_encode(digest)


def hmac_verify(key: str, message: str, signature: str, algorithm: str = "sha256") -> bool:
    expected = hmac_sign(key, message, algorithm)
    return hmac.compare_digest(expected, signature or "")


# --------------------------------------------------------------------------- #
# Password hashing (PBKDF2-HMAC-SHA256)
# --------------------------------------------------------------------------- #
PBKDF2_ITERATIONS = 240_000


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${b64u_encode(salt)}${b64u_encode(derived)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_b64, hash_b64 = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), b64u_decode(salt_b64), int(iterations)
        )
        return hmac.compare_digest(b64u_encode(derived), hash_b64)
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# Signer abstraction
# --------------------------------------------------------------------------- #
class Signer:
    """Interface for detached signatures over canonical payloads."""

    algorithm = "none"

    def sign(self, payload: Any) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def verify(self, payload: Any, signature: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    @property
    def key_id(self) -> str:
        return "unset"


class NullSigner(Signer):
    """No-op signer used when signing is disabled."""

    algorithm = "none"

    def sign(self, payload: Any) -> str:
        return ""

    def verify(self, payload: Any, signature: str) -> bool:
        return True


class HmacSigner(Signer):
    """Symmetric signer - the default, zero-dependency option."""

    algorithm = "hmac-sha256"

    def __init__(self, key: str, key_id: str = "default") -> None:
        if not key:
            key = os.environ.get("AEGIS_SIGNING_KEY", "") or random_token(32)
        self._key = key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: Any) -> str:
        return hmac_sign(self._key, canonical_json(payload))

    def verify(self, payload: Any, signature: str) -> bool:
        return hmac_verify(self._key, canonical_json(payload), signature)


class Ed25519Signer(Signer):
    """Asymmetric signer - enabled when ``cryptography`` is installed."""

    algorithm = "ed25519"

    def __init__(self, private_key_pem: str = "", key_id: str = "default") -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:  # pragma: no cover - optional path
            raise RuntimeError(
                "Ed25519Signer requires the 'cryptography' package "
                "(pip install 'aegisagent[crypto]')"
            ) from exc

        self._serialization = serialization
        if private_key_pem:
            self._private = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"), password=None
            )
        else:
            self._private = ed25519.Ed25519PrivateKey.generate()
        self._public = self._private.public_key()
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_key_pem(self) -> str:
        return self._public.public_bytes(
            encoding=self._serialization.Encoding.PEM,
            format=self._serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def sign(self, payload: Any) -> str:
        return b64u_encode(self._private.sign(canonical_json(payload).encode("utf-8")))

    def verify(self, payload: Any, signature: str) -> bool:
        try:
            self._public.verify(
                b64u_decode(signature), canonical_json(payload).encode("utf-8")
            )
            return True
        except Exception:
            return False


def build_signer(algorithm: str = "hmac-sha256", key: str = "", key_id: str = "default") -> Signer:
    """Factory used by the provenance and audit subsystems."""
    algo = (algorithm or "hmac-sha256").lower()
    if algo in ("none", "off", "disabled"):
        return NullSigner()
    if algo.startswith("ed25519"):
        return Ed25519Signer(key, key_id)
    return HmacSigner(key, key_id)


# --------------------------------------------------------------------------- #
# Compact JWT (HS256) - avoids a PyJWT dependency for the control plane
# --------------------------------------------------------------------------- #
def encode_jwt(claims: Dict[str, Any], secret: str, ttl_s: int = 3600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    body = {"iat": now, "exp": now + ttl_s, **claims}
    segments = [
        b64u_encode(canonical_json(header).encode("utf-8")),
        b64u_encode(canonical_json(body).encode("utf-8")),
    ]
    signing_input = ".".join(segments)
    signature = hmac.new(
        secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).digest()
    segments.append(b64u_encode(signature))
    return ".".join(segments)


def decode_jwt(token: str, secret: str, *, verify_exp: bool = True) -> Dict[str, Any]:
    try:
        header_b64, body_b64, sig_b64 = token.split(".")
    except ValueError as exc:
        raise ValueError("malformed token") from exc
    signing_input = f"{header_b64}.{body_b64}"
    expected = hmac.new(
        secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(b64u_encode(expected), sig_b64):
        raise ValueError("signature mismatch")
    claims = json.loads(b64u_decode(body_b64).decode("utf-8"))
    if verify_exp and int(claims.get("exp", 0)) < int(time.time()):
        raise ValueError("token expired")
    return claims


def derive_key(master: str, purpose: str, length: int = 32) -> str:
    """HKDF-lite key separation so one master secret serves many subsystems."""
    prk = hmac.new(b"aegis-hkdf", master.encode("utf-8"), hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + purpose.encode("utf-8") + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return b64u_encode(okm[:length])


def totp_now(secret: str, *, step: int = 30, digits: int = 6, at: Optional[int] = None) -> str:
    """RFC-6238 TOTP used for approval step-up authentication."""
    counter = int((at if at is not None else time.time()) // step)
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = int.from_bytes(digest[offset: offset + 4], "big") & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_verify(secret: str, code: str, *, window: int = 1, step: int = 30) -> bool:
    now = int(time.time())
    for drift in range(-window, window + 1):
        if constant_time_equals(totp_now(secret, step=step, at=now + drift * step), code):
            return True
    return False


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def split_key_material(raw: str) -> Tuple[str, str]:
    """Split ``kid:key`` material, tolerating a bare key."""
    if ":" in raw:
        kid, _, key = raw.partition(":")
        return kid.strip(), key.strip()
    return "default", raw.strip()
