"""Layered configuration for AegisAgent.

Precedence (lowest to highest):

1. Built-in defaults defined in this module
2. ``aegis.yaml`` / ``aegis.yml`` / ``aegis.json`` discovered from the CWD upwards
3. File pointed at by ``AEGIS_CONFIG``
4. Environment variables prefixed with ``AEGIS_`` (double underscore = nesting)
5. Explicit overrides passed to :func:`load_settings`

YAML support is optional: if PyYAML is not installed a compact built-in parser
handles the subset of YAML used by the shipped configuration files, so the core
runtime stays dependency-free.
"""

from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .errors import ConfigError

__all__ = [
    "Settings",
    "load_settings",
    "get_settings",
    "reset_settings",
    "DEFAULTS",
    "deep_merge",
    "parse_simple_yaml",
]


DEFAULTS: Dict[str, Any] = {
    "app": {
        "name": "AegisAgent",
        "environment": "production",
        "tenant": "default",
        "debug": False,
        "timezone": "UTC",
    },
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        "workers": 1,
        "cors_origins": ["*"],
        "root_path": "",
        "request_timeout_s": 30.0,
        "max_body_bytes": 4 * 1024 * 1024,
    },
    "security": {
        "jwt_secret": "change-me-in-production",
        "jwt_algorithm": "HS256",
        "jwt_ttl_s": 3600,
        "api_keys": [],
        "signing_key": "",
        "signing_algorithm": "hmac-sha256",
        "require_hardware_key_for": ["critical"],
        "password_min_length": 12,
        "bootstrap_admin": {"email": "admin@example.com", "password": ""},
    },
    "provenance": {
        "enabled": True,
        "mode": "enforce",              # off | monitor | enforce
        "require_attestation": True,
        "max_age_s": 300,
        "clock_skew_s": 30,
        "nonce_ttl_s": 900,
        "trusted_issuers": ["aegis-gateway"],
        "unsigned_effect": "require_approval",
        "orphan_effect": "deny",
    },
    "policy": {
        "bundle_dir": "policies",
        "default_effect": "require_approval",
        "fail_closed": True,
        "hot_reload": True,
        "reload_interval_s": 15,
        "enabled_packs": [
            "baseline",
            "corebreak",
            "prompt-injection",
            "secrets",
            "destructive",
            "egress",
            "mcp-hardening",
        ],
    },
    "detection": {
        "enabled": True,
        "parallel": True,
        "timeout_ms": 750,
        "min_confidence": 0.35,
        "detectors": {
            "prompt_injection": True,
            "exfiltration": True,
            "secret_leak": True,
            "tool_poisoning": True,
            "schema_drift": True,
            "anomaly": True,
            "egress": True,
        },
        "llm_judge": {
            "enabled": False,
            "provider": "openai",
            "model": "gpt-4o-mini",
            "timeout_s": 8.0,
        },
    },
    "sandbox": {
        "default_kind": "subprocess",
        "image": "python:3.12-slim",
        "timeout_s": 30.0,
        "memory_mb": 512,
        "cpu_quota": 1.0,
        "network": "deny",
        "egress_allowlist": [],
        "canary_enabled": True,
        "boundary_tests_on_start": False,
    },
    "approval": {
        "enabled": True,
        "default_ttl_s": 900,
        "auto_approve_below": "medium",
        "escalate_after_s": 300,
        "require_step_up_for": ["critical"],
        "channels": ["console"],
        "webhook_url": "",
        "slack_webhook": "",
        "break_glass_enabled": True,
        "break_glass_ttl_s": 1800,
    },
    "audit": {
        "enabled": True,
        "ledger_path": "data/audit/ledger.jsonl",
        "hash_algorithm": "sha256",
        "sign_events": True,
        "export_format": "ocsf",
        "siem": {"enabled": False, "endpoint": "", "token": ""},
        "retention_days": 365,
    },
    "storage": {
        "backend": "sqlite",             # memory | sqlite | postgres
        "dsn": "data/aegis.db",
        "pool_size": 5,
        "echo": False,
    },
    "gateway": {
        "enabled": True,
        "listen_path": "/v1",
        "upstreams": {},
        "inject_attestation": True,
        "strip_unsafe_headers": True,
    },
    "mcp": {
        "enabled": True,
        "servers": [],
        "pin_schemas": True,
        "block_on_drift": True,
        "scan_on_connect": True,
        "shadow_detection": True,
    },
    "observability": {
        "metrics_enabled": True,
        "metrics_path": "/metrics",
        "tracing_enabled": False,
        "otlp_endpoint": "",
        "log_level": "INFO",
        "log_format": "json",
        "log_file": "",
    },
    "redteam": {
        "scenario_dir": "aegis/redteam/scenarios",
        "parallel": 4,
        "fail_threshold": 0.9,
        "include_destructive": False,
    },
    "compliance": {
        "frameworks": ["owasp_llm_top10", "nist_ai_rmf", "eu_ai_act", "iso42001", "mitre_atlas"],
        "report_dir": "data/reports",
    },
}


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base``."""
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


# --------------------------------------------------------------------------- #
# Minimal YAML subset parser (used when PyYAML is unavailable)
# --------------------------------------------------------------------------- #
def _coerce_scalar(raw: str) -> Any:
    text = raw.strip()
    if not text:
        return ""
    if text.startswith(("'", '"')) and text.endswith(("'", '"')) and len(text) >= 2:
        return text[1:-1]
    low = text.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none", "~"):
        return None
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_coerce_scalar(part) for part in _split_flow(inner)]
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        if not inner:
            return {}
        out: Dict[str, Any] = {}
        for part in _split_flow(inner):
            if ":" in part:
                k, v = part.split(":", 1)
                out[k.strip().strip("'\"")] = _coerce_scalar(v)
        return out
    try:
        if text.startswith("0") and text != "0" and not text.startswith("0."):
            raise ValueError
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def _split_flow(text: str) -> List[str]:
    parts, depth, buf, quote = [], 0, [], ""
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Parse the block-mapping / block-sequence subset of YAML.

    A small, dependency-free parser covering the indentation-based subset that
    AegisAgent policy packs rely on: nested mappings, nested block sequences
    (``-`` items, including items that open a mapping or a nested sequence),
    inline flow collections (``[a, b]`` / ``{k: v}``) and ``#`` comments.  It is
    intentionally *not* a full YAML implementation - it targets the structured
    documents this project authors, not arbitrary user uploads.

    Returns a single root mapping.  Block-sequence bodies are lists of either
    scalars or mappings depending on the ``-`` item shape.
    """
    return _parse_block_yaml(text)


def _parse_block_yaml(text: str) -> Dict[str, Any]:
    """Indentation-driven parser.  See :func:`parse_simple_yaml`."""
    root: Dict[str, Any] = {}
    # Pre-tokenise into (indent, raw) pairs, pruning comments/blanks, so we can
    # look ahead at the next *significant* line to decide whether an empty
    # "key:" opens a block sequence or a mapping.
    lines: List[Tuple[int, str]] = []
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        line = raw_line.split(" #")[0].rstrip()
        lines.append((len(line) - len(line.lstrip(" ")), line.strip()))

    def _next_significant(index: int) -> Optional[Tuple[int, str]]:
        return lines[index + 1] if index + 1 < len(lines) else None

    # Stack frames: (indent, container, allow_same_indent_items).  The flag is
    # set for sequences authored in the "key:" / "- item" style where the dashes
    # sit at the *same* column as their parent key, which YAML permits.
    stack: List[Tuple[int, Any, bool]] = [(-1, root, False)]

    for idx, (indent, stripped) in enumerate(lines):
        is_dash = stripped == "-" or stripped.startswith("- ")

        while len(stack) > 1:
            top_indent, top_container, allow_same = stack[-1]
            if indent < top_indent:
                stack.pop()
                continue
            if indent == top_indent:
                if is_dash and isinstance(top_container, list) and allow_same:
                    break
                stack.pop()
                continue
            break
        container = stack[-1][1]

        if is_dash:
            item_text = stripped[1:].strip()
            if not isinstance(container, list):
                continue
            if item_text and not item_text.startswith(("'", '"', "[", "{")):
                # YAML requires a space after the key's colon, which is what
                # keeps qualified tool names such as "fs::rm" a plain scalar.
                item_key, sep, item_value = item_text.partition(": ")
                if not sep and item_text.endswith(":"):
                    item_key, sep, item_value = item_text[:-1], ":", ""
                if sep:
                    obj: Dict[str, Any] = {}
                    container.append(obj)
                    stack.append((indent, obj, False))
                    if item_value.strip():
                        obj[item_key.strip()] = _coerce_scalar(item_value)
                    else:
                        # "- key:" opens a nested block owned by this item.
                        peek = _next_significant(idx)
                        nested_is_seq = bool(
                            peek and peek[1].startswith("-") and peek[0] > indent
                        )
                        nested: Any = [] if nested_is_seq else {}
                        obj[item_key.strip()] = nested
                        stack.append((indent + 1, nested, False))
                    continue
            container.append(_coerce_scalar(item_text))
            continue

        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip().strip("'\"")
        value = value.strip()
        if not isinstance(container, dict):
            continue
        if value == "":
            peek = _next_significant(idx)
            child_is_seq = bool(peek and peek[0] >= indent and peek[1].startswith("-"))
            holder: Any = [] if child_is_seq else {}
            container[key] = holder
            stack.append((indent, holder, child_is_seq and bool(peek) and peek[0] == indent))
        else:
            container[key] = _coerce_scalar(value)
    return root


def _prune_empty_placeholders(node: Any) -> Any:
    """A key that opened a block but only received list items becomes that list."""
    if isinstance(node, dict):
        return {k: _prune_empty_placeholders(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_prune_empty_placeholders(v) for v in node]
    return node


def load_structured_file(path: Path) -> Dict[str, Any]:
    """Load a JSON or YAML document into a dict."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text) or {}
    try:  # pragma: no cover - exercised only when PyYAML present
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ImportError:
        return parse_simple_yaml(text)


# --------------------------------------------------------------------------- #
# Env overlay
# --------------------------------------------------------------------------- #
def _env_overlay(prefix: str = "AEGIS_") -> Dict[str, Any]:
    overlay: Dict[str, Any] = {}
    for key, value in os.environ.items():
        if not key.startswith(prefix) or key == f"{prefix}CONFIG":
            continue
        path = key[len(prefix):].lower().split("__")
        cursor = overlay
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
            if not isinstance(cursor, dict):  # pragma: no cover - defensive
                break
        if isinstance(cursor, dict):
            cursor[path[-1]] = _coerce_scalar(value)
    return overlay


def discover_config_file(start: Optional[Path] = None) -> Optional[Path]:
    env_path = os.environ.get("AEGIS_CONFIG")
    if env_path:
        candidate = Path(env_path).expanduser()
        if candidate.is_file():
            return candidate
        raise ConfigError(f"AEGIS_CONFIG points at a missing file: {candidate}")
    cursor = (start or Path.cwd()).resolve()
    for directory in [cursor, *cursor.parents]:
        for name in ("aegis.yaml", "aegis.yml", "aegis.json", "config/aegis.yaml"):
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


# --------------------------------------------------------------------------- #
# Settings facade
# --------------------------------------------------------------------------- #
@dataclass
class Settings:
    """Read-only view over the merged configuration tree."""

    data: Dict[str, Any] = field(default_factory=lambda: copy.deepcopy(DEFAULTS))
    source: str = "defaults"

    def get(self, path: str, default: Any = None) -> Any:
        cursor: Any = self.data
        for part in path.split("."):
            if isinstance(cursor, dict) and part in cursor:
                cursor = cursor[part]
            else:
                return default
        return cursor

    def section(self, name: str) -> Dict[str, Any]:
        value = self.get(name, {})
        return value if isinstance(value, dict) else {}

    def require(self, path: str) -> Any:
        value = self.get(path, _MISSING)
        if value is _MISSING:
            raise ConfigError(f"missing required configuration key: {path}")
        return value

    def set(self, path: str, value: Any) -> None:
        parts = path.split(".")
        cursor = self.data
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = value

    def as_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self.data)

    def redacted(self) -> Dict[str, Any]:
        """Copy with secret-looking values masked - safe for API responses."""
        secret_markers = ("secret", "password", "token", "key", "dsn", "webhook")

        def _walk(node: Any, path: str = "") -> Any:
            if isinstance(node, dict):
                return {k: _walk(v, f"{path}.{k}".lower()) for k, v in node.items()}
            if isinstance(node, list):
                return [_walk(v, path) for v in node]
            if isinstance(node, str) and node and any(m in path for m in secret_markers):
                return "***redacted***"
            return node

        return _walk(self.as_dict())

    # convenience accessors -------------------------------------------------- #
    @property
    def environment(self) -> str:
        return str(self.get("app.environment", "production"))

    @property
    def debug(self) -> bool:
        return bool(self.get("app.debug", False))

    @property
    def fail_closed(self) -> bool:
        return bool(self.get("policy.fail_closed", True))

    @property
    def server_host(self) -> str:
        return str(self.get("server.host", "0.0.0.0"))

    @property
    def server_port(self) -> int:
        return int(self.get("server.port", 8080))

    @property
    def api_key(self) -> str:
        keys = self.get("security.api_keys", [])
        if isinstance(keys, list) and keys:
            return str(keys[0])
        return ""

    @property
    def provenance_enabled(self) -> bool:
        return bool(self.get("provenance.enabled", True))


_MISSING = object()
_CACHED: Optional[Settings] = None


def load_settings(
    overrides: Optional[Dict[str, Any]] = None,
    *,
    path: Optional[str] = None,
    use_env: bool = True,
) -> Settings:
    """Build a :class:`Settings` object from every configuration layer."""
    merged = copy.deepcopy(DEFAULTS)
    source = "defaults"

    config_path = Path(path).expanduser() if path else discover_config_file()
    if config_path and config_path.is_file():
        try:
            merged = deep_merge(merged, load_structured_file(config_path))
            source = str(config_path)
        except Exception as exc:  # pragma: no cover - surfaced to operator
            raise ConfigError(f"failed to parse config file {config_path}: {exc}", cause=exc)

    if use_env:
        merged = deep_merge(merged, _env_overlay())
    if overrides:
        merged = deep_merge(merged, overrides)

    return Settings(data=merged, source=source)


def get_settings() -> Settings:
    """Process-wide cached settings."""
    global _CACHED
    if _CACHED is None:
        _CACHED = load_settings()
    return _CACHED


def reset_settings(settings: Optional[Settings] = None) -> None:
    """Replace (or clear) the cached settings - primarily for tests."""
    global _CACHED
    _CACHED = settings
