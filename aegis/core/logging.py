"""Structured logging with automatic secret redaction.

The platform handles prompts, tool arguments and credentials, so every log
record passes through a redaction filter before it is emitted.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from contextvars import ContextVar
from typing import Any, Dict, Optional

__all__ = [
    "configure_logging",
    "get_logger",
    "bind_context",
    "clear_context",
    "RedactingFilter",
    "JsonFormatter",
    "redact_text",
    "redact_mapping",
]


_context: ContextVar[Dict[str, Any]] = ContextVar("aegis_log_context", default={})
_configured = threading.Event()

SECRET_PATTERNS = [
    (re.compile(r"(?i)(sk-[a-zA-Z0-9]{16,})"), "sk-***REDACTED***"),
    (re.compile(r"(?i)(gh[pousr]_[A-Za-z0-9]{16,})"), "gh*_***REDACTED***"),
    (re.compile(r"(?i)(AKIA[0-9A-Z]{16})"), "AKIA***REDACTED***"),
    (re.compile(r"(?i)(xox[baprs]-[A-Za-z0-9-]{10,})"), "xox*-***REDACTED***"),
    (re.compile(r"(?i)(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})"), "jwt***REDACTED***"),
    (re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"), "***PRIVATE_KEY_REDACTED***"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token|authorization)\b\s*[:=]\s*['\"]?([^\s'\",;]{6,})"), r"\1=***REDACTED***"),
]

SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "authorization",
    "auth", "credential", "credentials", "private_key", "signing_key", "jwt_secret",
    "session_token", "refresh_token", "access_token", "client_secret", "cookie",
}


def redact_text(text: str) -> str:
    """Mask credential-shaped substrings."""
    if not text:
        return text
    out = text
    for pattern, replacement in SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def redact_mapping(data: Any, depth: int = 0) -> Any:
    """Recursively mask sensitive keys inside dictionaries and lists."""
    if depth > 12:
        return "***depth-limit***"
    if isinstance(data, dict):
        out: Dict[str, Any] = {}
        for key, value in data.items():
            if str(key).lower() in SENSITIVE_KEYS:
                out[key] = "***REDACTED***"
            else:
                out[key] = redact_mapping(value, depth + 1)
        return out
    if isinstance(data, (list, tuple)):
        return [redact_mapping(v, depth + 1) for v in data]
    if isinstance(data, str):
        return redact_text(data)
    return data


class RedactingFilter(logging.Filter):
    """Applies redaction to the formatted message and structured extras."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            if isinstance(record.msg, str):
                record.msg = redact_text(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = redact_mapping(record.args)
                else:
                    record.args = tuple(
                        redact_text(a) if isinstance(a, str) else a for a in record.args
                    )
            extra = getattr(record, "extra_fields", None)
            if isinstance(extra, dict):
                record.extra_fields = redact_mapping(extra)
        except Exception:  # pragma: no cover - logging must never explode
            pass
        return True


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per line, enriched with the ambient context."""

    def __init__(self, service: str = "aegis") -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "service": self.service,
            "message": record.getMessage(),
        }
        ctx = _context.get()
        if ctx:
            payload["context"] = ctx
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict) and extra:
            payload["fields"] = extra
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-friendly coloured output for local development."""

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"

    def __init__(self, color: bool = True) -> None:
        super().__init__("%(message)s")
        self.color = color and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        level = record.levelname.ljust(8)
        if self.color:
            level = f"{self.COLORS.get(record.levelname, '')}{level}{self.RESET}"
        line = f"{ts} {level} {record.name:<28} {record.getMessage()}"
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict) and extra:
            line += "  " + " ".join(f"{k}={v}" for k, v in extra.items())
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def configure_logging(
    level: str = "INFO",
    fmt: str = "json",
    log_file: str = "",
    service: str = "aegis",
) -> None:
    """Install handlers on the root logger. Safe to call multiple times."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    formatter: logging.Formatter = (
        JsonFormatter(service) if fmt == "json" else ConsoleFormatter()
    )

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    stream.addFilter(RedactingFilter())
    root.addHandler(stream)

    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(JsonFormatter(service))
            file_handler.addFilter(RedactingFilter())
            root.addHandler(file_handler)
        except OSError:  # pragma: no cover - degraded but non-fatal
            root.warning("could not open log file %s", log_file)

    for noisy in ("urllib3", "asyncio", "httpx", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured.set()


class _LoggerAdapter(logging.LoggerAdapter):
    """Adapter that folds keyword arguments into ``extra_fields``."""

    def process(self, msg: Any, kwargs: Dict[str, Any]):
        fields = kwargs.pop("fields", None) or {}
        reserved = {"exc_info", "stack_info", "stacklevel", "extra"}
        leftovers = {k: kwargs.pop(k) for k in list(kwargs) if k not in reserved}
        merged = {**(self.extra or {}), **fields, **leftovers}
        if merged:
            kwargs["extra"] = {"extra_fields": merged}
        return msg, kwargs


def get_logger(name: str, **static_fields: Any) -> _LoggerAdapter:
    """Return a namespaced logger that accepts structured keyword fields."""
    if not _configured.is_set():
        configure_logging(
            level=os.environ.get("AEGIS_LOG_LEVEL", "INFO"),
            fmt=os.environ.get("AEGIS_LOG_FORMAT", "console"),
        )
    base = logging.getLogger(name if name.startswith("aegis") else f"aegis.{name}")
    return _LoggerAdapter(base, dict(static_fields))


def bind_context(**fields: Any) -> None:
    """Attach request/session scoped fields to every subsequent log line."""
    current = dict(_context.get())
    current.update({k: v for k, v in fields.items() if v is not None})
    _context.set(current)


def clear_context() -> None:
    _context.set({})


def current_context() -> Dict[str, Any]:
    return dict(_context.get())
