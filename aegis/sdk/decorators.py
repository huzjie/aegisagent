"""Additional decorators for tool governance.

Provides decorators for enforcing policies, audit logging, and tracing.
"""

from __future__ import annotations

import functools
import time
from typing import Any, Callable

from aegis.core.logging import get_logger

__all__ = ["enforce", "audit", "trace"]

_log = get_logger(__name__)


def enforce(policy: str = "default") -> Callable:
    """Decorator to enforce a specific policy on a tool.

    Args:
        policy: policy name or path.

    Returns:
        Decorator function.

    Example:
        @enforce(policy="strict")
        def sensitive_operation():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            _log.info(
                "enforcing policy",
                fields={"function": func.__name__, "policy": policy},
            )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def audit(enabled: bool = True) -> Callable:
    """Decorator to enable audit logging for a tool.

    Args:
        enabled: whether to enable audit logging.

    Returns:
        Decorator function.

    Example:
        @audit(enabled=True)
        def important_action():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            _log.info(
                "audit: tool called",
                fields={"function": func.__name__, "args": args, "kwargs": kwargs},
            )
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                _log.info(
                    "audit: tool completed",
                    fields={"function": func.__name__, "duration_ms": duration_ms},
                )
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                _log.error(
                    "audit: tool failed",
                    fields={"function": func.__name__, "error": str(e), "duration_ms": duration_ms},
                )
                raise
        return wrapper
    return decorator


def trace(level: str = "info") -> Callable:
    """Decorator to add detailed tracing to a tool.

    Args:
        level: log level for trace messages (debug, info, warning).

    Returns:
        Decorator function.

    Example:
        @trace(level="debug")
        def complex_operation():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            _log.log(
                level,
                "trace: entering",
                fields={"function": func.__name__},
            )
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                _log.log(
                    level,
                    "trace: exiting",
                    fields={"function": func.__name__, "duration_ms": duration_ms},
                )
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                _log.log(
                    level,
                    "trace: exception",
                    fields={"function": func.__name__, "error": str(e), "duration_ms": duration_ms},
                )
                raise
        return wrapper
    return decorator
