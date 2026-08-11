"""Console notifier — prints approval requests to stdout/stderr.

Useful for local development, single-tenant deployments, and as the always-on
fallback when no remote channel is configured.  Output is fully redacted by
:func:`aegis.approval.notifier.base.render_message`, so a printed approval
request never leaks a secret argument value.
"""

from __future__ import annotations

import sys
from typing import Optional

from ...core.logging import get_logger
from ..models import ApprovalTicket
from .base import Notifier, NotifierContext

__all__ = ["ConsoleNotifier"]

_LOG = get_logger("aegis.approval.notifier.console")


class ConsoleNotifier(Notifier):
    """Writes notification text to a stream (defaults to stderr)."""

    name = "console"

    def __init__(self, *, stream=None, use_color: bool = False) -> None:
        """Create the notifier.

        Args:
            stream: Output stream; defaults to ``sys.stderr`` so that approval
                prompts stay visible even when stdout is captured.
            use_color: When true, a single ANSI bold wrapper is applied to the
                title.  Kept minimal to avoid terminal escape injection.
        """
        self._stream = stream if stream is not None else sys.stderr
        self._use_color = bool(use_color)

    def send(self, ticket: ApprovalTicket, event: str, *, context: Optional[NotifierContext] = None) -> None:
        """Print the rendered notification.

        Args:
            ticket: The ticket whose state changed.
            event: The lifecycle event name.
            context: Optional shared configuration.

        Raises:
            NotifierError: The underlying stream raised (e.g. closed pipe).
        """
        try:
            msg = self.render(ticket, event, context=context)
            title = msg["title"]
            if self._use_color and self._stream.isatty():
                title = f"\033[1m{title}\033[0m"
            self._stream.write(title + "\n")
            self._stream.write(msg["body"] + "\n")
            if msg["url"]:
                self._stream.write(f"Review: {msg['url']}\n")
            self._stream.flush()
        except Exception as exc:  # pragma: no cover - stream failure
            raise NotifierError("console write failed", channel=self.name, cause=exc)
