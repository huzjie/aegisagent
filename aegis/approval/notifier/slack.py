"""Slack notifier (incoming webhook).

Slack approval messages intentionally contain **no** interactive "Approve"
button payload that the platform would trust: a forged webhook could otherwise
trivially flip a decision.  The message carries a deep link to the AegisAgent
console where the authenticated approver performs the action.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Optional

from ...core.errors import IntegrationError
from ...core.logging import get_logger
from ..models import ApprovalTicket
from .base import Notifier, NotifierContext, NotifierError

__all__ = ["SlackNotifier"]

_LOG = get_logger("aegis.approval.notifier.slack")

_HTTP_TIMEOUT_S = 10.0


class SlackNotifier(Notifier):
    """Posts a Slack message via an incoming webhook URL."""

    name = "slack"

    def __init__(self, webhook_url: str, *, timeout_s: float = _HTTP_TIMEOUT_S, channel: str = "") -> None:
        """Create the notifier.

        Args:
            webhook_url: Slack incoming-webhook URL.
            timeout_s: Per-request timeout.
            channel: Optional ``#channel`` or ``@user`` override.

        Raises:
            NotifierError: ``webhook_url`` is empty.
        """
        if not webhook_url:
            raise NotifierError("slack webhook url is required", channel=self.name)
        self._url = webhook_url
        self._timeout = float(timeout_s)
        self._channel = channel

    def send(self, ticket: ApprovalTicket, event: str, *, context: Optional[NotifierContext] = None) -> None:
        """Post a Slack-formatted message.

        Args:
            ticket: The ticket whose state changed.
            event: The lifecycle event name.
            context: Optional shared configuration.

        Raises:
            NotifierError: Delivery failed.
        """
        msg = self.render(ticket, event, context=context)
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{msg['title']}*"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": msg["body"]}},
        ]
        if msg["url"]:
            blocks.append({"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "Review in console"}, "url": msg["url"]},
            ]})
        payload = {"text": msg["title"], "blocks": blocks}
        if self._channel:
            payload["channel"] = self._channel
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "AegisAgent/approval"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                if response.status >= 400:
                    raise NotifierError(f"slack returned HTTP {response.status}", channel=self.name)
        except NotifierError:
            raise
        except IntegrationError as exc:
            raise NotifierError(str(exc), channel=self.name, cause=exc)
        except Exception as exc:
            raise NotifierError(f"slack delivery failed: {exc}", channel=self.name, cause=exc)
