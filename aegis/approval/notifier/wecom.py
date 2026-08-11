"""WeCom (WeChat Work) notifier via group-robot webhook.

Sends a markdown message through the enterprise WeChat "群机器人" webhook.  As
with every other channel the message is non-authoritative: it links to the
console rather than carrying an approvable token.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Optional

from ...core.errors import IntegrationError
from ...core.logging import get_logger
from ..models import ApprovalTicket
from .base import Notifier, NotifierContext, NotifierError

__all__ = ["WeComNotifier"]

_LOG = get_logger("aegis.approval.notifier.wecom")

_HTTP_TIMEOUT_S = 10.0


class WeComNotifier(Notifier):
    """Posts markdown messages to a WeCom group-robot webhook."""

    name = "wecom"

    def __init__(self, webhook_url: str, *, timeout_s: float = _HTTP_TIMEOUT_S, mention_ids: Optional[list] = None) -> None:
        """Create the notifier.

        Args:
            webhook_url: WeCom group-robot webhook key URL.
            timeout_s: Per-request timeout.
            mention_ids: WeCom userids to ``@`` in the message.

        Raises:
            NotifierError: ``webhook_url`` is empty.
        """
        if not webhook_url:
            raise NotifierError("wecom webhook url is required", channel=self.name)
        self._url = webhook_url
        self._timeout = float(timeout_s)
        self._mentions = list(mention_ids or [])

    def send(self, ticket: ApprovalTicket, event: str, *, context: Optional[NotifierContext] = None) -> None:
        """Post the markdown notification.

        Args:
            ticket: The ticket whose state changed.
            event: The lifecycle event name.
            context: Optional shared configuration.

        Raises:
            NotifierError: Delivery failed or WeCom rejected the payload.
        """
        msg = self.render(ticket, event, context=context)
        mention_block = ""
        if self._mentions:
            mention_block = "\n" + " ".join(f"<@{uid}>" for uid in self._mentions)
        markdown = (
            f"# {msg['title']}\n"
            f">{msg['body'].replace(chr(10), '  \n>')}  \n"
            f"[Review in console]({msg['url']}){mention_block}"
        )
        payload = {"msgtype": "markdown", "markdown": {"content": markdown}}
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "AegisAgent/approval"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                body = response.read().decode("utf-8", "replace")
                if response.status >= 400:
                    raise NotifierError(f"wecom returned HTTP {response.status}", channel=self.name)
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict) and parsed.get("errcode", 0) != 0:
                        raise NotifierError(
                            f"wecom rejected message: {parsed.get('errmsg', 'unknown')}",
                            channel=self.name,
                        )
                except json.JSONDecodeError:
                    pass
        except NotifierError:
            raise
        except IntegrationError as exc:
            raise NotifierError(str(exc), channel=self.name, cause=exc)
        except Exception as exc:
            raise NotifierError(f"wecom delivery failed: {exc}", channel=self.name, cause=exc)
