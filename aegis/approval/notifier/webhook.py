"""Generic webhook notifier.

Posts a JSON payload to an arbitrary HTTPS endpoint.  This is the universal
outlet for SIEMs, on-call tools and internal dashboards that speak "POST JSON".

Delivery is best-effort: a network failure raises :class:`NotifierError`, which
the workflow treats as non-fatal because a notification channel going dark must
never block (or forge) an approval decision.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Optional

from ...core.errors import IntegrationError
from ...core.logging import get_logger
from ..models import ApprovalTicket
from .base import Notifier, NotifierContext, NotifierError

__all__ = ["WebhookNotifier"]

_LOG = get_logger("aegis.approval.notifier.webhook")

#: Outbound request timeout in seconds.
_HTTP_TIMEOUT_S = 10.0


class WebhookNotifier(Notifier):
    """Delivers approval events as JSON over HTTP POST."""

    name = "webhook"

    def __init__(self, url: str, *, timeout_s: float = _HTTP_TIMEOUT_S) -> None:
        """Create the notifier.

        Args:
            url: Fully-qualified endpoint that accepts JSON POSTs.
            timeout_s: Per-request timeout.

        Raises:
            NotifierError: ``url`` is empty.
        """
        if not url:
            raise NotifierError("webhook url is required", channel=self.name)
        self._url = url
        self._timeout = float(timeout_s)

    def send(self, ticket: ApprovalTicket, event: str, *, context: Optional[NotifierContext] = None) -> None:
        """POST the notification payload.

        Args:
            ticket: The ticket whose state changed.
            event: The lifecycle event name.
            context: Optional shared configuration.

        Raises:
            NotifierError: The request failed or returned a non-2xx status.
        """
        payload = self.to_payload(ticket, event, context=context)
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
                    raise NotifierError(
                        f"webhook returned HTTP {response.status}",
                        channel=self.name,
                    )
        except NotifierError:
            raise
        except IntegrationError as exc:  # surfaced from lower layers
            raise NotifierError(str(exc), channel=self.name, cause=exc)
        except Exception as exc:  # network / encoding failures
            raise NotifierError(f"webhook delivery failed: {exc}", channel=self.name, cause=exc)
