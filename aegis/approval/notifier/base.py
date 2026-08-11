"""Base interface and shared helpers for approval notifiers.

A notifier's only job is to *tell a human that a decision is needed*.  It never
carries authority: the actual vote must arrive through an authenticated call
into :class:`aegis.approval.workflow.ApprovalWorkflow`.  Treating
notifications as non-authoritative is what neutralises the "reply YES to the
Slack message" class of approval forgery seen in 2026.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from ...core.types import ApprovalState
from ..models import ApprovalTicket

__all__ = ["Notifier", "NotifierContext", "render_message", "NotifierError"]


class NotifierError(Exception):
    """Raised when a notifier cannot deliver its message."""

    def __init__(self, message: str = "", *, channel: str = "", cause: Optional[BaseException] = None) -> None:
        super().__init__(message)
        self.channel = channel
        self.cause = cause


@dataclass
class NotifierContext:
    """Static configuration shared by all notifier instances."""

    tenant_id: str = "default"
    environment: str = "production"
    approval_url_template: str = ""
    sender_name: str = "AegisAgent"
    webhook_url: str = ""
    slack_webhook: str = ""
    email_smtp_host: str = ""
    email_smtp_port: int = 25
    email_from: str = ""
    email_to: list = None  # type: ignore[assignment]
    wecom_webhook: str = ""

    def url_for(self, ticket_id: str) -> str:
        """Return a clickable approval console URL for ``ticket_id``."""
        if not self.approval_url_template:
            return f"approval://{self.tenant_id}/{ticket_id}"
        return self.approval_url_template.format(tenant_id=self.tenant_id, ticket_id=ticket_id)


def render_message(ticket: ApprovalTicket, event: str, *, context: Optional[NotifierContext] = None) -> Dict[str, str]:
    """Build the human-facing fields for a notification.

    Args:
        ticket: The ticket whose state changed.
        event: The lifecycle event (``submitted`` / ``vote`` / ``approved`` …).
        context: Optional rendering context for URLs and branding.

    Returns:
        A mapping with ``title``, ``body`` and ``url`` keys, already
        redacted so secrets never reach a chat channel.
    """
    ctx = context or NotifierContext()
    state = ticket.state.value
    verb = {
        "submitted": "needs your decision",
        "vote": "has new activity",
        "approved": "was approved",
        "auto_approved": "was auto-approved",
        "rejected": "was rejected",
        "expired": "expired (denied)",
        "cancelled": "was cancelled",
        "escalated": "was escalated",
    }.get(event, f"state: {state}")
    title = f"[AegisAgent] {ticket.request.tool} {verb}"
    quorum = ticket.quorum
    lines = [
        f"Ticket: {ticket.id}",
        f"Tool: {ticket.request.tool}",
        f"Risk: {ticket.risk.value} | Quorum: {quorum.describe()}",
        f"Requested by: {ticket.requester_id}",
        f"Blast radius: {ticket.request.blast_radius}",
        f"Justification: {ticket.request.justification}",
        f"State: {state}",
        f"Action: {verb}",
    ]
    if ticket.request.expires_at:
        from ...core.utils import utc_iso

        lines.append(f"Expires: {utc_iso(ticket.request.expires_at)}")
    body = "\n".join(lines)
    return {"title": title, "body": body, "url": ctx.url_for(ticket.id)}


class Notifier(ABC):
    """Interface every delivery channel implements."""

    #: Channel name, used for diagnostics and routing.
    name: str = "base"

    @abstractmethod
    def send(self, ticket: ApprovalTicket, event: str, *, context: Optional[NotifierContext] = None) -> None:
        """Deliver a notification for ``ticket`` / ``event``.

        Args:
            ticket: The ticket whose state changed.
            event: The lifecycle event name.
            context: Optional shared configuration.

        Raises:
            NotifierError: Delivery failed.  Implementations must never raise
            anything else on a simple network error, so callers can decide
            whether to fail-open or fail-closed.
        """

    def render(self, ticket: ApprovalTicket, event: str, *, context: Optional[NotifierContext] = None) -> Dict[str, str]:
        """Convenience wrapper around :func:`render_message`."""
        return render_message(ticket, event, context=context)

    def to_payload(self, ticket: ApprovalTicket, event: str, *, context: Optional[NotifierContext] = None) -> Mapping[str, Any]:
        """Return a JSON-safe payload suitable for webhook-style channels."""
        msg = self.render(ticket, event, context=context)
        return {
            "event": event,
            "ticket_id": ticket.id,
            "tool": ticket.request.tool,
            "risk": ticket.risk.value,
            "state": ticket.state.value,
            "quorum": ticket.quorum.describe(),
            "requester_id": ticket.requester_id,
            "title": msg["title"],
            "body": msg["body"],
            "url": msg["url"],
        }
