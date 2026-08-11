"""Email notifier using the standard library :mod:`smtplib`.

Configuration is sourced from :class:`NotifierContext`.  TLS is used when the
server advertises STARTTLS; plaintext is only attempted as a last resort and
is logged loudly because approval emails contain a link that grants authority.

Like every notifier, the email never embeds an authorising token - only a
non-authoritative console link.
"""

from __future__ import annotations

from email.message import EmailMessage
from typing import List, Optional

from ...core.logging import get_logger
from ..models import ApprovalTicket
from .base import Notifier, NotifierContext, NotifierError

__all__ = ["EmailNotifier"]

_LOG = get_logger("aegis.approval.notifier.email")


class EmailNotifier(Notifier):
    """Sends approval notifications over SMTP."""

    name = "email"

    def __init__(
        self,
        *,
        smtp_host: str = "",
        smtp_port: int = 25,
        sender: str = "",
        recipients: Optional[List[str]] = None,
        use_tls: bool = True,
        username: str = "",
        password: str = "",
    ) -> None:
        """Create the notifier.

        Args:
            smtp_host: SMTP server hostname.
            smtp_port: SMTP server port.
            sender: ``From`` address.
            recipients: Destination addresses.
            use_tls: Attempt STARTTLS when available.
            username: Optional auth user.
            password: Optional auth password.

        Raises:
            NotifierError: Host, sender or recipients are missing.
        """
        if not smtp_host:
            raise NotifierError("smtp host is required", channel=self.name)
        if not sender:
            raise NotifierError("sender address is required", channel=self.name)
        if not recipients:
            raise NotifierError("at least one recipient is required", channel=self.name)
        self._host = smtp_host
        self._port = int(smtp_port)
        self._sender = sender
        self._recipients = list(recipients)
        self._use_tls = bool(use_tls)
        self._username = username
        self._password = password

    def send(self, ticket: ApprovalTicket, event: str, *, context: Optional[NotifierContext] = None) -> None:
        """Send the approval email.

        Args:
            ticket: The ticket whose state changed.
            event: The lifecycle event name.
            context: Optional shared configuration (``sender_name`` used).

        Raises:
            NotifierError: SMTP delivery failed.
        """
        import smtplib

        ctx = context or NotifierContext()
        rendered = self.render(ticket, event, context=ctx)
        message = EmailMessage()
        message["Subject"] = rendered["title"]
        message["From"] = f"{ctx.sender_name} <{self._sender}>"
        message["To"] = ", ".join(self._recipients)
        message.set_content(rendered["body"] + (f"\n\nReview: {rendered['url']}" if rendered["url"] else ""))
        try:
            with smtplib.SMTP(self._host, self._port, timeout=15) as server:
                if self._use_tls:
                    try:
                        server.starttls()
                    except Exception as exc:  # pragma: no cover - server quirks
                        _LOG.warning("smtp starttls failed; continuing", extra={"error": str(exc)})
                if self._username and self._password:
                    server.login(self._username, self._password)
                server.send_message(message)
        except NotifierError:
            raise
        except Exception as exc:
            raise NotifierError(f"email delivery failed: {exc}", channel=self.name, cause=exc)
