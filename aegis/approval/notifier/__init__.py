"""Notification delivery for the approval layer.

This sub-package turns a lifecycle event into an out-of-band alert while
carefully *not* granting authority through the alert channel.  :func:`dispatch`
is the entry the workflow calls; it fans the event out to every channel named
in the active policy.  A failure on one channel never blocks the others or the
decision itself.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

from ...core.config import get_settings
from ...core.logging import get_logger
from ..models import ApprovalChannel, ApprovalPolicy, ApprovalTicket
from .base import Notifier, NotifierContext

__all__ = [
    "Notifier",
    "NotifierContext",
    "ConsoleNotifier",
    "WebhookNotifier",
    "SlackNotifier",
    "EmailNotifier",
    "WeComNotifier",
    "build_context",
    "build_notifiers",
    "dispatch",
]

# Import concrete notifiers lazily at call time to avoid import side effects
# when the approval package is imported standalone.

_LOG = get_logger("aegis.approval.notifier")


def build_context(settings=None) -> NotifierContext:
    """Construct a :class:`NotifierContext` from active settings.

    Args:
        settings: Optional settings object; loaded lazily when omitted.

    Returns:
        A context populated from the ``approval`` and top-level config.
    """
    cfg = settings or get_settings()
    ctx = NotifierContext()
    if cfg is None:
        return ctx
    section = cfg.section("approval")
    ctx.webhook_url = str(section.get("webhook_url", "") or "")
    ctx.slack_webhook = str(section.get("slack_webhook", "") or "")
    ctx.environment = cfg.environment()
    # Email + WeCom secrets live in their own section for separation.
    notify = cfg.section("notifications") if hasattr(cfg, "section") else {}
    ctx.email_smtp_host = str(notify.get("smtp_host", "") or "")
    ctx.email_smtp_port = int(notify.get("smtp_port", 25) or 25)
    ctx.email_from = str(notify.get("email_from", "") or "")
    ctx.email_to = list(notify.get("email_to", []) or [])
    ctx.wecom_webhook = str(notify.get("wecom_webhook", "") or "")
    return ctx


def build_notifiers(policy: ApprovalPolicy, context: Optional[NotifierContext] = None) -> List[Notifier]:
    """Instantiate the notifiers named by the policy.

    Args:
        policy: Approval policy whose ``channels`` select the activations.
        context: Shared configuration; built from settings when omitted.

    Returns:
        A list of ready notifiers.  ``console`` is always included so a human
        is never left without an alert, even when remote channels are
        misconfigured.
    """
    ctx = context or build_context()
    notifiers: List[Notifier] = []
    from .console import ConsoleNotifier

    notifiers.append(ConsoleNotifier())
    names = {str(c) for c in policy.channels} if policy.channels else set()
    try:
        if "webhook" in names and ctx.webhook_url:
            from .webhook import WebhookNotifier

            notifiers.append(WebhookNotifier(ctx.webhook_url))
        if "slack" in names and ctx.slack_webhook:
            from .slack import SlackNotifier

            notifiers.append(SlackNotifier(ctx.slack_webhook))
        if "email" in names and ctx.email_smtp_host and ctx.email_to:
            from .email import EmailNotifier

            notifiers.append(EmailNotifier(
                smtp_host=ctx.email_smtp_host,
                smtp_port=ctx.email_smtp_port,
                sender=ctx.email_from,
                recipients=ctx.email_to,
            ))
        if "wecom" in names and ctx.wecom_webhook:
            from .wecom import WeComNotifier

            notifiers.append(WeComNotifier(ctx.wecom_webhook))
    except Exception as exc:  # pragma: no cover - misconfig
        _LOG.warning("some notifiers disabled due to config error", extra={"error": str(exc)})
    return notifiers


def dispatch(ticket: ApprovalTicket, event: str, *, policy: Optional[ApprovalPolicy] = None) -> int:
    """Send ``event`` for ``ticket`` to every configured channel.

    Args:
        ticket: The ticket whose state changed.
        event: The lifecycle event name.
        policy: Active policy; loaded from settings when omitted.

    Returns:
        The number of channels that delivered successfully.  Failures are
        logged and swallowed so the approval decision is never blocked by a
        notification outage.
    """
    active_policy = policy or _default_policy()
    context = build_context()
    notifiers = build_notifiers(active_policy, context)
    delivered = 0
    for notifier in notifiers:
        try:
            notifier.send(ticket, event, context=context)
            delivered += 1
        except Exception as exc:
            _LOG.warning(
                "approval notification failed",
                extra={"channel": getattr(notifier, "name", "?"), "event": event, "error": str(exc)},
            )
    return delivered


def _default_policy() -> ApprovalPolicy:
    """Return the policy loaded from settings (import deferred)."""
    return ApprovalPolicy.from_mapping(get_settings().section("approval") if get_settings() else {})
