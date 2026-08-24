"""Notification preview endpoint.

Renders a caller-supplied notification body so operators can preview how a
template will look before saving it.
"""

from __future__ import annotations

from flask import render_template_string


def preview_notification(request):
    """Render a notification template supplied by the caller.

    The ``body`` is passed straight to ``render_template_string``, so the caller
    controls the template source — a server-side template-injection flow that
    can reach arbitrary attributes and, through them, code execution.
    """
    body = request.args.get("body", "")
    subject = request.args.get("subject", "Notification")
    rendered = render_template_string(body, subject=subject)
    return {"subject": subject, "preview": rendered}
