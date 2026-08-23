"""Nimbus control plane.

A small internal service for driving deploys, reporting on inventory and wiring
up integrations. This module is the router: it maps URL paths to the plain
handler callables defined under :mod:`app.routes`. Every handler takes the
incoming ``request`` and returns a JSON-serializable value.

The point of the demo is that the handlers are *inconsistent* about
authorization. Some resolve the caller through :mod:`app.security.access`
before touching a sink; the ones that forget are what Lachesis flags.
"""

from __future__ import annotations

from app import health
from app.routes import deploy, integrations, reports, templates

# path -> handler. Keep this the single source of truth for what is exposed.
ROUTES = {
    "GET /healthz": health.healthz,
    "GET /version": health.version,
    # deploy / host maintenance
    "GET /deploy/diagnostic": deploy.run_diagnostic,
    "POST /deploy/trigger": deploy.trigger_deploy,
    "POST /deploy/restart": deploy.restart_service,
    "GET /deploy/logs": deploy.collect_logs,
    # inventory reporting
    "GET /reports/run": reports.run_report,
    "GET /reports/search": reports.search_records,
    # integrations
    "GET /integrations/manifest": integrations.fetch_manifest,
    "POST /integrations/plugin-state": integrations.load_plugin_state,
    "GET /integrations/log": integrations.download_log,
    # notifications
    "GET /notifications/preview": templates.preview_notification,
}


def dispatch(method, path, request):
    """Look up and invoke the handler registered for ``method path``."""
    handler = ROUTES.get(f"{method} {path}")
    if handler is None:
        return {"error": "not found"}, 404
    return handler(request)
