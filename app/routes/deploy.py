"""Deploy and host-maintenance endpoints.

These handlers shell out to run deploy scripts, diagnostics and service
restarts on the target host. ``run_diagnostic`` resolves the caller before it
runs a command; the others take request input straight to the system shell.
"""

from __future__ import annotations

import os
import subprocess

from app.security.access import currentUser


def run_diagnostic(request):
    """Run a read-only diagnostic command against a host.

    Caller resolved with ``currentUser`` before the command runs -- the guarded
    baseline for the deploy handlers.
    """
    if currentUser(request) is None:
        return {"error": "authentication required"}, 401
    host = request.args.get("host", "localhost")
    check = request.args.get("check", "uptime")
    os.system(f"ssh {host} nimbus-diag --check {check}")
    return {"status": "diagnostic dispatched", "host": host}


def trigger_deploy(request):
    """Kick off a deploy of a release to a target environment.

    No caller resolution: ``target`` and ``release`` are interpolated straight
    into a shell command -- an unauthenticated command-injection path.
    """
    payload = request.get_json()
    target = payload["target"]
    release = payload["release"]
    os.system(f"nimbus-deploy --env {target} --release {release}")
    return {"status": "deploy started", "target": target, "release": release}


def restart_service(request):
    """Restart a named service on a host.

    ``service`` comes off the request and is concatenated into a shell command
    -- command injection with no guard on the path.
    """
    service = request.args.get("service", "")
    os.system("systemctl restart " + service)
    return {"status": "restarting", "service": service}


def collect_logs(request):
    """Tail and return recent logs for a unit.

    ``subprocess.run(..., shell=True)`` parses the caller's ``unit`` value with
    /bin/sh, so injected metacharacters are honored.
    """
    unit = request.args.get("unit", "nimbus")
    lines = request.args.get("lines", "200")
    proc = subprocess.run(
        f"journalctl -u {unit} -n {lines} --no-pager",
        shell=True, capture_output=True, text=True,
    )
    return {"unit": unit, "log": proc.stdout}
