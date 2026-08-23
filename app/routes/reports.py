"""Inventory reporting endpoints.

Every handler here builds a SQL string and runs it through a cursor. The set is
deliberately uneven: two handlers resolve and authorize the caller before they
query, the rest interpolate request input straight into the SQL text with no
check at all. Same ``cursor.execute`` sink reached both ways, so the
unauthenticated handlers surface as guard differentials against the two that
authorize -- SQL injection that Lachesis can rank by whether a sibling proves
the guarded shape is possible.
"""

from __future__ import annotations

import sqlite3

from app.security.access import authorize, currentUser

_DB_PATH = "nimbus.db"


def _cursor():
    """Open a connection to the inventory database and return a cursor."""
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn.cursor()


def run_report(request):
    """Authorized, filtered slice of the inventory.

    Guarded sibling: ``authorize`` runs before the query, so this
    ``cursor.execute`` reach is an authenticated path (a note) and one of the
    baselines the unguarded handlers are measured against.
    """
    authorize(request, "operator")
    region = request.args.get("region", "us-east-1")
    cursor = _cursor()
    cursor.execute(f"SELECT host, status FROM inventory WHERE region = '{region}'")
    return {"rows": cursor.fetchall()}


def audit_lookup(request):
    """Look up audit-log entries for an actor.

    Guarded sibling: the caller is resolved with ``currentUser`` before the
    query runs -- the second authenticated baseline.
    """
    if currentUser(request) is None:
        return {"error": "authentication required"}, 401
    actor = request.args.get("actor", "")
    cursor = _cursor()
    cursor.execute(f"SELECT ts, action FROM audit WHERE actor = '{actor}'")
    return {"rows": cursor.fetchall()}


def search_records(request):
    """Free-text search over the inventory.

    No caller resolution: ``term`` is interpolated straight into the SQL text.
    Same sink as ``run_report``/``audit_lookup`` with no guard on the path -- an
    error naming the guarded twins.
    """
    term = request.args.get("term", "")
    cursor = _cursor()
    cursor.execute(f"SELECT host, tags FROM inventory WHERE tags LIKE '%{term}%'")
    return {"rows": cursor.fetchall()}


def export_hosts(request):
    """Export every host in an environment.

    Unauthenticated: ``env`` flows straight into the query -- a SQL-injection
    error with the guarded siblings named.
    """
    env = request.args.get("env", "")
    cursor = _cursor()
    cursor.execute(f"SELECT * FROM inventory WHERE env = '{env}'")
    return {"rows": cursor.fetchall()}


def tag_search(request):
    """Resolve hosts carrying a named tag.

    Unauthenticated interpolation of ``name`` into the query text.
    """
    name = request.args.get("name", "")
    cursor = _cursor()
    cursor.execute(f"SELECT host FROM tags WHERE name = '{name}'")
    return {"rows": cursor.fetchall()}
