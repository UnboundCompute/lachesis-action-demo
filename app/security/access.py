"""Authentication and authorization accessors.

Every privileged handler is expected to resolve the caller and check their role
through one of these helpers before it touches an effectful sink. The handlers
that forget to are exactly the ones Lachesis flags as guard differentials: a
sibling reaches the same sink *with* one of these calls on the path, and they
do not.
"""

from __future__ import annotations


class AccessError(Exception):
    """Raised when a caller is not permitted to perform an action."""


# In a real deployment this reads a signed session cookie and looks the
# principal up in the identity service. The demo keeps it in-process.
_SESSIONS = {
    "tok-admin": {"id": "u-1", "name": "admin", "roles": {"admin", "operator"}},
    "tok-ops": {"id": "u-2", "name": "ops", "roles": {"operator"}},
    "tok-view": {"id": "u-3", "name": "viewer", "roles": {"viewer"}},
}


def currentUser(request):
    """Resolve the authenticated principal from the request session token.

    Returns ``None`` for an anonymous caller. Handlers that call this before a
    sink are treated as authenticated paths.
    """
    token = request.headers.get("X-Session-Token", "")
    return _SESSIONS.get(token)


def currentTenant(request):
    """Resolve the tenant the caller is scoped to."""
    user = currentUser(request)
    if not user:
        return None
    return request.headers.get("X-Tenant", "default")


def requireUser(request):
    """Return the principal or raise if the request is unauthenticated."""
    user = currentUser(request)
    if not user:
        raise AccessError("authentication required")
    return user


def authorize(request, role):
    """Assert the caller holds ``role``; raise :class:`AccessError` otherwise."""
    user = requireUser(request)
    if role not in user["roles"]:
        raise AccessError(f"{user['name']} lacks role {role!r}")
    return user


def checkPermission(request, action):
    """Boolean permission check used by the softer, non-raising call sites."""
    user = currentUser(request)
    if not user:
        return False
    return "admin" in user["roles"] or action in {"read", "list"}
