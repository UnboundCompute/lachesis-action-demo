"""Python request handlers — command injection with a guard differential.

Three functions reach the same sink (os.system). One forgets the authorization
check its sibling performs; one launders the taint through a helper. Lachesis is
built to see all three and to flag the *missing-guard* one as the differential.
"""

import os


def currentUser(request):
    """Authorization accessor. Its presence in a handler marks that handler
    'guarded' — the analyzer keys on the call, not on any if/else around it."""
    return request.headers.get("X-User")


def _relay(value):
    """Pass-through helper: carries taint across a call boundary unchanged."""
    return value


def public_exec(request):
    """UNGUARDED. Untrusted JSON body flows straight into os.system with no
    authorization accessor anywhere in the function. Because admin_exec reaches
    the same sink *with* a guard, this one is reported as the differential
    (error): the endpoint that forgot the check its sibling remembered."""
    cmd = request.get_json()
    os.system(cmd)


def admin_exec(request):
    """GUARDED. Same untrusted-body -> os.system flow, but currentUser() is
    present, so the analyzer treats the sink as guarded (note)."""
    currentUser(request)
    cmd = request.get_json()
    os.system(cmd)


def relay_exec(request):
    """INTERPROCEDURAL. Taint crosses _relay() before reaching os.system;
    the flow is still traced end-to-end (warning)."""
    cmd = request.get_json()
    os.system(_relay(cmd))
