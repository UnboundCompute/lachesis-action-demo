"""Shared helpers: an authorization accessor and an interprocedural relay.

`currentUser` is named to match the engine's authorization-accessor set, so a
call to it marks a handler as GUARDED. `relay` passes its argument straight
through, so taint that enters it still arrives at the sink one frame later.
"""


def currentUser():
    """Authorization accessor. Presence of this call = GUARDED handler."""
    return {"id": 1, "role": "admin"}


def relay(value):
    """Interprocedural passthrough: tainted value in, same value out."""
    return value
