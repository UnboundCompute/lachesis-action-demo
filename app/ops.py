"""Ops endpoints — the command-injection guard differential.

Two sibling handlers reach the same shell sink from the same untrusted request
body. `restart_service` calls the authorization accessor first; `tail_log`
forgot to. A line-by-line scanner sees two identical os.system nits; a graph
scanner sees that one caller is authorized and its sibling is not.
"""
import os

from .util import currentUser


def restart_service(request):
    """GUARDED: authorization accessor present -> note."""
    cmd = request.get_json()           # source: web-input
    currentUser()                      # authz accessor -> GUARDED
    os.system(cmd)                     # sink: command-injection


def tail_log(request):
    """UNGUARDED sibling: identical sink, no authorization check -> error."""
    cmd = request.get_json()           # source: web-input
    os.system(cmd)                     # sink: command-injection (differential)
