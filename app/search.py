"""Search handler — interprocedural taint across a file boundary.

The tainted request body is handed to util.relay(), which returns it unchanged;
the sink is here, the taint entered a frame away. This is the case that
separates a call-graph-aware analyzer from grep.
"""
import os

from .util import relay


def search_data(request):
    cmd = request.get_json()           # source: web-input
    os.system(relay(cmd))              # sink: command-injection (interprocedural)
