"""Third-party integration endpoints.

These handlers reach out to remote services, load plugin state from disk, and
read log files by name. Each takes an untrusted value and feeds it to an
effectful sink with no guard on the path.
"""

from __future__ import annotations

import pickle

import requests


def fetch_manifest(request):
    """Fetch and return a plugin manifest from a caller-supplied URL.

    The ``url`` is taken from the request and passed straight to
    ``requests.get`` — a server-side request forgery flow: the caller chooses
    what the server connects to.
    """
    url = request.args.get("url")
    resp = requests.get(url, timeout=10)
    return {"manifest": resp.text}


def load_plugin_state(request):
    """Restore a plugin's saved state from an uploaded blob.

    The request body is deserialized with ``pickle.loads`` — untrusted input
    into an unpickler is arbitrary code execution.
    """
    blob = request.get_data()
    state = pickle.loads(blob)
    return {"restored": bool(state)}


def download_log(request):
    """Return the contents of a named log file.

    ``name`` comes off the query string and is opened directly, with no
    normalization or base-directory check — a path-traversal read.
    """
    name = request.args.get("name", "nimbus.log")
    with open(name) as fh:
        return {"name": name, "content": fh.read()}
