"""Plugin loader — an untrusted deserialization sink.

The request body flows straight into pickle.loads, which will execute arbitrary
code during unpickling. No authorization sibling exists for this sink, so it
surfaces as a warning rather than a guard differential.
"""
import pickle


def load_state(request):
    body = request.get_json()          # source: web-input
    return pickle.loads(body)          # sink: deserialization (untrusted)
