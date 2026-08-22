"""Health endpoints — safe baseline (no sinks, nothing to find)."""


def healthz(request):
    return {"status": "ok"}


def version(request):
    return {"version": "1.0.0"}
