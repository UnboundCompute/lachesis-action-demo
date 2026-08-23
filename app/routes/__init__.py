"""Route handlers for the Nimbus control plane.

Each module here holds a family of endpoints. Handlers are plain callables that
take a ``request`` and return a JSON-serializable value; :mod:`app` wires them
to URL paths. The handlers are deliberately uneven — some resolve the caller
through :mod:`app.security.access` before acting, some do not — which is exactly
the kind of drift Lachesis surfaces as guard differentials.
"""
