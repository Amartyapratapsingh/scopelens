"""The policy service: the broker's decision endpoint, on its own port and network.

Why this is a separate application rather than a route on the operator API
=========================================================================

An earlier version mounted `/internal/broker/*` on the operator API. That API's port is
published to the host, so the route was reachable from the host too — while a docstring
claimed it was not. The claim and the fact disagreed, and the docstring was the thing that
was wrong.

Splitting it out makes the claim structural rather than documentary:

* this app is served on a port that is **not** published to the host
* it is attached only to the control network
* it exposes no OpenAPI schema, no docs and no operator routes at all

The consequence is that the only way to reach the broker's decision endpoint is from a
container on the control network — which is where the proxy and the TLS lane live, and
where workers never are.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from scopelens.api import internal
from scopelens.domain.errors import DomainError

DESCRIPTION = """
ScopeLens policy service.

Internal only: serves the broker's per-connection and per-request authorization decision
to the forward proxy and the TLS measurement lane. Not an operator interface, not
published to the host, and not reachable from a worker.
"""


def create_policy_app() -> FastAPI:
    app = FastAPI(
        title="ScopeLens policy service",
        description=DESCRIPTION,
        # No schema, no docs. This is a machine-to-machine endpoint and every route on it
        # is a security decision; publishing a browsable surface for it is pure downside.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.include_router(internal.router)

    @app.exception_handler(DomainError)
    async def domain_error_handler(_: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    return app


app = create_policy_app()
