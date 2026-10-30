"""FastAPI application factory.

M1 note: startup no longer asserts that execution is *disabled*. Execution is real now,
and the fences around it are the coordinator lease, the atomic budget reservation, the
policy broker and the cancellation epoch. Switching `SCOPELENS_SCANNER_EXECUTION_ENABLED`
off is a legitimate configuration — scans then stay queued — so it must not stop the API
from starting or an operator could not turn it back on.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from scopelens.api import (
    academic,
    assessments,
    auth,
    cleanup_recovery,
    dashboard,
    scans,
    scopes,
    system,
)
from scopelens.api.deps import settings_dependency
from scopelens.config import Settings
from scopelens.domain.errors import DomainError
from scopelens.execution.ledger import ExecutionDisabled

DESCRIPTION = """
Operator-only external configuration assessment.

**This build is M1.** It adds the durable task ledger, transactional outbox, Celery
dispatch with leases and fencing, the policy broker behind a mandatory forward proxy,
the constrained TLS measurement lane, isolated workers under a supervisor, trusted
evidence intake, and cancellation with crash recovery.

Scans now execute. Every request to a target is admitted individually by the policy
broker, and a scan whose lease is lost or whose authorization is revoked stops
immediately. See `/api/system/execution` for the machine-readable state.
"""


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(
        title="ScopeLens API",
        description=DESCRIPTION,
        version="0.2.0",
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    if settings is not None:
        # Actually override the settings the dependency graph resolves, rather than
        # accepting the argument and quietly ignoring it.
        app.dependency_overrides[settings_dependency] = lambda: settings

    app.include_router(system.router)
    app.include_router(auth.router)
    app.include_router(scopes.router)
    app.include_router(scans.router)
    app.include_router(dashboard.router)
    app.include_router(assessments.router)
    app.include_router(academic.router)
    app.include_router(cleanup_recovery.router)
    app.state.cleanup_recovery_runtime_enabled = True
    # NOTE: the broker's decision endpoint is deliberately NOT mounted here. It is served
    # by `scopelens.internal_app` on an unpublished port, because this app's port *is*
    # published to the host and the route must not be reachable from it.

    @app.exception_handler(DomainError)
    async def domain_error_handler(_: Request, exc: DomainError) -> JSONResponse:
        # Operator-fixable input problems. Deliberately narrow: a bare ValueError from
        # an internal bug keeps its 500 rather than being disguised as a client mistake.
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(ExecutionDisabled)
    async def execution_disabled_handler(_: Request, exc: ExecutionDisabled) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    return app


app = create_app()
