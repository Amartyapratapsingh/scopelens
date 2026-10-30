"""Unversioned operational endpoints: liveness, readiness and execution state."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from scopelens.api.deps import DbSession
from scopelens.config import get_settings
from scopelens.execution.ledger import execution_status

router = APIRouter(tags=["system"])

API_VERSION = "0.1.0"


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness. Deliberately does not touch the database."""
    return {"status": "ok", "api_version": API_VERSION}


@router.get("/readyz")
def readyz(response: Response, session: DbSession) -> dict[str, Any]:
    """Readiness. Fails if the database is unreachable or migrations are pending."""
    from scopelens.persistence.repositories import database_revision

    try:
        session.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - any failure means not ready
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "reason": f"database unreachable: {exc.__class__.__name__}"}

    revision = database_revision(session)
    if revision is None:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "reason": "database schema is not migrated"}

    return {"status": "ready", "schema_revision": revision}


@router.get("/api/system/execution")
def execution() -> dict[str, str | bool]:
    """Why nothing is running.

    Exposed unauthenticated on purpose: it reveals the build's capability, not any
    operator data, and it is the fastest way to tell "M0 is working as designed" apart
    from "the scanner is broken".
    """
    settings = get_settings()
    return {
        **execution_status(settings),
        "milestone": "M0",
        "default_profile": settings.default_profile,
        "score_version": settings.score_version,
    }
