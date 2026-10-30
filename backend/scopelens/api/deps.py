"""Shared FastAPI dependencies.

Every route that touches a scope, a scan or an audit record depends on
:func:`require_operator`, which re-reads the operator from the database on each
request. The session cookie carries only an identity, never an authority, so a
tampered cookie cannot widen access (Build Plan §5.1: "Every API call and evidence
read is checked against the operator/owner server-side").
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from scopelens.config import Settings, get_settings
from scopelens.persistence.models import OperatorRow
from scopelens.persistence.repositories import get_operator
from scopelens.persistence.session import session_scope
from scopelens.security.sessions import SessionError, SessionSigner

SESSION_COOKIE = "scopelens_session"


def settings_dependency() -> Settings:
    return get_settings()


def get_session() -> Iterator[Session]:
    with session_scope() as session:
        yield session


def get_signer(settings: Annotated[Settings, Depends(settings_dependency)]) -> SessionSigner:
    secret = settings.session_secret
    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SCOPELENS_SESSION_SECRET is not configured",
        )
    return SessionSigner(
        secret.get_secret_value(), max_age_seconds=settings.session_max_age_seconds
    )


def optional_operator(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    signer: Annotated[SessionSigner, Depends(get_signer)],
) -> OperatorRow | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        payload = signer.verify(token)
    except SessionError:
        return None

    try:
        operator_id = uuid.UUID(str(payload["sub"]))
    except (KeyError, ValueError):
        return None

    operator = get_operator(session, operator_id)
    if operator is None or operator.disabled:
        return None
    return operator


def require_operator(
    operator: Annotated[OperatorRow | None, Depends(optional_operator)],
) -> OperatorRow:
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
        )
    return operator


CurrentOperator = Annotated[OperatorRow, Depends(require_operator)]
DbSession = Annotated[Session, Depends(get_session)]
AppSettings = Annotated[Settings, Depends(settings_dependency)]
Signer = Annotated[SessionSigner, Depends(get_signer)]
