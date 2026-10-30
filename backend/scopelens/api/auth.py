"""Operator authentication routes (Build Plan §5.1).

Deliberately minimal: login, logout, and who-am-I. There is no signup, no password
reset, no self-service account creation and no registration endpoint — the single
account is seeded from the environment by ``scopelens seed-operator``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from scopelens.api.deps import SESSION_COOKIE, AppSettings, CurrentOperator, DbSession, Signer
from scopelens.persistence.repositories import get_operator_by_username, record_audit
from scopelens.security.passwords import verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

# One message for every failure mode. Distinguishing "no such user" from "wrong
# password" would turn the login form into an account-enumeration oracle
# (Project Specification §10.1 ADD-07).
_INVALID_CREDENTIALS = "invalid username or password"


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class OperatorView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    username: str
    last_login_at: datetime | None


@router.post("/login", response_model=OperatorView)
def login(
    payload: LoginRequest,
    response: Response,
    session: DbSession,
    signer: Signer,
    settings: AppSettings,
) -> OperatorView:
    operator = get_operator_by_username(session, payload.username)

    if operator is None or not verify_password(payload.password, operator.password_hash):
        record_audit(
            session,
            actor=payload.username[:64],
            action="auth.login",
            subject_type="operator",
            subject_id=str(operator.id) if operator else None,
            outcome="denied",
            detail={"reason": "invalid credentials"},
        )
        # Commit the audit row before raising, so a failed attempt is recorded.
        session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDENTIALS)

    if operator.disabled:
        record_audit(
            session,
            actor=operator.username,
            action="auth.login",
            subject_type="operator",
            subject_id=str(operator.id),
            outcome="denied",
            detail={"reason": "account disabled"},
        )
        session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDENTIALS)

    operator.last_login_at = datetime.now(UTC)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=signer.sign({"sub": str(operator.id), "username": operator.username}),
        max_age=signer.max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )
    record_audit(
        session,
        actor=operator.username,
        action="auth.login",
        subject_type="operator",
        subject_id=str(operator.id),
        outcome="success",
        detail={},
    )
    return OperatorView(
        id=str(operator.id),
        username=operator.username,
        last_login_at=operator.last_login_at,
    )


@router.post("/logout")
def logout(response: Response, operator: CurrentOperator, session: DbSession) -> Response:
    record_audit(
        session,
        actor=operator.username,
        action="auth.logout",
        subject_type="operator",
        subject_id=str(operator.id),
        outcome="success",
        detail={},
    )
    response.delete_cookie(SESSION_COOKIE, path="/")
    # Set explicitly rather than via the decorator: the injected Response is returned
    # as-is, so the decorator's status_code would not be applied to it.
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=OperatorView)
def me(operator: CurrentOperator) -> OperatorView:
    return OperatorView(
        id=str(operator.id),
        username=operator.username,
        last_login_at=operator.last_login_at,
    )
