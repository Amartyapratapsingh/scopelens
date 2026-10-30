"""Internal broker endpoints (Build Plan §5.3).

Served by ``scopelens.internal_app`` on its own unpublished port, never by the operator
API. The credential is the scan's egress token itself: 32 bytes of
``secrets.token_urlsafe``, and without a valid one the endpoint reveals nothing but
"unknown token".

The staged native-ZAP route also requires a supervisor signature binding the exact
child container, task and request. This key is never placed in a worker. Ordinary
scan routes retain their existing revocable egress-token protocol. Workers cannot
reach these unpublished control-plane routes.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field, model_validator

from scopelens.api.deps import AppSettings, DbSession
from scopelens.broker.policy import BrokerRequest, authorize, scan_for_token
from scopelens.broker.zap_task import SignedTaskRequest, authorize_task, grant_live
from scopelens.browser.policy import BrowserCommand
from scopelens.browser.policy import command as browser_command
from scopelens.browser.vision import VisionRequest, vision
from scopelens.expansion.control import AssessmentCommand
from scopelens.expansion.control import command as assessment_command
from scopelens.scope.dns import SystemResolver

router = APIRouter(prefix="/internal/broker", tags=["internal"])


class ZapTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signed: SignedTaskRequest
    egress_token: str = Field(repr=False)
    method: str
    url: str
    body_sha256: str


@router.post("/zap-task/authorize")
def zap_task_authorize(payload: ZapTaskRequest, session: DbSession, settings: AppSettings):
    scan = scan_for_token(session, payload.egress_token)
    if (
        scan is None
        or scan.id != payload.signed.scan_id
        or payload.method != payload.signed.method
        or payload.url != payload.signed.url
        or payload.body_sha256 != payload.signed.body_sha256
    ):
        return {"allowed": False, "reason": "zap_task_binding_refused"}
    decision = authorize_task(
        session, settings=settings, request=payload.signed, resolver=SystemResolver()
    )
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "addresses": list(decision.addresses),
        "limits": decision.extra,
        "scope_version_id": decision.scope_version_id,
    }


@router.post("/zap-task/alive")
def zap_task_alive(payload: SignedTaskRequest, session: DbSession, settings: AppSettings):
    return {"allowed": grant_live(session, settings=settings, signed=payload)}


class AuthorizeRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    egress_token: str = Field(min_length=1)
    method: str = Field(min_length=1)
    scheme: str = Field(min_length=1)
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    path: str = Field(min_length=1)
    probe_task: str | None = Field(default=None, min_length=1, max_length=128)


class AuthorizeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    detail: str = ""
    addresses: list[str] = Field(default_factory=list)
    scope_version_id: str | None = None
    limits: dict[str, str] = Field(default_factory=dict)


@router.post("/authorize", response_model=AuthorizeResponse)
def authorize_request(
    payload: AuthorizeRequestBody, session: DbSession, settings: AppSettings
) -> AuthorizeResponse:
    """Decide one proxied request.

    Always returns 200 with an `allowed` flag rather than an HTTP error for a denial:
    the proxy needs the *reason* to record, and a denial is a normal, expected outcome
    of the policy — not a transport failure.
    """
    decision = authorize(
        session,
        settings=settings,
        request=BrokerRequest(
            method=payload.method,
            scheme=payload.scheme,
            host=payload.host,
            port=payload.port,
            path=payload.path,
            egress_token=payload.egress_token,
            probe_task=payload.probe_task,
        ),
        resolver=SystemResolver(),
    )
    limits = dict(decision.extra)
    if decision.allowed:
        scan = scan_for_token(session, payload.egress_token)
        if scan and (scan.assessment_plan or {}).get("expansion_config", {}).get(
            "callback_recipes"
        ):
            limits["callback_capture"] = "1"
    return AuthorizeResponse(
        allowed=decision.allowed,
        reason=decision.reason,
        detail=decision.detail,
        addresses=list(decision.addresses),
        scope_version_id=decision.scope_version_id,
        limits=limits,
    )


@router.post("/browser")
def browser_request(payload: BrowserCommand, session: DbSession, settings: AppSettings) -> dict:
    return browser_command(session, settings, payload)


@router.post("/alive")
def alive(payload: BrowserCommand, session: DbSession):
    from datetime import UTC, datetime

    from scopelens.broker.policy import scan_for_token
    from scopelens.execution.leases import lease_is_live
    from scopelens.persistence.repositories import scope_row_to_domain

    scan = scan_for_token(session, payload.egress_token)
    return {
        "allowed": bool(
            scan
            and not scan.cancel_requested_at
            and scan.cancel_epoch == scan.egress_token_epoch
            and lease_is_live(session, scan.id)
            and not scope_row_to_domain(scan.scope_version).is_expired(datetime.now(UTC))
        )
    }


@router.post("/vision")
def vision_request(payload: VisionRequest, settings: AppSettings):
    return vision(settings, payload)


@router.post("/assessment")
def assessment_request(
    payload: AssessmentCommand, session: DbSession, settings: AppSettings
) -> dict:
    return assessment_command(session, settings, payload)


class CallbackDispatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: Literal["begin", "complete"]
    egress_token: str = Field(min_length=1, repr=False)
    method: str | None = Field(default=None, max_length=16)
    url: str | None = Field(default=None, max_length=16384, repr=False)
    body_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    dispatch_id: str | None = Field(default=None, max_length=64)
    response_status: int | None = Field(default=None, ge=100, le=599)

    @model_validator(mode="after")
    def exact_operation_fields(self):
        if self.operation == "begin":
            if not (self.method and self.url and self.body_sha256) or (
                self.dispatch_id is not None or self.response_status is not None
            ):
                raise ValueError("begin requires only request commitments")
        elif (
            not self.dispatch_id
            or self.response_status is None
            or any(v is not None for v in (self.method, self.url, self.body_sha256))
        ):
            raise ValueError("complete requires only dispatch ID and response status")
        return self


@router.post("/callback-dispatch")
def callback_dispatch(
    payload: CallbackDispatchRequest, session: DbSession, settings: AppSettings
) -> dict:
    """Proxy-only capture; deliberately absent from the worker control router.

    The proxy commits the actual request before upstream dispatch and records the
    received upstream status. A worker cannot manufacture this capture via its
    assessment capability or its stdout.
    """
    from datetime import UTC, datetime

    from scopelens.callbacks.deployment import runtime_from_settings
    from scopelens.execution.leases import lease_is_live
    from scopelens.persistence.session import build_session_factory

    deny = {"allowed": False, "reason": "callback_capture_denied"}
    scan = scan_for_token(session, payload.egress_token)
    if (
        scan is None
        or scan.cancel_requested_at is not None
        or scan.egress_token_epoch != scan.cancel_epoch
        or not lease_is_live(session, scan.id)
        or scan.scope_version.authorization_expires_at <= datetime.now(UTC)
        or not (scan.assessment_plan or {}).get("expansion_config", {}).get("callback_recipes")
    ):
        return deny
    runtime = runtime_from_settings(
        settings, session_factory=build_session_factory(session.get_bind())
    )
    if runtime is None:
        return deny
    try:
        if payload.operation == "begin":
            row = runtime.bind_request(
                str(scan.id), payload.method, payload.url, payload.body_sha256
            )
            return {"allowed": True, "dispatch_id": row.id if row else None}
        runtime.record_response(str(scan.id), payload.dispatch_id, payload.response_status)
        return {"allowed": True}
    except (ValueError, PermissionError):
        return deny
