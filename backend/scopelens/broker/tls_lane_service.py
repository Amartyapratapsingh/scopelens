"""TLS measurement lane service (Build Plan §5.3).

A separate process from the API because it needs a different network position: it must
reach the target directly, while the API must not. Keeping it separate means the API's
network policy stays "no direct egress" and the one component with a route out has a
single, auditable job.

Authorization is not optional here. The lane asks the same question the HTTP lane asks —
is this destination inside this scan's scope, under a live lease, with budget left? — and
refuses otherwise. Without that check this service would be an unauthenticated internet
reachability probe on the control network.
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, FastAPI, status
from pydantic import BaseModel, ConfigDict, Field

from scopelens.adapters.scanners import ScannerResult
from scopelens.api.deps import AppSettings, DbSession
from scopelens.broker.policy import BrokerRequest, authorize, scan_for_token
from scopelens.broker.tls_lane import TLSFacts, measure_tls
from scopelens.scope.dns import SystemResolver

logger = logging.getLogger(__name__)

router = APIRouter(tags=["internal"])


class MeasureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    egress_token: str = Field(min_length=1)
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)


class MeasureResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    detail: str = ""
    facts: TLSFacts | None = None


@router.post("/measure", response_model=MeasureResponse)
def measure(payload: MeasureRequest, session: DbSession, settings: AppSettings) -> MeasureResponse:
    """Measure the real upstream certificate, if the destination is authorized.

    The destination is authorized by reusing the HTTP lane's decision function: an
    ``https`` request against the same host and port. That keeps one authorization
    implementation rather than two that can disagree.
    """

    class HandshakeDenied(RuntimeError):
        pass

    def admit_handshake() -> str:
        session.expire_all()
        decision = authorize(
            session,
            settings=settings,
            request=BrokerRequest(
                method="CONNECT",
                scheme="https",
                host=payload.host,
                port=payload.port,
                path="/",
                egress_token=payload.egress_token,
            ),
            resolver=SystemResolver(),
        )
        session.commit()
        if not decision.allowed or not decision.addresses:
            raise HandshakeDenied(str(decision.reason))
        import time

        time.sleep(float(decision.extra.get("wait_seconds", 0)))
        return decision.addresses[0]

    scan = scan_for_token(session, payload.egress_token)
    ca_file = None
    if scan is not None and scan.scope_version.authority_domain == "lab":
        ca_file = str(settings.tls_lab_ca_file) if settings.tls_lab_ca_file else None
    session.rollback()
    try:
        facts = measure_tls(
            payload.host, payload.port, ca_file=ca_file, authorize_handshake=admit_handshake
        )
    except HandshakeDenied as exc:
        return MeasureResponse(allowed=False, reason=str(exc))
    return MeasureResponse(allowed=True, reason="measured", facts=facts)


app = FastAPI(
    title="ScopeLens TLS measurement lane", docs_url=None, redoc_url=None, openapi_url=None
)
app.include_router(router)


class TLSLaneClient:
    """What the supervisor uses to ask the lane for a measurement."""

    def __init__(self, base_url: str, *, timeout: float = 30.0) -> None:
        self._url = base_url.rstrip("/") + "/measure"
        self._timeout = timeout

    def measure(self, *, egress_token: str, host: str, port: int) -> TLSFacts | None:
        """Return facts, or None when the lane refused or was unreachable.

        A refusal is not raised: it is a normal authorization outcome the caller records
        as a blocked measurement rather than a crash.
        """
        try:
            response = httpx.post(
                self._url,
                json={"egress_token": egress_token, "host": host, "port": port},
                timeout=self._timeout,
                # The lane is a control-plane service on the internal network, not target
                # traffic. The supervisor runs with HTTP_PROXY/HTTPS_PROXY set so that any
                # accidental egress is forced through the broker, and httpx honours those
                # variables by default — which sent this call to the forward proxy, where it
                # was refused as out of scope. Bypassing the proxy here is deliberate: the
                # call still carries the scan's egress token, and the lane authorizes with it.
                trust_env=False,
            )
        except httpx.HTTPError as exc:
            # Logged, not swallowed. An unreachable lane and a refusing lane are different
            # problems and the control's report can only say "no measurement" — this is where
            # the difference is visible.
            logger.warning("tls lane unreachable at %s: %s", self._url, exc)
            return None

        if response.status_code != status.HTTP_200_OK:
            logger.warning("tls lane returned HTTP %s; no measurement taken", response.status_code)
            return None

        body = response.json()
        if not body.get("allowed") or not body.get("facts"):
            # Logged rather than swallowed: a control that cannot be assessed must be able to
            # say why, and "the lane said no" without the reason is not an explanation.
            logger.warning(
                "tls lane took no measurement: reason=%s detail=%s",
                body.get("reason"),
                body.get("detail"),
            )
            return None
        return TLSFacts(**body["facts"])


@app.post("/testssl", response_model=ScannerResult)
def measure_testssl(payload: MeasureRequest, settings: AppSettings):
    from scopelens.broker.tls_tool import run_testssl
    from scopelens.execution.leases import lease_is_live
    from scopelens.persistence.session import session_scope

    def live():
        with session_scope(settings) as db:
            scan = scan_for_token(db, payload.egress_token)
            return bool(
                scan
                and not scan.cancel_requested_at
                and scan.cancel_epoch == scan.egress_token_epoch
                and lease_is_live(db, scan.id)
            )

    def admit():
        with session_scope(settings) as db:
            decision = authorize(
                db,
                settings=settings,
                request=BrokerRequest(
                    method="CONNECT",
                    scheme="https",
                    host=payload.host,
                    port=payload.port,
                    path="/",
                    egress_token=payload.egress_token,
                ),
                resolver=SystemResolver(),
            )
        if not decision.allowed or not decision.addresses:
            raise RuntimeError("TLS connection denied")
        import time

        time.sleep(float(decision.extra.get("wait_seconds", 0)))
        return decision.addresses[0]

    with session_scope(settings) as db:
        scan = scan_for_token(db, payload.egress_token)
        if (
            scan is None
            or scan.scope_version.scheme != "https"
            or payload.host != scan.scope_version.host
            or payload.port != scan.scope_version.port
        ):
            return {
                "tool": "testssl",
                "version": "3.2.4",
                "state": "not_tested",
                "errors": ["TLS target outside scope"],
            }
    if not live():
        return {
            "tool": "testssl",
            "version": "3.2.4",
            "state": "not_tested",
            "errors": ["revoked or unknown scan"],
        }
    return run_testssl(payload.host, payload.port, admit, live).model_dump()
