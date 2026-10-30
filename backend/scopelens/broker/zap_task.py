"""Origin-scoped task grants for supervisor-mediated native ZAP.

Requests require a signature over the actual Docker child-container identity,
task, scope and exact request. The key and grant token remain outside the
network-none scanner worker. Closed task tombstones prohibit replay/reissue.
"""

import hashlib
import hmac
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from scopelens.adapters.zap_active import ActiveRuleTask, reviewed_rule, rule_authorized_for_scope
from scopelens.broker.policy import (
    BrokerDecision,
    BrokerRequest,
    DenialReason,
    _authorize_known_scan,
    _record_decision,
)
from scopelens.domain.budget import BudgetExceeded
from scopelens.domain.capabilities import canonical_sha256
from scopelens.domain.enums import ScanStatus
from scopelens.execution.leases import lease_is_live
from scopelens.execution.ledger import budget_limits_for
from scopelens.persistence.models import ScanRow, ScopeVersionRow
from scopelens.persistence.repositories import scope_row_to_domain
from scopelens.scope.dns import ResolverError
from scopelens.scope.validator import ScopeViolation

PRIVATE_PLAN_KEY = "zap_active_grants"
ZAP_TASK_HEADER = "x-scopelens-zap-task"


class TaskGrantDenied(ValueError):
    """A staged grant cannot authorize this action."""


class SignedTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scan_id: UUID
    scope_version_id: UUID
    grant_id: str
    task_id: str
    worker_id: str
    rule_id: str
    method: str
    url: str
    body_sha256: str
    nonce: str = Field(min_length=16, max_length=128)
    token: str = Field(repr=False)
    signature: str = Field(repr=False)


def _key(settings):
    key = settings.zap_active_signing_key
    if not settings.zap_active_lab_enabled or key is None:
        raise TaskGrantDenied("lab ZAP task grants disabled")
    return key.get_secret_value().encode()


def _signature(key, payload):
    return hmac.new(
        key, ("scopelens-zap-request-v1:" + canonical_sha256(payload)).encode(), hashlib.sha256
    ).hexdigest()


def _live(session, scan, scope, now):
    return (
        not scan.cancel_requested_at
        and scan.cancel_epoch == scan.egress_token_epoch
        and not ScanStatus(scan.status).is_terminal
        and not scope.is_expired(now)
        and lease_is_live(session, scan.id, now=now)
    )


def issue_grant(session, *, settings, scan_id, task, worker_id, now=None):
    """Trusted supervisor only, after creating the exact child container.

    This does not enable a launcher or ordinary proxy use. Only reviewed pins and
    lab active-v2 scopes or explicitly origin-approved external-dast scopes are admissible.
    """
    _key(settings)
    now = now or datetime.now(UTC)
    task = ActiveRuleTask.model_validate(task)
    scan = session.scalar(
        select(ScanRow)
        .where(ScanRow.id == scan_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if scan is None:
        raise TaskGrantDenied("scan missing")
    scope = scope_row_to_domain(session.get(ScopeVersionRow, scan.scope_version_id))
    if (
        not _live(session, scan, scope, now)
        or task.scan_id != str(scan.id)
        or len(worker_id) != 64
        or any(c not in "0123456789abcdef" for c in worker_id)
    ):
        raise TaskGrantDenied("lab task authority unavailable")
    pin = reviewed_rule(task.rule_id, settings)
    destination = urlsplit(task.url)
    if (
        not rule_authorized_for_scope(pin, scope, profile=scan.profile, url=task.url)
        or task.rule_config_sha256 != pin.rule_config_sha256
        or task.max_requests > pin.max_requests
        or task.deadline_seconds > pin.deadline_seconds
        or destination.scheme != scope.scheme
        or destination.hostname != scope.host
        or (destination.port or (443 if destination.scheme == "https" else 80)) != scope.port
    ):
        raise TaskGrantDenied("unreviewed rule, origin authority or task destination/limits")
    grants = dict((scan.assessment_plan or {}).get(PRIVATE_PLAN_KEY, {}))
    if any(row["task"]["task_id"] == task.task_id for row in grants.values()):
        raise TaskGrantDenied("task grant cannot be reissued")
    deadline = min(
        scope.authorization_expires_at,
        now + timedelta(seconds=task.deadline_seconds),
        (scan.started_at or now)
        + timedelta(
            seconds=budget_limits_for(
                session.get(ScopeVersionRow, scan.scope_version_id), settings
            ).wall_clock_seconds
        ),
    )
    if deadline <= now:
        raise TaskGrantDenied("scan wall-clock budget exhausted")
    ident, token = secrets.token_hex(16), secrets.token_urlsafe(32)
    grants[ident] = {
        "task": task.model_dump(mode="json"),
        "scope_version_id": str(scope.id),
        "worker_id": worker_id,
        "cancel_epoch": scan.cancel_epoch,
        "pin_sha256": canonical_sha256(pin.model_dump(mode="json")),
        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "expires_at": deadline.isoformat(),
        "state": "open",
        "requests": 0,
        "nonces": [],
    }
    scan.assessment_plan = {**(scan.assessment_plan or {}), PRIVATE_PLAN_KEY: grants}
    session.flush()
    return {"grant_id": ident, "token": token, **grants[ident]}


def sign_request(settings, grant, *, scan_id, worker_id, method, url, body=b"", nonce=None):
    """Trusted channel adapter must pass container.id, never a worker-supplied ID."""
    payload = {
        "scan_id": str(scan_id),
        "scope_version_id": grant["scope_version_id"],
        "grant_id": grant["grant_id"],
        "task_id": grant["task"]["task_id"],
        "worker_id": worker_id,
        "rule_id": grant["task"]["rule_id"],
        "method": method,
        "url": url,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "nonce": nonce or secrets.token_hex(16),
        "token": grant["token"],
    }
    return SignedTaskRequest(**payload, signature=_signature(_key(settings), payload))


def authorize_task(session, *, settings, request, resolver, body=b"", now=None):
    """Atomic task and scan budgets. Call only from an authenticated trusted channel."""
    now = now or datetime.now(UTC)
    denied = BrokerDecision.deny(DenialReason.DESTINATION_REFUSED, "ZAP task grant refused")
    try:
        request = SignedTaskRequest.model_validate(request)
        payload = request.model_dump(mode="json", exclude={"signature"})
        if not hmac.compare_digest(request.signature, _signature(_key(settings), payload)):
            return denied
        scan = session.scalar(
            select(ScanRow)
            .where(ScanRow.id == request.scan_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if scan is None:
            return denied
        scope = scope_row_to_domain(session.get(ScopeVersionRow, scan.scope_version_id))
        grants = dict((scan.assessment_plan or {}).get(PRIVATE_PLAN_KEY, {}))
        grant = dict(grants.get(request.grant_id, {}))
        if not grant:
            return denied
        task = ActiveRuleTask.model_validate(grant["task"])
        pin = reviewed_rule(task.rule_id, settings)
        if (
            not rule_authorized_for_scope(pin, scope, profile=scan.profile, url=request.url)
            or not _live(session, scan, scope, now)
            or request.scope_version_id != scan.scope_version_id
            or grant["scope_version_id"] != str(scan.scope_version_id)
            or grant["cancel_epoch"] != scan.cancel_epoch
            or grant["worker_id"] != request.worker_id
            or task.task_id != request.task_id
            or task.rule_id != request.rule_id
            or pin is None
            or grant["pin_sha256"] != canonical_sha256(pin.model_dump(mode="json"))
            or task.rule_config_sha256 != pin.rule_config_sha256
            or grant["state"] != "open"
            or now >= datetime.fromisoformat(grant["expires_at"])
            or grant["requests"] >= task.max_requests
            or request.nonce in grant["nonces"]
            or body
            or request.body_sha256 != hashlib.sha256(body).hexdigest()
            or not hmac.compare_digest(
                grant["token_sha256"], hashlib.sha256(request.token.encode()).hexdigest()
            )
            or not task.accepts(request.method, request.url, body, pin)
        ):
            return denied
        # Shared rate scheduling cannot defer an admitted task beyond its expiry.
        due = (scan.assessment_plan or {}).get("next_request_at")
        if due and datetime.fromisoformat(due) >= datetime.fromisoformat(grant["expires_at"]):
            return denied
        part = urlsplit(request.url)
        broker_request = BrokerRequest(
            method=request.method,
            scheme=part.scheme,
            host=part.hostname,
            port=part.port or (443 if part.scheme == "https" else 80),
            path=part.path + ("?" + part.query if part.query else ""),
            egress_token="",
        )
        decision = _authorize_known_scan(session, settings, broker_request, resolver, now, scan)
        decision = replace(
            decision,
            scan_id=str(scan.id),
            extra={
                **decision.extra,
                "task_expires_at": grant["expires_at"],
                "task_remaining_seconds": str(
                    max(0, (datetime.fromisoformat(grant["expires_at"]) - now).total_seconds())
                ),
            },
        )
        _record_decision(session, broker_request, decision)
        if not decision.allowed:
            return decision
        grant["requests"] += 1
        grant["nonces"] = [*grant["nonces"], request.nonce]
        grants[request.grant_id] = grant
        scan.assessment_plan = {**scan.assessment_plan, PRIVATE_PLAN_KEY: grants}
        session.flush()
        return decision
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        BudgetExceeded,
        ResolverError,
        ScopeViolation,
    ):
        return denied


def close_grant(session, *, scan_id, grant_id, worker_id):
    scan = session.scalar(
        select(ScanRow)
        .where(ScanRow.id == scan_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if scan is None:
        raise TaskGrantDenied("scan missing")
    grants = dict((scan.assessment_plan or {}).get(PRIVATE_PLAN_KEY, {}))
    grant = dict(grants.get(grant_id, {}))
    if not grant or grant["worker_id"] != worker_id:
        raise TaskGrantDenied("task grant ownership mismatch")
    grant["state"] = "closed"
    grants[grant_id] = grant
    scan.assessment_plan = {**scan.assessment_plan, PRIVATE_PLAN_KEY: grants}
    session.flush()


def grant_live(session, *, settings, signed, require_admitted=True, now=None):
    """Recheck at transmission time; this never authorizes an additional request.

    The proxy must pass the same signed request after rate scheduling. A supervisor
    may check an issued grant before any request with require_admitted=False.
    """
    now = now or datetime.now(UTC)
    try:
        signed = SignedTaskRequest.model_validate(signed)
        payload = signed.model_dump(mode="json", exclude={"signature"})
        if not hmac.compare_digest(signed.signature, _signature(_key(settings), payload)):
            return False
        scan = session.get(ScanRow, signed.scan_id)
        if scan is None:
            return False
        scope = scope_row_to_domain(session.get(ScopeVersionRow, scan.scope_version_id))
        grant = (scan.assessment_plan or {}).get(PRIVATE_PLAN_KEY, {}).get(signed.grant_id)
        if not grant:
            return False
        task = ActiveRuleTask.model_validate(grant["task"])
        pin = reviewed_rule(task.rule_id, settings)
        return bool(
            rule_authorized_for_scope(pin, scope, profile=scan.profile, url=signed.url)
            and _live(session, scan, scope, now)
            and signed.scope_version_id == scan.scope_version_id
            and grant["scope_version_id"] == str(scan.scope_version_id)
            and grant["cancel_epoch"] == scan.cancel_epoch
            and grant["worker_id"] == signed.worker_id
            and task.task_id == signed.task_id
            and task.rule_id == signed.rule_id
            and pin is not None
            and grant["pin_sha256"] == canonical_sha256(pin.model_dump(mode="json"))
            and grant["state"] == "open"
            and now < datetime.fromisoformat(grant["expires_at"])
            and (not require_admitted or signed.nonce in grant["nonces"])
            and signed.body_sha256 == hashlib.sha256(b"").hexdigest()
            and hmac.compare_digest(
                grant["token_sha256"], hashlib.sha256(signed.token.encode()).hexdigest()
            )
            and task.accepts(signed.method, signed.url, b"", pin)
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
