"""Staged broker grants; fixture pins do not execute or qualify ZAP."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import SecretStr

from scopelens.adapters.zap_active import REVIEWED_RULES, ActiveRulePin, ActiveRuleTask
from scopelens.broker.policy import revoke_egress
from scopelens.broker.zap_task import (
    TaskGrantDenied,
    authorize_task,
    close_grant,
    issue_grant,
    sign_request,
)
from scopelens.domain.enums import ProfileName
from scopelens.execution.coordinator import _prepare
from scopelens.persistence.models import ScopeVersionRow

pytestmark = pytest.mark.db
WORKER = "a" * 64


@pytest.fixture
def prepared(settings, queued_scan, db_session, monkeypatch):
    from scopelens.domain.lab import LabBinding
    from scopelens.domain.scope import LabScopeCreate
    from scopelens.execution.ledger import create_scan_with_task
    from scopelens.persistence.repositories import create_scope_version

    old_scan, _ = queued_scan
    old = db_session.get(ScopeVersionRow, old_scan.scope_version_id)
    row = create_scope_version(
        db_session,
        operator_id=old_scan.operator_id,
        payload=LabScopeCreate(
            lab_service="labs-bad",
            scheme="http",
            lab_port=80,
            allowed_check_profile=ProfileName.EXTERNAL_ACTIVE_V2,
            authorization_expires_at=datetime.now(UTC) + timedelta(days=30),
        ),
        scheme="http",
        host=old.host,
        port=80,
        lab_binding=LabBinding(
            service="labs-bad", address=old.host, port=80, environment="docker-compose-labs"
        ),
    )
    scan, root_task = create_scan_with_task(
        db_session,
        operator_id=old_scan.operator_id,
        scope_version=row,
        score_version=settings.score_version,
    )
    db_session.commit()
    _, scope, _, _ = _prepare(settings, scan_id=scan.id, task_id=root_task.id)
    configured = settings.model_copy(
        update={"zap_active_lab_enabled": True, "zap_active_signing_key": SecretStr("k" * 32)}
    )
    task = ActiveRuleTask(
        scan_id=str(scan.id),
        task_id="fixture-input-task",
        input_id="fixture-input",
        rule_id="40012",
        url=scope.origin + "/search?q=baseline&fixed=ordinary",
        input_name="q",
        rule_config_sha256="1" * 64,
        max_requests=2,
        deadline_seconds=5,
    )
    pin = ActiveRulePin(
        rule_id="40012",
        control_id="SL-C03-XSS-01",
        engine_version="fixture-only",
        engine_sha256="2" * 64,
        rule_config_sha256="1" * 64,
        allowed_values=("marker-one", "marker-two"),
        max_requests=2,
        deadline_seconds=5,
    )
    monkeypatch.setitem(REVIEWED_RULES, pin.rule_id, pin)
    now = datetime.now(UTC)
    grant = issue_grant(
        db_session, settings=configured, scan_id=scan.id, task=task, worker_id=WORKER, now=now
    )
    db_session.commit()
    return SimpleNamespace(settings=configured, scan=scan, task=task, grant=grant, now=now)


def request(p, **kwargs):
    return sign_request(
        p.settings,
        p.grant,
        scan_id=p.scan.id,
        worker_id=kwargs.pop("worker_id", WORKER),
        method=kwargs.pop("method", "GET"),
        url=kwargs.pop("url", p.task.url.replace("baseline", "marker-one")),
        **kwargs,
    )


def decide(p, session, signed, **kwargs):
    return authorize_task(
        session,
        settings=p.settings,
        request=signed,
        resolver=None,
        now=kwargs.pop("now", p.now),
        **kwargs,
    )


def test_authenticated_exact_request_spends_task_and_scan_budgets(prepared, db_session):
    p = prepared
    assert decide(p, db_session, request(p)).allowed
    db_session.commit()
    db_session.refresh(p.scan)
    assert p.scan.assessment_plan["zap_active_grants"][p.grant["grant_id"]]["requests"] == 1
    assert p.scan.budget_reserved["requests"] == 2
    assert decide(p, db_session, request(p)).allowed
    db_session.commit()
    assert not decide(p, db_session, request(p)).allowed


@pytest.mark.parametrize(
    "fault",
    [
        "origin",
        "path",
        "fixed_input",
        "payload",
        "body",
        "method",
        "worker",
        "task",
        "scope",
        "rule",
        "signature",
        "token",
        "expiry",
        "closed",
        "cancel",
        "pin",
    ],
)
def test_grant_refuses_scope_lifetime_and_authenticated_principal_substitution(
    prepared, db_session, fault
):
    p = prepared
    kwargs = {}
    if fault == "origin":
        signed = request(p, url="http://172.28.0.10/search?q=marker-one&fixed=ordinary")
    elif fault == "path":
        signed = request(
            p, url=p.task.url.replace("/search", "/admin").replace("baseline", "marker-one")
        )
    elif fault == "fixed_input":
        signed = request(
            p, url=p.task.url.replace("ordinary", "changed").replace("baseline", "marker-one")
        )
    elif fault == "payload":
        signed = request(p, url=p.task.url.replace("baseline", "unreviewed"))
    elif fault == "body":
        signed = request(p, body=b"unexpected")
        kwargs["body"] = b"unexpected"
    elif fault == "method":
        signed = request(p, method="POST")
    elif fault == "worker":
        # Even a valid supervisor signature for another principal cannot borrow the grant.
        signed = request(p, worker_id="b" * 64)
    elif fault in {"token", "task", "scope", "rule"}:
        other = {**p.grant, "task": dict(p.grant["task"])}
        if fault == "token":
            other["token"] = "wrong-token"
        elif fault == "scope":
            other["scope_version_id"] = str(uuid4())
        else:
            other["task"]["task_id" if fault == "task" else "rule_id"] = "different"
        signed = sign_request(
            p.settings,
            other,
            scan_id=p.scan.id,
            worker_id=WORKER,
            method="GET",
            url=p.task.url.replace("baseline", "marker-one"),
        )
    else:
        signed = request(p)
        if fault == "signature":
            signed = signed.model_copy(update={"signature": "different"})
        elif fault == "expiry":
            kwargs["now"] = p.now + timedelta(seconds=5)
        elif fault == "closed":
            close_grant(
                db_session, scan_id=p.scan.id, grant_id=p.grant["grant_id"], worker_id=WORKER
            )
            db_session.commit()
        elif fault == "cancel":
            revoke_egress(db_session, scan=p.scan)
            db_session.commit()
        elif fault == "pin":
            REVIEWED_RULES[p.task.rule_id] = REVIEWED_RULES[p.task.rule_id].model_copy(
                update={"engine_sha256": "f" * 64}
            )
    assert not decide(p, db_session, signed, **kwargs).allowed
    db_session.refresh(p.scan)
    assert p.scan.budget_reserved.get("requests", 0) == 1


def test_signed_request_nonce_cannot_be_replayed(prepared, db_session):
    p = prepared
    signed = request(p)
    assert decide(p, db_session, signed).allowed
    db_session.commit()
    assert not decide(p, db_session, signed).allowed


def test_external_dast_and_task_reissue_remain_blocked(prepared, db_session):
    p = prepared
    with pytest.raises(TaskGrantDenied, match="reissued"):
        issue_grant(
            db_session, settings=p.settings, scan_id=p.scan.id, task=p.task, worker_id=WORKER
        )
    p.scan.profile = ProfileName.EXTERNAL_DAST.value
    db_session.commit()
    with pytest.raises(TaskGrantDenied, match="authority"):
        issue_grant(
            db_session, settings=p.settings, scan_id=p.scan.id, task=p.task, worker_id=WORKER
        )


def test_concurrent_task_budget_is_serialized_at_broker(prepared, db_session, engine):
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy.orm import Session

    p = prepared
    db_session.commit()
    messages = [request(p) for _ in range(5)]

    def consume(signed):
        with Session(engine) as independent:
            result = decide(p, independent, signed)
            independent.commit()
            return result.allowed

    with ThreadPoolExecutor(max_workers=5) as pool:
        allowed = list(pool.map(consume, messages))
    assert sum(allowed) == 2
    db_session.refresh(p.scan)
    assert p.scan.assessment_plan["zap_active_grants"][p.grant["grant_id"]]["requests"] == 2
    assert p.scan.budget_reserved["requests"] == 3


def test_feature_disabled_refuses_signed_grant(prepared, db_session):
    p = prepared
    signed = request(p)
    disabled = p.settings.model_copy(update={"zap_active_lab_enabled": False})
    assert not authorize_task(
        db_session, settings=disabled, request=signed, resolver=None, now=p.now
    ).allowed


def test_scan_budget_exhaustion_denies_without_spending_task(prepared, db_session):
    from scopelens.execution.ledger import budget_limits_for

    p = prepared
    scope = db_session.get(ScopeVersionRow, p.scan.scope_version_id)
    limits = budget_limits_for(scope, p.settings)
    p.scan.budget_spent = {"requests": limits.max_requests}
    db_session.commit()
    assert not decide(p, db_session, request(p)).allowed
    db_session.refresh(p.scan)
    assert p.scan.assessment_plan["zap_active_grants"][p.grant["grant_id"]]["requests"] == 0


def test_private_grant_never_appears_in_report(prepared, authed_client):
    response = authed_client.get(f"/api/scans/{prepared.scan.id}/export.json")
    assert response.status_code == 200
    assert "zap_active_grants" not in response.json()["assessment_plan"]
    assert prepared.grant["token"] not in response.text


def test_rate_delay_cannot_extend_task_deadline(prepared, db_session):
    p = prepared
    p.scan.assessment_plan = {
        **p.scan.assessment_plan,
        "next_request_at": (p.now + timedelta(seconds=5)).isoformat(),
    }
    db_session.commit()
    assert not decide(p, db_session, request(p)).allowed
    db_session.refresh(p.scan)
    assert p.scan.assessment_plan["zap_active_grants"][p.grant["grant_id"]]["requests"] == 0


def test_valid_signature_cannot_borrow_grant_for_another_scan(prepared, queued_scan, db_session):
    p = prepared
    other_scan, _ = queued_scan
    signed = sign_request(
        p.settings,
        p.grant,
        scan_id=other_scan.id,
        worker_id=WORKER,
        method="GET",
        url=p.task.url.replace("baseline", "marker-one"),
    )
    assert not decide(p, db_session, signed).allowed


def test_liveness_requires_admission_and_revokes_on_close(prepared, db_session):
    from scopelens.broker.zap_task import grant_live

    p = prepared
    signed = request(p)
    assert not grant_live(db_session, settings=p.settings, signed=signed, now=p.now)
    assert grant_live(
        db_session, settings=p.settings, signed=signed, require_admitted=False, now=p.now
    )
    assert decide(p, db_session, signed).allowed
    db_session.commit()
    assert grant_live(db_session, settings=p.settings, signed=signed, now=p.now)
    assert not grant_live(
        db_session, settings=p.settings, signed=signed, now=p.now + timedelta(seconds=5)
    )
    close_grant(db_session, scan_id=p.scan.id, grant_id=p.grant["grant_id"], worker_id=WORKER)
    db_session.commit()
    assert not grant_live(db_session, settings=p.settings, signed=signed, now=p.now)


def test_admitted_request_liveness_revoked_on_cancel(prepared, db_session):
    from scopelens.broker.zap_task import grant_live

    p = prepared
    signed = request(p)
    assert decide(p, db_session, signed).allowed
    db_session.commit()
    revoke_egress(db_session, scan=p.scan)
    db_session.commit()
    assert not grant_live(db_session, settings=p.settings, signed=signed, now=p.now)


@pytest.mark.parametrize("fault", ["token", "method", "url", "body"])
def test_internal_task_route_binds_actual_proxy_request(prepared, db_session, fault):
    from scopelens.api.internal import ZapTaskRequest, zap_task_authorize

    p = prepared
    signed = request(p)
    payload = {
        "signed": signed,
        "egress_token": "wrong-token",
        "method": signed.method,
        "url": signed.url,
        "body_sha256": signed.body_sha256,
    }
    if fault != "token":
        from scopelens.broker.policy import issue_egress_token

        payload["egress_token"] = issue_egress_token(db_session, scan=p.scan)
        if fault == "method":
            payload["method"] = "POST"
        if fault == "url":
            payload["url"] = signed.url.replace("/search", "/admin")
        if fault == "body":
            payload["body_sha256"] = "f" * 64
        db_session.commit()
    assert not zap_task_authorize(ZapTaskRequest(**payload), db_session, p.settings)["allowed"]
