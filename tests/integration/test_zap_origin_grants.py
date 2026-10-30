"""Synthetic origin-bound grants: no native scan or external target traffic."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from scopelens.adapters.zap_active import ActiveRuleTask, OriginScopedRulePin
from scopelens.broker.policy import issue_egress_token, revoke_egress
from scopelens.broker.zap_task import (
    TaskGrantDenied,
    authorize_task,
    grant_live,
    issue_grant,
    sign_request,
)
from scopelens.domain.enums import ProfileName
from scopelens.domain.scope import ProductionScopeCreate
from scopelens.execution.leases import acquire_lease
from scopelens.execution.ledger import create_scan_with_task
from scopelens.persistence.repositories import create_scope_version
from scopelens.scope.dns import StaticResolver

pytestmark = pytest.mark.db
WORKER = "a" * 64


@pytest.fixture
def origin_grant(settings, db_session, seeded_operator, tmp_path, monkeypatch):
    monkeypatch.setattr("scopelens.adapters.zap_active.REVIEWED_RULES", {})
    now = datetime.now(UTC)
    operator_id, _ = seeded_operator
    row = create_scope_version(
        db_session,
        operator_id=operator_id,
        payload=ProductionScopeCreate(
            host="owned.example",
            scheme="https",
            port=443,
            allowed_check_profile=ProfileName.EXTERNAL_DAST,
            authorization_expires_at=now + timedelta(days=30),
        ),
        scheme="https",
        host="owned.example",
        port=443,
        lab_binding=None,
    )
    scan, _ = create_scan_with_task(
        db_session, operator_id=operator_id, scope_version=row, score_version=settings.score_version
    )
    issue_egress_token(db_session, scan=scan)
    acquire_lease(db_session, scan_id=scan.id, holder="fixture", ttl_seconds=300)
    db_session.commit()
    pin = OriginScopedRulePin(
        rule_id="40012",
        control_id="SL-C03-XSS-01",
        engine_version="fixture-only",
        engine_sha256="2" * 64,
        rule_config_sha256="1" * 64,
        allowed_values=("marker-one", "marker-two"),
        max_requests=2,
        deadline_seconds=5,
        approved_origins=[{"scheme": "https", "host": "owned.example", "port": 443}],
        approval={
            "operator": "Fixture operator",
            "date": "2026-10-11",
            "decision": "Synthetic authorization test only.",
        },
    )
    path = tmp_path / "approved.json"
    path.write_text(
        json.dumps(
            {"version": "zap-active-allowlist-v2", "approved_rules": [pin.model_dump(mode="json")]}
        )
    )
    config = settings.model_copy(
        update={
            "zap_active_lab_enabled": True,
            "zap_active_signing_key": SecretStr("k" * 32),
            "zap_active_allowlist_file": path,
        }
    )
    task = ActiveRuleTask(
        scan_id=str(scan.id),
        task_id="origin-task",
        input_id="input",
        rule_id="40012",
        url="https://owned.example/active/xss?q=marker-one",
        input_name="q",
        rule_config_sha256=pin.rule_config_sha256,
        max_requests=2,
        deadline_seconds=5,
    )
    grant = issue_grant(
        db_session, settings=config, scan_id=scan.id, task=task, worker_id=WORKER, now=now
    )
    db_session.commit()
    return SimpleNamespace(
        config=config,
        scan=scan,
        task=task,
        pin=pin,
        path=path,
        grant=grant,
        now=now,
        resolver=StaticResolver({"owned.example": ["93.184.216.34"]}),
    )


def signed(p, *, url=None, worker=WORKER):
    return sign_request(
        p.config, p.grant, scan_id=p.scan.id, worker_id=worker, method="GET", url=url or p.task.url
    )


def admit(p, session, request, *, now=None):
    return authorize_task(
        session, settings=p.config, request=request, resolver=p.resolver, now=now or p.now
    )


def test_v2_https_request_admits_and_spends_both_budgets(origin_grant, db_session):
    p = origin_grant
    request = signed(p)
    assert admit(p, db_session, request).allowed
    db_session.commit()
    assert grant_live(db_session, settings=p.config, signed=request, now=p.now)
    db_session.refresh(p.scan)
    assert p.scan.assessment_plan["zap_active_grants"][p.grant["grant_id"]]["requests"] == 1
    assert p.scan.budget_reserved["requests"] == 1


@pytest.mark.parametrize(
    "url",
    [
        "https://other.example/active/xss?q=marker-one",
        "http://owned.example/active/xss?q=marker-one",
        "https://owned.example:444/active/xss?q=marker-one",
    ],
)
def test_v2_broker_denies_other_scheme_host_port_before_any_budget(origin_grant, db_session, url):
    p = origin_grant
    request = signed(p, url=url)
    assert not admit(p, db_session, request).allowed
    assert not grant_live(
        db_session, settings=p.config, signed=request, require_admitted=False, now=p.now
    )
    db_session.refresh(p.scan)
    assert p.scan.assessment_plan["zap_active_grants"][p.grant["grant_id"]]["requests"] == 0
    assert p.scan.budget_reserved.get("requests", 0) == 0


@pytest.mark.parametrize("fault", ["origin_removed", "approval_changed", "empty", "v1"])
def test_approval_revocation_or_manifest_downgrade_revokes_existing_grant(
    origin_grant, db_session, fault
):
    p = origin_grant
    request = signed(p)
    assert admit(p, db_session, request).allowed
    db_session.commit()
    row = p.pin.model_dump(mode="json")
    version = "zap-active-allowlist-v2"
    if fault == "origin_removed":
        row["approved_origins"][0]["host"] = "other.example"
    elif fault == "approval_changed":
        row["approval"]["decision"] += " changed"
    elif fault == "v1":
        version = "zap-active-allowlist-v1"
        del row["approved_origins"], row["approval"]
    p.path.write_text(
        json.dumps({"version": version, "approved_rules": [] if fault == "empty" else [row]})
    )
    assert not grant_live(db_session, settings=p.config, signed=request, now=p.now)
    assert not admit(p, db_session, signed(p)).allowed
    if fault == "approval_changed":
        # A newly approved record may authorize a distinct future task, never revive
        # an old grant. Even after pin changes the old task tombstone forbids reissue.
        with pytest.raises(TaskGrantDenied, match="reissued"):
            issue_grant(
                db_session,
                settings=p.config,
                scan_id=p.scan.id,
                task=p.task,
                worker_id=WORKER,
                now=p.now,
            )
    else:
        with pytest.raises(TaskGrantDenied):
            issue_grant(
                db_session,
                settings=p.config,
                scan_id=p.scan.id,
                task=p.task.model_copy(update={"task_id": "new"}),
                worker_id=WORKER,
                now=p.now,
            )


@pytest.mark.parametrize("fault", ["worker", "cancel", "deadline", "budget"])
def test_v2_retains_worker_cancel_deadline_and_task_budget(origin_grant, db_session, fault):
    p = origin_grant
    now = p.now
    if fault == "cancel":
        revoke_egress(db_session, scan=p.scan)
        db_session.commit()
    elif fault == "deadline":
        now += timedelta(seconds=5)
    elif fault == "budget":
        assert admit(p, db_session, signed(p)).allowed
        db_session.commit()
        assert admit(p, db_session, signed(p)).allowed
        db_session.commit()
    assert not admit(
        p, db_session, signed(p, worker="b" * 64 if fault == "worker" else WORKER), now=now
    ).allowed
