"""Reviewed probes spend request/task budgets without consuming crawl pages."""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from tests.integration.test_broker import (
    PUBLIC_V4,
    request_for,
    resolver_for,
)

from scopelens.broker.policy import authorize, issue_egress_token
from scopelens.broker.probe_tasks import conditional_reference
from scopelens.domain.enums import ProfileName
from scopelens.domain.scope import ProductionScopeCreate
from scopelens.execution.leases import acquire_lease
from scopelens.execution.ledger import create_scan_with_task
from scopelens.persistence.models import AuditEventRow
from scopelens.persistence.repositories import create_scope_version

pytestmark = pytest.mark.db
ENTRY = {"kind": "sql", "path": "/app/search", "parameter": "q"}


@pytest.fixture
def prepared(db_session, seeded_operator, settings, request):
    operator_id, _ = seeded_operator
    scope = create_scope_version(
        db_session,
        operator_id=operator_id,
        payload=ProductionScopeCreate(
            host="owned.example.com",
            scheme="https",
            port=443,
            allowed_path_prefixes=["/app"],
            excluded_paths=["/app/admin"],
            allowed_check_profile=(
                ProfileName.EXTERNAL_DAST
                if isinstance(getattr(request, "param", None), dict)
                else getattr(request, "param", ProfileName.EXTERNAL_DAST)
            ),
            budgets_override=request.param
            if isinstance(getattr(request, "param", None), dict)
            else {},
            authorization_expires_at=datetime.now(UTC) + timedelta(days=30),
        ),
        scheme="https",
        host="owned.example.com",
        port=443,
        lab_binding=None,
    )
    scan, _ = create_scan_with_task(
        db_session,
        operator_id=operator_id,
        scope_version=scope,
        score_version=settings.score_version,
        actor="test",
    )
    token = issue_egress_token(db_session, scan=scan)
    acquire_lease(db_session, scan_id=scan.id, holder="test", ttl_seconds=300)
    scan.assessment_plan = {"conditional_probes": [ENTRY]}
    db_session.commit()
    return scope, token, scan


def run_request(db_session, settings, prepared, path, probe_task=None):
    scope, token, _ = prepared
    # The new optional transport field is ignored by the baseline broker.
    request = SimpleNamespace(
        **{**asdict(request_for(scope, token, path=path)), "probe_task": probe_task}
    )
    return authorize(
        db_session, settings=settings, request=request, resolver=resolver_for(PUBLIC_V4)
    )


def small_limits(settings, **limits):
    return settings.model_copy(update={"budgets": settings.budgets.model_copy(update=limits)})


def test_exception_denial_retains_scan_audit(db_session, settings, prepared):
    _, _, scan = prepared
    settings = small_limits(settings, max_pages=1)
    assert run_request(db_session, settings, prepared, "/app/one").allowed
    decision = run_request(db_session, settings, prepared, "/app/two")
    assert decision.reason == "budget_exhausted"
    assert decision.scan_id == str(scan.id)
    rows = db_session.scalars(
        select(AuditEventRow).where(
            AuditEventRow.subject_id == str(scan.id), AuditEventRow.action == "broker.admit"
        )
    ).all()
    assert [r.outcome for r in rows] == ["allowed", "denied"]


def test_crawl_pages_exhausted_but_reviewed_query_uses_request_budget(
    db_session, settings, prepared
):
    settings = small_limits(settings, max_pages=2, max_total_requests=3)
    assert run_request(db_session, settings, prepared, "/app/search?q=bar").allowed
    assert run_request(db_session, settings, prepared, "/app/other").allowed
    scan = prepared[2]
    keys = list(scan.assessment_plan["page_request_keys"])
    reference = conditional_reference(ENTRY)
    assert run_request(db_session, settings, prepared, "/app/search?q=marker", reference).allowed
    assert scan.assessment_plan["page_request_keys"] == keys
    assert scan.assessment_plan["reviewed_probe_requests"] == {reference: 1}
    decision = run_request(db_session, settings, prepared, "/app/search?q=another", reference)
    assert not decision.allowed and decision.reason == "budget_exhausted"
    assert decision.scan_id == str(scan.id)
    assert scan.assessment_plan["reviewed_probe_requests"] == {reference: 1}


def test_ordinary_new_query_still_spends_crawl_page(db_session, settings, prepared):
    settings = small_limits(settings, max_pages=1)
    assert run_request(db_session, settings, prepared, "/app/search?q=bar").allowed
    denied = run_request(db_session, settings, prepared, "/app/search?q=new")
    assert not denied.allowed and denied.detail == "shared page cap reached"


@pytest.mark.parametrize(
    "path,reference",
    [
        ("/app/search?q=new", "purpose:probe"),
        ("/app/other?q=new", conditional_reference(ENTRY)),
        ("/app/search?other=new", conditional_reference(ENTRY)),
        ("/app/search?q=new&q=duplicate", conditional_reference(ENTRY)),
        ("/app/admin?q=new", conditional_reference(ENTRY)),
        ("/app/search?q=new", "conditional:" + "0" * 64),
    ],
)
def test_probe_annotation_cannot_grant_other_request(
    db_session, settings, prepared, path, reference
):
    decision = run_request(db_session, settings, prepared, path, reference)
    assert not decision.allowed
    assert "reviewed_probe_requests" not in prepared[2].assessment_plan


def test_existing_control_request_cap_is_enforced(db_session, settings, prepared):
    _, _, scan = prepared
    reference = conditional_reference(ENTRY)
    scan.assessment_plan = {**scan.assessment_plan, "reviewed_probe_requests": {reference: 36}}
    db_session.commit()
    denied = run_request(db_session, settings, prepared, "/app/search?q=marker", reference)
    assert not denied.allowed and denied.detail == "reviewed probe task request cap reached"


def test_scope_and_revocation_still_apply_to_valid_probe(db_session, settings, prepared):
    from scopelens.broker.policy import revoke_egress

    _, _, scan = prepared
    revoke_egress(db_session, scan=scan)
    decision = run_request(
        db_session, settings, prepared, "/app/search?q=marker", conditional_reference(ENTRY)
    )
    assert not decision.allowed and decision.reason == "revoked_egress_token"


@pytest.mark.parametrize(
    "error,reason",
    [
        ("scope", "destination_refused"),
        ("resolver", "resolution_failed"),
        ("unexpected", "broker_internal_error"),
    ],
)
def test_exception_paths_keep_known_scan_attribution(
    db_session, settings, prepared, monkeypatch, error, reason
):
    from scopelens.broker import policy
    from scopelens.scope.dns import ResolverError
    from scopelens.scope.validator import ScopeViolation

    exceptions = {"scope": ScopeViolation, "resolver": ResolverError, "unexpected": ValueError}

    def fail(*args, **kwargs):
        raise exceptions[error]("fixture failure")

    monkeypatch.setattr(policy, "_check_destination", fail)
    decision = run_request(db_session, settings, prepared, "/app/search?q=bar")
    assert decision.reason == reason
    assert decision.scan_id == str(prepared[2].id)
    audit = db_session.scalars(
        select(AuditEventRow).where(
            AuditEventRow.subject_id == decision.scan_id,
            AuditEventRow.action == "broker.admit",
        )
    ).one()
    assert audit.outcome == "denied" and audit.detail["reason"] == reason


@pytest.mark.parametrize("prepared", [ProfileName.EXTERNAL_ACTIVE_V2], indirect=True)
def test_expansion_probe_admitted_after_crawl_cap(db_session, settings, prepared):
    from tests.unit.test_reviewed_probe_authority import expanded_scan

    from scopelens.broker.probe_tasks import input_reference
    from scopelens.domain.assessment import stable_id

    _, _, scan = prepared
    frozen = expanded_scan().assessment_plan
    frozen["request_catalogue"]["templates"][0]["origin"] = "https://owned.example.com"
    frozen["input_assessment_plan"]["scope_version"] = str(scan.scope_version_id)
    frozen["input_assessment_plan"]["catalogue_hash"] = stable_id(frozen["request_catalogue"])
    scan.assessment_plan = {**scan.assessment_plan, **frozen}
    db_session.commit()
    settings = small_limits(settings, max_pages=1, max_total_requests=2)
    assert run_request(db_session, settings, prepared, "/app/one").allowed
    assert run_request(
        db_session, settings, prepared, "/app/search?q=marker&fixed=stable", input_reference("task")
    ).allowed
    denied = run_request(
        db_session, settings, prepared, "/app/search?q=again&fixed=stable", input_reference("task")
    )
    assert not denied.allowed and denied.reason == "budget_exhausted"
    assert len(scan.assessment_plan["page_request_keys"]) == 1


@pytest.mark.parametrize(
    "prepared,policy_max,rate_max,expected,rate",
    [
        ({}, 8, 10, 2, 2),
        ({"max_in_flight": 2, "requests_per_second": 5}, 8, 10, 2, 5),
        ({"max_in_flight": 4, "requests_per_second": 5}, 8, 10, 4, 5),
        ({"max_in_flight": 20, "requests_per_second": 20}, 8, 10, 8, 10),
        ({"max_in_flight": 8, "requests_per_second": 5}, 4, 3, 4, 3),
    ],
    indirect=["prepared"],
)
def test_policy_preserves_scope_concurrency_and_existing_pacing(
    db_session, settings, prepared, policy_max, rate_max, expected, rate
):
    from scopelens.broker.policy import BrokerRequest

    scope, token, _ = prepared
    # Keep pilot defaults at 2/2: approval is in the scope, not the global defaults.
    settings = settings.model_copy(
        update={
            "scope_max_in_flight": policy_max,
            "scope_max_requests_per_second": rate_max,
            "budgets": settings.budgets.model_copy(
                update={"max_in_flight": 2, "requests_per_second": 2}
            ),
        }
    )
    now = datetime.now(UTC)
    waits = []
    for index in range(2):
        decision = authorize(
            db_session,
            settings=settings,
            request=BrokerRequest(**asdict(request_for(scope, token, path=f"/app/{index}"))),
            resolver=resolver_for(PUBLIC_V4),
            now=now,
        )
        assert decision.allowed
        assert decision.extra["max_in_flight"] == str(expected)
        waits.append(float(decision.extra["wait_seconds"]))
        db_session.commit()
    assert waits == [0, pytest.approx(1 / rate, abs=0.000001)]
