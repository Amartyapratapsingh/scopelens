"""Approved rate increases are recorded atomically at first scan admission."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from scopelens.domain.lab import LabBinding
from scopelens.domain.scope import LabScopeCreate
from scopelens.execution.coordinator import CoordinatorResult, _prepare
from scopelens.execution.ledger import budget_limits_for, create_scan_with_task
from scopelens.persistence.models import AuditEventRow, ScanRow, ScopeVersionRow
from scopelens.persistence.repositories import create_scope_version
from scopelens.scope.dns import StaticResolver

pytestmark = pytest.mark.db


@pytest.fixture
def settings(settings):
    """Audit expectations use explicit test rates rather than operator deployment rates."""
    return settings.model_copy(
        update={
            "scope_max_in_flight": 8,
            "scope_max_requests_per_second": 10,
            "budgets": settings.budgets.model_copy(
                update={"max_in_flight": 2, "requests_per_second": 2}
            ),
        }
    )


def queued(db_session, seeded_operator, settings, override):
    operator_id, _ = seeded_operator
    scope = create_scope_version(
        db_session,
        operator_id=operator_id,
        payload=LabScopeCreate(
            lab_service="labs-bad",
            scheme="http",
            lab_port=80,
            authorization_expires_at=datetime.now(UTC) + timedelta(days=30),
            budgets_override=override,
        ),
        scheme="http",
        host="172.28.0.11",
        port=80,
        lab_binding=LabBinding(
            service="labs-bad",
            address="172.28.0.11",
            port=80,
            environment="docker-compose-labs",
        ),
    )
    scan, task = create_scan_with_task(
        db_session,
        operator_id=operator_id,
        scope_version=scope,
        score_version=settings.score_version,
    )
    db_session.commit()
    return scope, scan, task


def increases(db_session, scan):
    return db_session.scalars(
        select(AuditEventRow).where(
            AuditEventRow.subject_id == str(scan.id),
            AuditEventRow.action == "budget.increase",
        )
    ).all()


@pytest.mark.parametrize(
    "override,concurrency,rate,expected",
    [
        (None, 2, 2, {}),
        ({"max_in_flight": 1, "requests_per_second": 1}, 1, 1, {}),
        (
            {"max_in_flight": 4, "requests_per_second": 5},
            4,
            5,
            {
                "max_in_flight": {"default": 2, "approved": 4, "effective": 4},
                "requests_per_second": {"default": 2, "approved": 5, "effective": 5},
            },
        ),
        (
            {"max_in_flight": 20, "requests_per_second": 50},
            8,
            10,
            {
                "max_in_flight": {"default": 2, "approved": 20, "effective": 8},
                "requests_per_second": {"default": 2, "approved": 50, "effective": 10},
            },
        ),
        (
            {"max_in_flight": 4},
            4,
            2,
            {"max_in_flight": {"default": 2, "approved": 4, "effective": 4}},
        ),
        ({"max_pages": 999999, "max_total_requests": 999999}, 2, 2, {}),
    ],
)
def test_admission_audits_only_approved_rate_increases(
    db_session, seeded_operator, settings, override, concurrency, rate, expected
):
    scope, scan, task = queued(db_session, seeded_operator, settings, override)
    assert increases(db_session, scan) == []  # Creation is not execution admission.
    result = _prepare(settings, scan_id=scan.id, task_id=task.id)
    assert not isinstance(result, CoordinatorResult)
    _, _, limits, _ = result
    assert (limits.max_in_flight, limits.requests_per_second) == (concurrency, rate)
    assert limits.max_pages <= settings.budgets.max_pages
    assert limits.max_requests <= settings.budgets.max_total_requests
    rows = increases(db_session, scan)
    if expected:
        assert len(rows) == 1
        row = rows[0]
        assert (row.actor, row.outcome, row.subject_type) == ("coordinator", "admitted", "scan")
        assert row.detail == {
            "scope_version_id": str(scope.id),
            "scope_key": scope.scope_key,
            "scope_version": scope.version,
            "increases": expected,
        }
    else:
        assert rows == []
    _prepare(settings, scan_id=scan.id, task_id=task.id)
    assert len(increases(db_session, scan)) == len(rows)  # Duplicate delivery.


def test_requested_increase_is_audited_even_when_ceiling_prevents_it(
    db_session, seeded_operator, settings
):
    settings = settings.model_copy(update={"scope_max_in_flight": 1})
    scope, scan, task = queued(db_session, seeded_operator, settings, {"max_in_flight": 4})
    assert budget_limits_for(scope, settings).max_in_flight == 1
    _prepare(settings, scan_id=scan.id, task_id=task.id)
    assert increases(db_session, scan)[0].detail["increases"] == {
        "max_in_flight": {"default": 2, "approved": 4, "effective": 1}
    }


def test_refused_admission_does_not_record_increase(db_session, seeded_operator, settings):
    _, scan, task = queued(db_session, seeded_operator, settings, {"max_in_flight": 4})
    scan.budget_spent = {"requests": 1}
    db_session.commit()
    settings = settings.model_copy(
        update={"budgets": settings.budgets.model_copy(update={"max_total_requests": 1})}
    )
    result = _prepare(settings, scan_id=scan.id, task_id=task.id)
    assert isinstance(result, CoordinatorResult)
    assert "request budget exhausted" in result.reason
    assert increases(db_session, scan) == []
    db_session.refresh(scan)
    assert scan.started_at is None


def test_failed_audit_rolls_back_admission(db_session, seeded_operator, settings, monkeypatch):
    from scopelens.execution import ledger

    _, scan, task = queued(db_session, seeded_operator, settings, {"max_in_flight": 4})
    original = ledger.record_audit

    def fail_after_write(session, **kwargs):
        row = original(session, **kwargs)
        if kwargs["action"] == "budget.increase":
            raise RuntimeError("audit persistence failed")
        return row

    monkeypatch.setattr(ledger, "record_audit", fail_after_write)
    with pytest.raises(RuntimeError, match="audit persistence failed"):
        _prepare(settings, scan_id=scan.id, task_id=task.id)
    db_session.expire_all()
    assert db_session.get(ScanRow, scan.id).started_at is None
    assert task.state == "planned"
    assert increases(db_session, scan) == []


@pytest.mark.parametrize("authority", ["lab", "production"])
@pytest.mark.parametrize(
    "override,expected",
    [
        (None, {}),
        ({}, {}),
        (
            {"max_in_flight": 4, "requests_per_second": 5},
            {"max_in_flight": 4, "requests_per_second": 5},
        ),
        (
            {"max_in_flight": 20, "requests_per_second": 50},
            {"max_in_flight": 20, "requests_per_second": 50},
        ),
        ({"max_in_flight": 4}, {"max_in_flight": 4}),
        ({"requests_per_second": 5}, {"requests_per_second": 5}),
        ({"max_pages": 1}, {}),
    ],
)
def test_registration_and_admission_audit_approved_rates(
    authed_client, db_session, settings, monkeypatch, authority, override, expected
):
    import uuid

    monkeypatch.setattr(
        "scopelens.api.scopes.SystemResolver",
        lambda: StaticResolver({"owned.example.com": ["93.184.216.34"]}),
    )
    payload = {
        "authority_domain": authority,
        "authorization_expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        "owner_note": "operator note must not be copied into rate audit values",
    }
    if authority == "lab":
        payload.update(lab_service="labs-bad", scheme="http", lab_port=80)
    else:
        payload.update(host="owned.example.com", scheme="https", port=443)
    if override is not None:
        payload["budgets_override"] = override
    response = authed_client.post("/api/scopes", json=payload)
    assert response.status_code == 201, response.text
    scope = db_session.get(ScopeVersionRow, uuid.UUID(response.json()["id"]))
    registration = db_session.scalars(
        select(AuditEventRow).where(
            AuditEventRow.action == "scope.register",
            AuditEventRow.subject_id == str(scope.id),
        )
    ).one()
    if expected:
        assert registration.detail["budgets_override"] == expected
        assert all(
            type(v) in (int, float) for v in registration.detail["budgets_override"].values()
        )
    else:
        assert "budgets_override" not in registration.detail
    scan, task = create_scan_with_task(
        db_session,
        operator_id=scope.operator_id,
        scope_version=scope,
        score_version=settings.score_version,
    )
    db_session.commit()
    result = _prepare(settings, scan_id=scan.id, task_id=task.id)
    assert not isinstance(result, CoordinatorResult)
    rows = increases(db_session, scan)
    if expected:
        assert len(rows) == 1
        assert rows[0].detail["scope_version_id"] == str(scope.id)
        assert rows[0].detail["scope_version"] == registration.detail["version"]
        assert set(rows[0].detail["increases"]) == set(expected)
        for field, approved in expected.items():
            assert rows[0].detail["increases"][field] == {
                "default": getattr(settings.budgets, field),
                "approved": approved,
                "effective": getattr(result[2], field),
            }
    else:
        assert rows == []
