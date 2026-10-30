from datetime import UTC, datetime, timedelta

import pytest

from scopelens.broker.policy import BrokerRequest, authorize, issue_egress_token
from scopelens.domain.scope import LabScopeCreate
from scopelens.execution.leases import acquire_lease
from scopelens.execution.ledger import create_scan_with_task
from scopelens.scope.dns import StaticResolver
from scopelens.scope.service import ScopeRegistrationError, register_scope

pytestmark = pytest.mark.db


def test_transport_grant_is_one_initial_get_only(db_session, settings, seeded_operator):
    operator, _ = seeded_operator
    scope = register_scope(
        db_session,
        operator_id=operator,
        actor="test",
        settings=settings,
        resolver=StaticResolver({}),
        payload=LabScopeCreate(
            lab_service="labs-bad",
            scheme="https",
            lab_port=8443,
            transport_http_port=80,
            authorization_expires_at=datetime.now(UTC) + timedelta(days=1),
        ),
    )
    scan, _ = create_scan_with_task(
        db_session,
        operator_id=operator,
        scope_version=scope,
        score_version="score-v1.0",
        actor="test",
    )
    token = issue_egress_token(db_session, scan=scan)
    acquire_lease(db_session, scan_id=scan.id, holder="test", ttl_seconds=60)
    db_session.commit()

    def decide(**overrides):
        values = dict(
            method="GET", scheme="http", host=scope.host, port=80, path="/", egress_token=token
        )
        values.update(overrides)
        decision = authorize(
            db_session,
            settings=settings,
            request=BrokerRequest(**values),
            resolver=StaticResolver({}),
        )
        db_session.commit()
        return decision

    assert not decide(path="/admin").allowed
    assert not decide(method="CONNECT").allowed
    assert not decide(host="172.28.0.12").allowed
    assert decide().allowed
    before = dict(scan.budget_reserved)
    assert not decide().allowed
    db_session.refresh(scan)
    assert scan.budget_reserved == before
    assert decide(scheme="https", port=8443).allowed


def test_lab_transport_cannot_authorize_unlisted_port(db_session, settings, seeded_operator):
    with pytest.raises(ScopeRegistrationError):
        register_scope(
            db_session,
            operator_id=seeded_operator[0],
            actor="test",
            settings=settings,
            resolver=StaticResolver({}),
            payload=LabScopeCreate(
                lab_service="labs-bad",
                scheme="https",
                lab_port=8443,
                transport_http_port=6379,
                authorization_expires_at=datetime.now(UTC) + timedelta(days=1),
            ),
        )


def test_tls_lane_denial_never_opens_socket(db_session, settings, monkeypatch):
    from scopelens.broker.tls_lane_service import MeasureRequest, measure

    def forbidden(*args, **kwargs):
        raise AssertionError("socket must not open")

    monkeypatch.setattr("socket.create_connection", forbidden)
    result = measure(
        MeasureRequest(egress_token="unknown", host="example.test", port=443), db_session, settings
    )
    assert not result.allowed
    assert result.facts is None


def test_tls_rechecks_cancel_epoch_between_handshakes(
    queued_scan, db_session, settings, monkeypatch
):
    from sqlalchemy.orm import Session

    from scopelens.broker.tls_lane_service import MeasureRequest, measure
    from scopelens.persistence.models import ScanRow

    scan, _ = queued_scan
    token = issue_egress_token(db_session, scan=scan)
    acquire_lease(db_session, scan_id=scan.id, holder="test", ttl_seconds=60)
    db_session.commit()
    calls = []

    def fake_measure(host, port, *, authorize_handshake, **kwargs):
        calls.append(authorize_handshake())
        with Session(db_session.get_bind()) as other:
            current = other.get(ScanRow, scan.id)
            current.cancel_epoch += 1
            other.commit()
        authorize_handshake()
        raise AssertionError("Cancelled second handshake must not be admitted")

    monkeypatch.setattr("scopelens.broker.tls_lane_service.measure_tls", fake_measure)
    result = measure(
        MeasureRequest(egress_token=token, host=scan.scope_version.host, port=80),
        db_session,
        settings,
    )
    assert not result.allowed
    assert len(calls) == 1
