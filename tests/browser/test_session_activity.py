"""Active owners renew idle expiry; denied or idle sessions cannot recover authority."""

from datetime import UTC, datetime, timedelta

import pytest

from scopelens.broker.policy import issue_egress_token
from scopelens.browser import policy
from scopelens.browser.policy import BrowserAction, BrowserCommand
from scopelens.execution.leases import acquire_lease
from scopelens.persistence.models import BrowserSessionRow, CoordinatorLeaseRow

pytestmark = pytest.mark.db


@pytest.fixture
def active_session(queued_scan, db_session, settings, monkeypatch):
    scan, _ = queued_scan
    clock = [datetime.now(UTC)]

    class Clock:
        @staticmethod
        def now(zone):
            return clock[0]

    monkeypatch.setattr(policy, "datetime", Clock)
    token = issue_egress_token(db_session, scan=scan)
    acquire_lease(db_session, scan_id=scan.id, holder="test", ttl_seconds=3600, now=clock[0])
    db_session.commit()

    def run(operation, owner="active-owner-long", **fields):
        result = policy.command(
            db_session,
            settings,
            BrowserCommand(egress_token=token, owner=owner, operation=operation, **fields),
        )
        db_session.commit()
        return result

    assert run("open")["allowed"]
    return run, clock, scan, db_session.get(BrowserSessionRow, scan.id)


def test_activity_continues_past_initial_fifteen_minutes(active_session):
    run, clock, scan, row = active_session
    initial_expiry = row.expires_at
    action = BrowserAction(kind="navigate", url=scan.target_origin + "/")
    clock[0] += timedelta(minutes=14)
    assert run("admit", sequence=1, action=action)["allowed"]
    assert row.expires_at == clock[0] + timedelta(minutes=15)
    assert run("complete", sequence=1)["allowed"]
    clock[0] += timedelta(minutes=14)
    assert clock[0] > initial_expiry
    assert run("admit", sequence=2, action=action)["allowed"]
    assert run("complete", sequence=2)["allowed"]
    assert row.expires_at == clock[0] + timedelta(minutes=15)
    assert row.sequence == 2


def test_idle_session_still_expires_and_cannot_be_reopened(active_session):
    run, clock, _, row = active_session
    expiry = row.expires_at
    clock[0] = expiry
    assert run("admit", sequence=1)["reason"] == "session_expired"
    assert run("open")["reason"] == "context_already_owned"
    assert row.expires_at == expiry


@pytest.mark.parametrize("denial", ["unsafe", "wrong_owner", "revoked", "lease_lost"])
def test_denied_activity_does_not_renew(active_session, db_session, denial):
    run, clock, scan, row = active_session
    expiry = row.expires_at
    clock[0] += timedelta(minutes=14)
    if denial == "unsafe":
        result = run(
            "admit",
            sequence=1,
            action=BrowserAction(kind="navigate", url=scan.target_origin + "/delete"),
        )
    elif denial == "wrong_owner":
        result = run("open", owner="different-owner-long")
    elif denial == "revoked":
        scan.cancel_epoch += 1
        db_session.commit()
        result = run("open")
    else:
        lease = db_session.get(CoordinatorLeaseRow, scan.id)
        lease.expires_at = clock[0]
        db_session.commit()
        result = run("open")
    assert not result["allowed"]
    assert row.expires_at == expiry


def test_close_does_not_extend_or_reopen_a_session(active_session):
    run, clock, _, row = active_session
    expiry = row.expires_at
    clock[0] += timedelta(minutes=14)
    assert run("close")["allowed"]
    assert row.status == "closed" and row.expires_at == expiry
    assert not run("open")["allowed"]


def test_renewal_never_outlives_scope_authorization(active_session, monkeypatch):
    run, clock, _, row = active_session
    scope_expiry = clock[0] + timedelta(minutes=20)
    original_scope = policy.scope_row_to_domain
    monkeypatch.setattr(
        policy,
        "scope_row_to_domain",
        lambda scope: original_scope(scope).model_copy(
            update={"authorization_expires_at": scope_expiry}
        ),
    )
    clock[0] += timedelta(minutes=14)
    assert run("open")["allowed"]
    assert row.expires_at == scope_expiry
    clock[0] = scope_expiry
    assert run("open")["reason"] == "scope_expired"
    assert row.expires_at == scope_expiry
