import pytest

from scopelens.broker.policy import issue_egress_token
from scopelens.browser.policy import BrowserAction, BrowserCommand, action_reason, command
from scopelens.execution.leases import acquire_lease


@pytest.mark.parametrize("label", ["Pay now", "Delete account", "Send email", "Logout", "Buy item"])
def test_side_effect_intent_denied(label):
    assert (
        action_reason(
            BrowserAction(
                kind="click", url="https://example.test/", label=label, state_hash="a" * 64
            )
        )
        == "side_effect_intent"
    )


def test_passive_controls_and_search_only():
    assert (
        action_reason(
            BrowserAction(
                kind="click", url="https://example.test/", label="Show details", state_hash="a" * 64
            )
        )
        is None
    )
    assert action_reason(
        BrowserAction(
            kind="submit",
            url="https://example.test/search",
            label="Search",
            form_method="POST",
            state_hash="a" * 64,
        )
    )
    assert (
        action_reason(
            BrowserAction(
                kind="coordinate",
                url="https://example.test/",
                label="View details",
                state_hash="a" * 64,
            )
        )
        == "vision_unavailable"
    )


@pytest.mark.db
def test_context_has_one_owner_ordered_actions_and_revocation(queued_scan, db_session, settings):
    scan, _ = queued_scan
    token = issue_egress_token(db_session, scan=scan)
    acquire_lease(db_session, scan_id=scan.id, holder="test", ttl_seconds=60)
    db_session.commit()

    def run(operation, owner="first-owner-long", **kw):
        result = command(
            db_session,
            settings,
            BrowserCommand(egress_token=token, owner=owner, operation=operation, **kw),
        )
        db_session.commit()
        return result

    assert run("open")["allowed"]
    assert not run("open", owner="second-owner-long")["allowed"]
    action = BrowserAction(kind="navigate", url=scan.target_origin + "/")
    assert run("admit", sequence=1, action=action)["allowed"]
    assert not run("admit", sequence=2, action=action)["allowed"]
    assert run("complete", sequence=1, after_hash="b" * 64)["allowed"]
    assert not run("admit", sequence=1, action=action)["allowed"]
    scan.cancel_epoch += 1
    db_session.commit()
    assert not run("admit", sequence=2, action=action)["allowed"]
