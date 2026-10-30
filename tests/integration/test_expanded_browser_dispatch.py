"""Real database ownership transitions and the fixed supervisor launch contract."""

import json
from datetime import UTC, datetime

import pytest

from scopelens.broker.policy import issue_egress_token
from scopelens.browser.policy import BrowserCommand, command
from scopelens.execution.leases import acquire_lease
from scopelens.execution.supervisor import RESULT_MARKER, SupervisorError, WorkerResult, WorkerSpec
from scopelens.expansion.integration import prepare_browser_owner, run_expanded_browser
from scopelens.persistence.models import BrowserSessionRow

pytestmark = pytest.mark.db


def authority(db, scan):
    token = issue_egress_token(db, scan=scan)
    acquire_lease(db, scan_id=scan.id, holder="coordinator", ttl_seconds=60)
    db.commit()
    return token


def test_only_coordinator_can_replace_closed_context(queued_scan, db_session, settings):
    scan, _ = queued_scan
    token = authority(db_session, scan)
    first, second = "original-browser-owner", "expanded-browser-owner"

    def request(owner, op):
        return BrowserCommand(egress_token=token, owner=owner, operation=op)

    assert command(db_session, settings, request(first, "open"))["allowed"]
    db_session.commit()
    with pytest.raises(SupervisorError, match="not closed"):
        prepare_browser_owner(settings, scan.id, token, second)
    assert command(db_session, settings, request(first, "close"))["allowed"]
    db_session.commit()
    original = db_session.get(BrowserSessionRow, scan.id).context_id
    # A worker cannot take over a closed context through its public control RPC.
    assert not command(db_session, settings, request(second, "open"))["allowed"]
    db_session.commit()
    prepare_browser_owner(settings, scan.id, token, second)
    assert command(db_session, settings, request(second, "open"))["allowed"]
    assert not command(db_session, settings, request(first, "close"))["allowed"]
    db_session.commit()
    assert db_session.get(BrowserSessionRow, scan.id).context_id != original


@pytest.mark.parametrize("revocation", ["cancel", "epoch", "unknown"])
def test_revoked_authority_cannot_prepare_context(queued_scan, db_session, settings, revocation):
    scan, _ = queued_scan
    token = authority(db_session, scan)
    if revocation == "cancel":
        scan.cancel_requested_at = datetime.now(UTC)
    elif revocation == "epoch":
        scan.cancel_epoch += 1
    else:
        token = "unknown"
    db_session.commit()
    with pytest.raises(SupervisorError):
        prepare_browser_owner(settings, scan.id, token, "expanded-browser-owner")
    assert db_session.get(BrowserSessionRow, scan.id) is None


def test_launch_preserves_proxy_token_labels_and_uses_browser_image(
    queued_scan, db_session, settings
):
    scan, _ = queued_scan
    token = authority(db_session, scan)
    spec = WorkerSpec(
        image="http-worker",
        command=["crawler"],
        network="worker-only",
        environment={
            "HTTP_PROXY": "http://broker:8098",
            "SCOPELENS_EGRESS_TOKEN": token,
            "SCOPELENS_PROXY_CA_PEM": "public-ca",
        },
        labels={"scopelens.scan_id": str(scan.id)},
    )
    calls = []

    class Supervisor:
        def run(self, launched, *, run_id):
            calls.append(launched)
            return WorkerResult(run_id, 0, RESULT_MARKER + json.dumps({"ok": True}), "", 0)

    settings = settings.model_copy(update={"browser_enabled": True})
    result = run_expanded_browser(
        settings,
        Supervisor(),
        spec,
        run_id="review-run",
        scan_id=scan.id,
        payload="{}",
        capability="test-capability",
    )
    assert result.succeeded and len(calls) == 1
    launched = calls[0]
    assert launched.browser and launched.image == settings.browser_worker_image
    assert launched.command == ["python", "-m", "scopelens.expansion.browser_worker"]
    assert all(launched.environment[k] == v for k, v in spec.environment.items())
    assert launched.labels["scopelens.scan_id"] == str(scan.id)
    assert launched.environment["SCOPELENS_BROWSER_OWNER"] == result.run_id
    # Repeated admission must not launch a second worker into the same context.
    repeat = run_expanded_browser(
        settings,
        Supervisor(),
        spec,
        run_id="review-run",
        scan_id=scan.id,
        payload="{}",
        capability="test-capability",
    )
    assert not repeat.succeeded and len(calls) == 1
