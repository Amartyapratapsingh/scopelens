"""Only broker-captured exact requests can supply durable callback dispatch proof."""

import hashlib

import pytest
from sqlalchemy import select
from tests.unit.test_callback_runtime import call, sequence

from scopelens.callbacks.runtime import CallbackDispatchIntentRow

pytest_plugins = ["tests.unit.test_callback_runtime"]


def capture(runtime, task, dispatch):
    record = runtime.bind_request(task.scan_id, dispatch.method, dispatch.url, dispatch.body_sha256)
    assert record is not None
    runtime.record_response(task.scan_id, record.id, 200)
    return record


def test_issue_commits_private_request_before_return(fixture):
    runtime, task, _ = fixture
    result = call(runtime, task, "issue", purpose="negative")
    with runtime.service.sessions() as db:
        intent = db.get(CallbackDispatchIntentRow, result["nonce"]["id"])
        assert intent.callback_url == result["nonce"]["url"]
        assert intent.recipe_digest == task.recipe_digest
        assert intent.task_id == task.task_id
        assert intent.body_sha256 == hashlib.sha256(b"").hexdigest()
        assert not hasattr(intent, "body")


def test_exact_request_only_and_response_once(fixture):
    runtime, task, clock = fixture
    dispatches = sequence(fixture)
    # Restore the capture clock and revocation solely for testing actual-request matching.
    from scopelens.callbacks.service import NonceRow

    with runtime.service.sessions() as db:
        for nonce in db.scalars(select(NonceRow)).all():
            nonce.revoked = False
        db.commit()
    clock[0] = 1001.0
    d = dispatches[0]
    assert runtime.bind_request("other", d.method, d.url, d.body_sha256) is None
    assert runtime.bind_request(task.scan_id, "POST", d.url, d.body_sha256) is None
    assert runtime.bind_request(task.scan_id, d.method, d.url + "x", d.body_sha256) is None
    assert runtime.bind_request(task.scan_id, d.method, d.url, "f" * 64) is None
    row = capture(runtime, task, d)
    with pytest.raises(PermissionError):
        runtime.record_response("other", row.id, 200)
    with pytest.raises(PermissionError):
        runtime.record_response(task.scan_id, row.id, 200)


def test_stored_proof_rejects_duplicates_and_incomplete_responses(fixture):
    runtime, task, clock = fixture
    dispatches = sequence(fixture)
    from scopelens.callbacks.service import NonceRow

    with runtime.service.sessions() as db:
        for nonce in db.scalars(select(NonceRow)).all():
            nonce.revoked = False
        db.commit()
    clock[0] = 1001.0
    with pytest.raises(ValueError):
        runtime.stored_dispatch_evidence(task)
    for d in dispatches:
        capture(runtime, task, d)
        clock[0] += 0.1
    stored = runtime.stored_dispatch_evidence(task)
    assert len(stored) == 3
    assert all(d.evidence_ref.startswith("callback-dispatch:") for d in stored)
    capture(runtime, task, dispatches[0])
    with pytest.raises(ValueError, match="repeated"):
        runtime.stored_dispatch_evidence(task)


def test_expired_or_revoked_request_never_bound(fixture):
    runtime, task, clock = fixture
    dispatches = sequence(fixture)
    d = dispatches[0]
    with pytest.raises(PermissionError):
        runtime.bind_request(task.scan_id, d.method, d.url, d.body_sha256)
    clock[0] += 1000
    with pytest.raises(PermissionError):
        runtime.bind_request(task.scan_id, d.method, d.url, d.body_sha256)


def test_durable_broker_sequence_drives_independent_proof(fixture):
    from urllib.parse import urlsplit

    from scopelens.callbacks.runtime import _expected_request, evaluate_stored_callback_proof

    runtime, task, clock = fixture
    nonces = []
    for purpose in ("negative", "positive", "positive"):
        nonce = call(runtime, task, "issue", purpose=purpose)["nonce"]
        nonces.append(nonce)
        url, body = _expected_request(task.recipe, nonce["url"], purpose)
        record = runtime.bind_request(
            task.scan_id, task.recipe.method, url, hashlib.sha256(body).hexdigest()
        )
        clock[0] += 0.1
        if purpose == "positive":
            runtime.service.capture(
                urlsplit(nonce["url"]).path.rsplit("/", 1)[1], peer="192.0.2.10", method="GET"
            )
        runtime.record_response(task.scan_id, record.id, 200)
    clock[0] += task.recipe.max_wait_seconds
    for nonce in nonces:
        call(runtime, task, "revoke", nonce_id=nonce["id"])
    evidence = runtime.stored_dispatch_evidence(task)
    outcome = evaluate_stored_callback_proof(
        runtime,
        task,
        evidence,
        trusted_refs={d.evidence_ref for d in evidence},
        finished_at=clock[0],
    )
    assert outcome.status.value == "confirmed_issue"
    assert len(outcome.proof.evidence_refs) == 3
    with pytest.raises(ValueError):
        runtime.stored_dispatch_evidence(task.model_copy(update={"owner_id": "other"}))
