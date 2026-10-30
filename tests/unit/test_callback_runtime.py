"""Durable callback proof and worker RPC loss: synthetic SQLite collector fixtures."""

import hashlib
import json
from urllib.parse import urlsplit

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from scopelens.callbacks.client import CallbackControlClient, collect_remote_callback
from scopelens.callbacks.probes import CallbackProbeRecipe
from scopelens.callbacks.runtime import (
    CallbackClosureRow,
    CallbackCommand,
    CallbackDispatchEvidence,
    FrozenCallbackTask,
    _expected_request,
    create_callback_runtime,
    evaluate_stored_callback_proof,
)
from scopelens.callbacks.service import CallbackBase, NonceRow, ReceiptRow
from scopelens.domain.callback import CallbackNonce


@pytest.fixture
def fixture(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "callback.db"))
    CallbackBase.metadata.create_all(engine)
    clock = [1000.0]
    runtime = create_callback_runtime(
        sessionmaker(engine),
        collector_origins={"http://collector.test"},
        signing_key=b"fixture-only-key-with-32-characters",
        now=lambda: clock[0],
    )
    task = FrozenCallbackTask(
        owner_id="owner",
        scan_id="scan",
        recipe_id="owned-recipe",
        recipe=CallbackProbeRecipe(
            family="ssrf",
            target_url="https://stage.test/preview?url=baseline",
            parameter="url",
            callback_origin="http://collector.test",
            expected_target_peers=frozenset({"192.0.2.10"}),
            scanner_peers=frozenset({"192.0.2.20"}),
            approved_staging=True,
            unexpected_external_fetch=True,
            max_wait_seconds=1,
        ),
    )
    yield runtime, task, clock
    engine.dispose()


def call(runtime, task, operation, **kwargs):
    return runtime.handle(
        task,
        CallbackCommand(operation=operation, recipe_id=task.recipe_id, **kwargs),
        admit=lambda: True,
    )


def sequence(fixture, *, source="target", protocol="http", negative=False, close_early=False):
    runtime, task, clock = fixture
    dispatches = []
    for index, purpose in enumerate(("negative", "positive", "positive")):
        issued = call(runtime, task, "issue", purpose=purpose)
        nonce = CallbackNonce.model_validate(issued["nonce"])
        expected_url, body = _expected_request(task.recipe, nonce.url, purpose)
        dispatches.append(
            CallbackDispatchEvidence(
                nonce_id=nonce.id,
                callback_url=nonce.url,
                method=task.recipe.method,
                url=expected_url,
                body_sha256=hashlib.sha256(body).hexdigest(),
                response_status=200,
                evidence_ref=f"trusted-{index}",
                sent_at=clock[0],
            )
        )
        clock[0] += 0.1
        if purpose == "positive" or negative:
            runtime.service.capture(
                urlsplit(nonce.url).path.rsplit("/", 1)[1],
                peer="192.0.2.10"
                if source == "target"
                else "192.0.2.20"
                if source == "scanner"
                else "192.0.2.30",
                method="GET",
                protocol=protocol,
            )
    clock[0] += 0 if close_early else 1
    for dispatch in dispatches:
        call(runtime, task, "revoke", nonce_id=dispatch.nonce_id)
    return dispatches


def evaluate(fixture, dispatches):
    runtime, task, clock = fixture
    return evaluate_stored_callback_proof(
        runtime,
        task,
        dispatches,
        trusted_refs={f"trusted-{i}" for i in range(3)},
        finished_at=clock[0] + 2,
    )


def test_two_target_http_receipts_exact_requests_and_closed_negative_window_confirm(fixture):
    dispatches = sequence(fixture)
    outcome = evaluate(fixture, dispatches)
    assert outcome.status.value == "confirmed_issue"
    assert outcome.proof.evidence_refs == ("trusted-0", "trusted-1", "trusted-2")
    assert outcome.proposed_severity.value == "medium"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"source": "scanner"},
        {"source": "unknown"},
        {"protocol": "dns"},
        {"negative": True},
        {"close_early": True},
    ],
)
def test_ambiguous_or_uncontrolled_callback_never_confirms_or_passes(fixture, kwargs):
    outcome = evaluate(fixture, sequence(fixture, **kwargs))
    assert outcome.status.value == "inconclusive"
    assert not outcome.proof.satisfied


@pytest.mark.parametrize(
    "tamper",
    ["signature", "ownership", "purpose", "expiry", "closure", "request", "evidence", "duplicate"],
)
def test_binding_tampering_fails_independent_proof(fixture, tamper):
    runtime, _task, _ = fixture
    dispatches = sequence(fixture)
    with runtime.service.sessions() as db:
        if tamper == "signature":
            row = db.scalar(select(ReceiptRow))
            data = json.loads(row.data)
            data["signature"] = "0" * 64
            row.data = json.dumps(data)
        elif tamper == "closure":
            row = db.get(CallbackClosureRow, dispatches[0].nonce_id)
            row.signature = "0" * 64
        elif tamper in {"ownership", "purpose", "expiry"}:
            row = db.get(NonceRow, dispatches[1].nonce_id)
            if tamper == "ownership":
                row.owner_id = "other"
            if tamper == "purpose":
                row.purpose = "negative"
            if tamper == "expiry":
                row.expires_at = row.created_at
        db.commit()
    if tamper == "request":
        dispatches[1] = dispatches[1].model_copy(update={"url": "https://stage.test/other"})
    if tamper == "evidence":
        dispatches[1] = dispatches[1].model_copy(update={"evidence_ref": "worker-invented"})
    if tamper == "duplicate":
        dispatches[1] = dispatches[0]
    assert evaluate(fixture, dispatches).status.value == "inconclusive"


def test_rpc_issuance_bound_to_frozen_recipe_and_three_nonces(fixture):
    runtime, task, _ = fixture
    with pytest.raises(PermissionError):
        call(runtime, task, "issue", purpose="positive")
    dispatches = sequence(fixture)
    with pytest.raises(PermissionError):
        call(runtime, task, "issue", purpose="positive")
    other = task.model_copy(update={"owner_id": "other"})
    with pytest.raises(PermissionError):
        call(runtime, other, "query", nonce_id=dispatches[0].nonce_id)
    with pytest.raises(PermissionError):
        runtime.handle(
            task,
            CallbackCommand(
                operation="query", recipe_id=task.recipe_id, nonce_id=dispatches[0].nonce_id
            ),
            admit=lambda: False,
        )


def test_replay_revocation_cannot_extend_observation_window(fixture):
    runtime, task, clock = fixture
    dispatches = sequence(fixture, close_early=True)
    clock[0] += 10
    for item in dispatches:
        call(runtime, task, "revoke", nonce_id=item.nonce_id)
    assert evaluate(fixture, dispatches).status.value == "inconclusive"


def test_factory_requires_explicit_origin_and_private_signing_key(fixture):
    runtime, _, _ = fixture
    with pytest.raises(ValueError):
        create_callback_runtime(
            runtime.service.sessions, collector_origins=set(), signing_key=b"x" * 32
        )
    with pytest.raises(ValueError):
        create_callback_runtime(
            runtime.service.sessions,
            collector_origins={"http://collector.test"},
            signing_key=b"short",
        )


def test_worker_rpc_loss_retains_cached_receipts_and_nonce_ids(fixture):
    runtime, task, _clock = fixture
    task = task.model_copy(
        update={"recipe": task.recipe.model_copy(update={"max_wait_seconds": 0})}
    )

    def rpc(payload):
        command = CallbackCommand.model_validate(payload)
        if command.operation == "revoke":
            raise ConnectionError("control revoked")
        return runtime.handle(task, command, admit=lambda: True)

    remote = CallbackControlClient(rpc, task)

    def target(request):
        callback = request.url.params["url"]
        if callback.startswith("http"):
            runtime.service.capture(
                urlsplit(callback).path.rsplit("/", 1)[1], peer="192.0.2.10", method="GET"
            )
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(target)) as client:
        result = collect_remote_callback(client, remote)
    assert result.state == "blocked"
    assert len(result.nonce_ids) == 3 and len(result.receipts) == 2
    assert "partial evidence retained" in result.reason
    assert not hasattr(remote, "key")


def test_existing_xxe_family_uses_exact_xml_hash_and_frozen_recipe(fixture):
    runtime, task, clock = fixture
    recipe = CallbackProbeRecipe(
        family="xxe",
        target_url="https://stage.test/xml",
        method="POST",
        callback_origin=task.recipe.callback_origin,
        expected_target_peers=task.recipe.expected_target_peers,
        scanner_peers=task.recipe.scanner_peers,
        approved_staging=True,
        unexpected_external_fetch=True,
        max_wait_seconds=1,
    )
    task = task.model_copy(update={"recipe": recipe})
    current = runtime, task, clock
    dispatches = sequence(current)
    assert evaluate(current, dispatches).status.value == "confirmed_issue"
    dispatches[1] = dispatches[1].model_copy(update={"body_sha256": "0" * 64})
    assert evaluate(current, dispatches).status.value == "inconclusive"


def test_no_receipt_never_means_a_pass(fixture):
    runtime, _, _ = fixture
    dispatches = sequence(fixture)
    with runtime.service.sessions() as db:
        for row in db.scalars(select(ReceiptRow)).all():
            db.delete(row)
        db.commit()
    assert evaluate(fixture, dispatches).status.value == "inconclusive"
