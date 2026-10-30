"""Trusted callback snapshots exclude private URLs and never credit worker verdicts."""

import hashlib
import json
from copy import deepcopy
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
import pytest
from tests.unit.test_callback_runtime import call

from scopelens.callbacks.integration import (
    capture_callback_artifacts,
    collect_callback_diagnostics,
    evaluate_callback_artifacts,
)
from scopelens.callbacks.runtime import _expected_request

pytest_plugins = ["tests.unit.test_callback_runtime"]


def config(task):
    return SimpleNamespace(
        callback_recipes=(SimpleNamespace(id=task.recipe_id, recipe=task.recipe),)
    )


def broker_sequence(fixture, *, callbacks=True, close_early=False, duplicate=False):
    runtime, task, clock = fixture
    nonces = []
    for purpose in ("negative", "positive", "positive"):
        nonce = call(runtime, task, "issue", purpose=purpose)["nonce"]
        nonces.append(nonce)
        url, body = _expected_request(task.recipe, nonce["url"], purpose)
        record = runtime.bind_request(
            task.scan_id, task.recipe.method, url, hashlib.sha256(body).hexdigest()
        )
        if duplicate and purpose == "negative":
            runtime.bind_request(
                task.scan_id, task.recipe.method, url, hashlib.sha256(body).hexdigest()
            )
        clock[0] += 0.1
        if callbacks and purpose == "positive":
            runtime.service.capture(
                urlsplit(nonce["url"]).path.rsplit("/", 1)[1], peer="192.0.2.10", method="GET"
            )
        runtime.record_response(task.scan_id, record.id, 200)
    if not close_early:
        clock[0] += task.recipe.max_wait_seconds
    for nonce in nonces:
        call(runtime, task, "revoke", nonce_id=nonce["id"])
    captures = capture_callback_artifacts(
        runtime, config(task), owner_id=task.owner_id, scan_id=task.scan_id
    )
    captures[0]["evidence_ref"] = "trusted-real-evidence-row"
    return captures, nonces


def evaluate(fixture, captures):
    runtime, task, _ = fixture
    return evaluate_callback_artifacts(
        runtime,
        config(task),
        owner_id=task.owner_id,
        scan_id=task.scan_id,
        artifacts=captures,
        trusted_refs={"trusted-real-evidence-row"},
    )[0]


def test_snapshot_uses_real_evidence_ref_and_fixed_capture_time(fixture):
    captures, nonces = broker_sequence(fixture)
    before = evaluate(fixture, captures)
    assert before.status.value == "confirmed_issue"
    assert before.proof.evidence_refs == ("trusted-real-evidence-row",)
    fixture[2][0] += 10000
    assert evaluate(fixture, captures) == before
    serialized = json.dumps(captures) + before.model_dump_json()
    for nonce in nonces:
        assert nonce["url"] not in serialized
        assert nonce["url"].rsplit("/", 1)[1] not in serialized
    assert "http://collector.test" not in serialized


@pytest.mark.parametrize(
    "change",
    [
        "worker_summary",
        "source",
        "unknown_ref",
        "claimed_confirmed",
        "duplicate_capture",
        "missing_capture",
    ],
)
def test_forged_summary_or_capture_cannot_confirm(fixture, change):
    captures, _ = broker_sequence(fixture)
    if change == "worker_summary":
        captures = [
            {
                "kind": "callback_diagnostic",
                "data": {"state": "confirmed"},
                "evidence_ref": "trusted-real-evidence-row",
            }
        ]
    elif change == "source":
        captures[0]["source"] = "worker"
    elif change == "unknown_ref":
        captures[0]["evidence_ref"] = "invented"
    elif change == "claimed_confirmed":
        captures[0]["data"]["state"] = "confirmed"
    elif change == "duplicate_capture":
        captures.append(deepcopy(captures[0]))
    else:
        captures = []
    assert evaluate(fixture, captures).status.value == "inconclusive"


@pytest.mark.parametrize(
    "kwargs", [{"callbacks": False}, {"close_early": True}, {"duplicate": True}]
)
def test_no_callback_short_window_and_duplicate_dispatch_inconclusive(fixture, kwargs):
    captures, _ = broker_sequence(fixture, **kwargs)
    assert evaluate(fixture, captures).status.value == "inconclusive"


def test_missing_dispatches_and_disabled_runtime_inconclusive(fixture):
    runtime, task, _ = fixture
    for current in (runtime, None):
        captures = capture_callback_artifacts(
            current, config(task), owner_id=task.owner_id, scan_id=task.scan_id
        )
        captures[0]["evidence_ref"] = "trusted-real-evidence-row"
        assert evaluate(fixture, captures).status.value == "inconclusive"


def test_worker_uses_control_facade_and_retains_safe_diagnostics_on_rpc_loss(fixture):
    _, task, _ = fixture
    seen = []

    def lost(payload):
        seen.append(payload)
        raise OSError("unavailable")

    output = []
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
        collect_callback_diagnostics(
            config(task),
            SimpleNamespace(callback_rpc=lost),
            client,
            owner_id=task.owner_id,
            scan_id=task.scan_id,
            emit=lambda kind, data: output.append({"kind": kind, "data": data}),
        )
    assert seen == [{"operation": "issue", "recipe_id": task.recipe_id, "purpose": "negative"}]
    assert output[0]["kind"] == "callback_diagnostic"
    assert output[0]["data"]["state"] == "blocked"
    assert "http" not in json.dumps(output)


def test_existing_worker_probe_and_control_rpc_produce_only_safe_diagnostics(fixture):
    from urllib.parse import parse_qs

    from scopelens.callbacks.runtime import CallbackCommand

    runtime, original, clock = fixture
    task = original.model_copy(
        update={"recipe": original.recipe.model_copy(update={"max_wait_seconds": 0})}
    )

    def rpc(payload):
        return runtime.handle(task, CallbackCommand.model_validate(payload), admit=lambda: True)

    def target(request):
        record = runtime.bind_request(
            task.scan_id,
            request.method,
            str(request.url),
            hashlib.sha256(request.content).hexdigest(),
        )
        assert record is not None
        clock[0] += 0.01
        value = parse_qs(urlsplit(str(request.url)).query)["url"][0]
        if value.startswith("http://"):
            runtime.service.capture(
                urlsplit(value).path.rsplit("/", 1)[1], peer="192.0.2.10", method="GET"
            )
        runtime.record_response(task.scan_id, record.id, 200)
        return httpx.Response(200)

    emitted = []
    with httpx.Client(transport=httpx.MockTransport(target)) as client:
        collect_callback_diagnostics(
            config(task),
            SimpleNamespace(callback_rpc=rpc),
            client,
            owner_id=task.owner_id,
            scan_id=task.scan_id,
            emit=lambda kind, data: emitted.append({"kind": kind, "data": data}),
        )
    assert emitted[0]["data"]["state"] == "confirmed"
    assert emitted[0]["data"]["nonce_count"] == 3
    assert emitted[0]["data"]["receipt_count"] == 2
    assert "http" not in json.dumps(emitted)
    captures = capture_callback_artifacts(
        runtime, config(task), owner_id=task.owner_id, scan_id=task.scan_id
    )
    captures[0]["evidence_ref"] = "trusted-real-evidence-row"
    outcomes = evaluate_callback_artifacts(
        runtime,
        config(task),
        owner_id=task.owner_id,
        scan_id=task.scan_id,
        artifacts=captures,
        trusted_refs={"trusted-real-evidence-row"},
    )
    assert outcomes[0].status.value == "confirmed_issue"


def test_multiple_recipes_one_control_keep_missing_instance_and_frozen_locations(fixture):
    from scopelens.callbacks.integration import callback_controls

    captures, _ = broker_sequence(fixture)
    runtime, task, clock = fixture
    second = task.model_copy(
        update={
            "recipe_id": "second-owned-recipe",
            "recipe": task.recipe.model_copy(
                update={"target_url": "https://stage.test/second?url=baseline"}
            ),
        }
    )
    configuration = SimpleNamespace(
        callback_recipes=(*config(task).callback_recipes, *config(second).callback_recipes)
    )
    outcomes = callback_controls(
        runtime,
        configuration,
        owner_id=task.owner_id,
        scan_id=task.scan_id,
        artifacts=captures,
        trusted_refs={"trusted-real-evidence-row", "second-real-ref"},
    )
    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.status.value == "confirmed_issue"
    assert outcome.required_instances == (task.recipe_id, second.recipe_id)
    assert outcome.completed_instances == (task.recipe_id,)
    assert not outcome.is_fully_assessed and outcome.incomplete_reasons
    assert [(location.route, location.parameter) for location in outcome.locations] == [
        ("/preview", "url")
    ]
    second_captures, _ = broker_sequence((runtime, second, clock))
    second_captures[0]["evidence_ref"] = "second-real-ref"
    outcome = callback_controls(
        runtime,
        configuration,
        owner_id=task.owner_id,
        scan_id=task.scan_id,
        artifacts=captures + second_captures,
        trusted_refs={"trusted-real-evidence-row", "second-real-ref"},
    )[0]
    assert outcome.is_fully_assessed
    assert outcome.completed_instances == outcome.required_instances
    assert {location.route for location in outcome.locations} == {"/preview", "/second"}
    assert outcome.proof.evidence_refs == ("trusted-real-evidence-row", "second-real-ref")
