"""Exercise the actual LangGraph loop with deterministic worker/ledger fixtures.

Database locking/fencing has separate PostgreSQL coverage. These tests isolate graph
transitions and budget/cancellation decisions without target traffic or model calls.
"""

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from tests.unit.test_expansion_adaptive import prepared

from scopelens.execution.supervisor import ARTIFACT_MARKER, WorkerResult
from scopelens.orchestration.graph import candidates_from, run_graph


def worker_result(artifacts, code=0):
    return WorkerResult(
        "fixture",
        code,
        "\n".join(ARTIFACT_MARKER + json.dumps(a) for a in artifacts),
        "partial" if code else "",
        0.01,
    )


@pytest.fixture
def harness(monkeypatch):
    catalogue, plan, artifact = prepared("https://app.test")
    scan = SimpleNamespace(
        id="scan",
        scope_version_id="scope",
        cancel_requested_at=None,
        cancel_epoch=0,
        egress_token_epoch=0,
        budget_spent={"requests": 1},
        budget_reserved={"requests": 0},
        assessment_plan={
            "request_catalogue": catalogue.model_dump(mode="json"),
            "input_assessment_plan": plan.model_dump(mode="json"),
        },
    )
    settings = SimpleNamespace(
        adaptive_max_tasks=6,
        adaptive_max_rounds=3,
        tool_worker_image="owned-image",
        proxy_host="proxy",
        proxy_http_port=8080,
        worker_network="isolated",
        browser_enabled=False,
        callbacks_enabled=False,
    )
    scope = SimpleNamespace(
        id="scope",
        origin="https://app.test",
        authorization_expires_at=datetime.now(UTC) + timedelta(hours=1),
        allowed_check_profile=SimpleNamespace(expanded=True),
        allowed_path_prefixes=("/",),
        excluded_paths=(),
    )
    limits = SimpleNamespace(max_requests=200, max_response_bytes=4096)
    calls, audits = [], []

    class Database:
        def scalar(self, query):
            return scan

        def get(self, model, key):
            return scan

    @contextmanager
    def sessions(settings):
        yield Database()

    monkeypatch.setattr("scopelens.orchestration.graph.session_scope", sessions)
    monkeypatch.setattr(
        "scopelens.orchestration.graph.record_audit", lambda *args, **kwargs: audits.append(kwargs)
    )
    monkeypatch.setattr("scopelens.broker.policy.scan_for_token", lambda db, token: scan)
    monkeypatch.setattr("scopelens.execution.leases.lease_is_live", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        "scopelens.orchestration.models.call_model",
        lambda *args, **kwargs: {"state": "unavailable"},
    )
    monkeypatch.setattr(
        "scopelens.orchestration.scripts.analyze_local", lambda *args, **kwargs: None
    )
    monkeypatch.setattr("scopelens.skills.load_pack", lambda *args: {})
    monkeypatch.setattr(
        "scopelens.execution.coordinator._proxy_ca_pem", lambda settings: "fixture-ca"
    )
    return SimpleNamespace(
        scan=scan,
        settings=settings,
        scope=scope,
        limits=limits,
        initial=artifact,
        calls=calls,
        audits=audits,
    )


def run(h, followup, *, baseline_code=0):
    def execute(spec, run_id):
        assert h.scan.assessment_plan["baseline_obligations"]["run_returned"]
        assert spec.environment["SCOPELENS_EGRESS_TOKEN"] == "token"
        h.calls.append(spec)
        return followup(len(h.calls))

    return run_graph(
        h.settings,
        scan_id="scan",
        scope=h.scope,
        limits=h.limits,
        token="token",
        run_id="run",
        supervisor=SimpleNamespace(run=execute),
        baseline=lambda: worker_result([h.initial], baseline_code),
    )


def next_artifact(h, index):
    return {
        **h.initial,
        "data": {**h.initial["data"], "captures": [{"body_hash": str(index)}]},
    }


def test_fresh_observation_reenters_loop_and_stops_at_three_rounds(harness):
    h = harness
    run(h, lambda index: worker_result([next_artifact(h, index)]))
    assert len(h.calls) == 3
    assert [entry["round"] for entry in h.scan.assessment_plan["hypotheses"]] == [1, 2, 3]
    assert all(entry["state"] == "inconclusive" for entry in h.scan.assessment_plan["hypotheses"])


def test_unchanged_evidence_and_metadata_only_changes_do_not_replay(harness):
    h = harness
    run(
        h,
        lambda index: worker_result(
            [{**h.initial, "data": {**h.initial["data"], "timestamp": index, "run_id": "fresh"}}]
        ),
    )
    assert len(h.calls) == 1


def test_partial_baseline_keeps_missing_denominator_and_can_follow_safe_lead(harness):
    h = harness
    h.scan.assessment_plan["input_assessment_plan"]["tasks"].append(
        {
            **h.scan.assessment_plan["input_assessment_plan"]["tasks"][0],
            "id": "missing-task",
            "state": "blocked",
            "reason": "unavailable",
        }
    )
    h.scan.assessment_plan["input_assessment_plan"]["denominator"] += 1
    run(h, lambda index: worker_result([]), baseline_code=1)
    obligations = h.scan.assessment_plan["baseline_obligations"]
    assert len(h.calls) == 1
    assert obligations["missing_capture_task_ids"] == ["missing-task"]
    assert obligations["blocked_task_ids"] == ["missing-task"]
    assert not h.scan.assessment_plan["baseline_complete_before_adaptation"]
    assert h.scan.assessment_plan["baseline_finished_before_adaptation"]
    assert len(h.scan.assessment_plan["input_assessment_plan"]["tasks"]) == 2


def test_remaining_shared_budget_preserves_baseline_reservations(harness):
    h = harness
    h.limits.max_requests = 30
    h.scan.budget_reserved = {"requests": 10}
    run(h, lambda index: worker_result([]))
    assert h.calls == []
    assert h.scan.assessment_plan["baseline_obligations"]["reserved_requests"] == 10


def test_cancellation_after_followup_prevents_another_admission(harness):
    h = harness

    def followup(index):
        h.scan.cancel_requested_at = datetime.now(UTC)
        return worker_result([next_artifact(h, index)])

    run(h, followup)
    assert len(h.calls) == 1


@pytest.mark.parametrize("reason", ["epoch", "expired", "lease"])
def test_expired_authority_does_not_dispatch(harness, monkeypatch, reason):
    h = harness
    if reason == "epoch":
        h.scan.cancel_epoch = 1
    elif reason == "expired":
        h.scope.authorization_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    else:
        monkeypatch.setattr(
            "scopelens.execution.leases.lease_is_live", lambda *args, **kwargs: False
        )
    run(h, lambda index: worker_result([]))
    assert h.calls == []


def test_supervisor_failure_retains_partial_baseline_and_stops_replay(harness):
    from scopelens.execution.supervisor import SupervisorError

    h = harness

    def fail(index):
        raise SupervisorError("unavailable")

    output = run(h, fail, baseline_code=1)
    assert len(h.calls) == 1
    assert output.exit_code == 1 and output.artifacts()[0] == h.initial
    assert h.scan.assessment_plan["hypotheses"][0]["state"] == "inconclusive"


def test_max_task_count_with_distinct_leads_does_not_hit_graph_recursion_limit(harness):
    h = harness
    h.initial = {
        "kind": "exposure_pack",
        "data": {
            "observations": [
                {
                    "family": "config",
                    "url": f"https://app.test/fixture-{index}/.env",
                    "state": "candidate",
                    "body_hash": str(index),
                }
                for index in range(12)
            ]
        },
    }
    run(h, lambda index: worker_result([]))
    assert len(h.calls) == h.settings.adaptive_max_tasks
    assert len(h.scan.assessment_plan["hypotheses"]) == h.settings.adaptive_max_tasks


def test_admission_rechecks_shared_budget_after_planning(harness, monkeypatch):
    h = harness

    def model(*args, **kwargs):
        h.scan.budget_spent["requests"] = h.limits.max_requests
        return {"state": "unavailable"}

    monkeypatch.setattr("scopelens.orchestration.models.call_model", model)
    run(h, lambda index: worker_result([]))
    assert h.calls == []


def test_plan_revision_between_observation_and_admission_blocks_dispatch(harness, monkeypatch):
    h = harness

    def model(*args, **kwargs):
        h.scan.assessment_plan["input_assessment_plan"]["id"] = "changed-plan"
        return {"state": "unavailable"}

    monkeypatch.setattr("scopelens.orchestration.models.call_model", model)
    run(h, lambda index: worker_result([]))
    assert h.calls == []
    assert h.scan.assessment_plan["adaptive_stop"]["reason"] == "frozen_binding_changed"


def test_ledger_links_followup_to_worker_capture_and_proof(harness):
    h = harness
    output = run(h, lambda index: worker_result([h.initial]))
    entry = h.scan.assessment_plan["hypotheses"][0]
    assert entry["task_id"] == h.initial["data"]["task_id"]
    assert entry["plan_id"] == h.scan.assessment_plan["input_assessment_plan"]["id"]
    assert entry["run_id"] == "run-adaptive-0"
    assert len(entry["capture_hashes"]) == 1
    assert entry["proof_detail"]["state"] == "inconclusive"
    assert entry["worker_exit_code"] == 0
    assert entry["request_count"] is None
    followup = output.artifacts()[-1]
    assert followup["hypothesis_id"] == entry["id"]
    assert followup["run_id"] == entry["run_id"]
    assert followup["plan_id"] == entry["plan_id"]
    assert h.scan.assessment_plan["adaptive_stop"] == {
        "reason": "no_eligible_followup",
        "completed_followups": 1,
    }


def test_dynamic_html_body_does_not_repeat_csp_recheck():
    response = {
        "kind": "response",
        "data": {
            "url": "https://app.test/page",
            "route": "/page",
            "status": 200,
            "content_type": "text/html",
            "headers": {},
            "body_excerpt": "first dynamic value",
        },
    }
    first = candidates_from([response], 2)[0]
    response["data"]["body_excerpt"] = "second dynamic value"
    assert candidates_from([response], 2, ledger=[first]) == []
