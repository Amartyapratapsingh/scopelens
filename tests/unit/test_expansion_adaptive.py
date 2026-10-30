import httpx
import pytest
from fastapi.testclient import TestClient
from labs.expansion_tools.app import create_app
from tests.unit.test_expanded_active import active_fixture as _active_fixture

from scopelens.discovery import discover_catalogue, plan_assessment
from scopelens.domain.assessment import ActionPolicy
from scopelens.orchestration.expansion import (
    execute_followup,
    hypotheses_from,
    select_hypothesis,
    verify_followup,
)

active_fixture = _active_fixture


def prepared(origin, family="sql", path="/bad/sql"):
    key = "next=/safe" if family == "redirect" else "q=apple"
    cat = discover_catalogue(
        origin, browser_requests=[{"url": origin + path + "?" + key, "method": "GET"}]
    )
    policies = tuple(
        ActionPolicy(
            template_id=t.id, role_id=t.role_id, classification="read_only", approval_ref="fixture"
        )
        for t in cat.templates
    )
    control = "SL-C04-REDIRECT-01" if family == "redirect" else "SL-C03-SQL-01"
    plan = plan_assessment(
        cat, scope_version="scope", policies=policies, reviewed_control_ids=(control,)
    )
    artifact = {
        "kind": "expanded_active_probe",
        "data": {
            "task_id": plan.tasks[0].id,
            "state": "inconclusive",
            "kind": family,
            "reason": "ambiguous initial observation",
        },
    }
    return cat, plan, artifact


@pytest.mark.parametrize("family", ["sql", "redirect"])
@pytest.mark.parametrize("variant", ["bad", "fixed"])
def test_actual_http_followup_proves_or_rejects_lead(active_fixture, family, variant):
    origin, requests = active_fixture
    cat, plan, artifact = prepared(origin, family, f"/{variant}/{family}")
    hypothesis = hypotheses_from([artifact], cat, plan)[0]
    with httpx.Client(timeout=2, trust_env=False) as client:
        output = execute_followup(client, hypothesis, cat, plan)
    verdict = verify_followup(hypothesis, output)
    assert verdict["state"] == ("corroborated" if variant == "bad" else "contradicted")
    assert len(requests) <= hypothesis.max_requests


def test_exposure_followup_rechecks_new_negative_control():
    cat, plan, _ = prepared("http://testserver")
    artifact = {
        "kind": "exposure_pack",
        "data": {
            "observations": [
                {
                    "family": "config",
                    "url": "http://testserver/.env",
                    "state": "candidate",
                    "body_hash": "old",
                }
            ]
        },
    }
    hypothesis = hypotheses_from([artifact], cat, plan)[0]
    for vulnerable in (True, False):
        with TestClient(create_app(vulnerable)) as client:
            artifacts = execute_followup(client, hypothesis, cat, plan)
        verdict = verify_followup(hypothesis, artifacts)
        assert verdict["state"] == ("corroborated" if vulnerable else "contradicted")


def test_budget_no_duplicate_and_new_evidence_round_limit():
    cat, plan, artifact = prepared("https://app.test")
    hypothesis = hypotheses_from([artifact], cat, plan)[0]
    assert (
        select_hypothesis([hypothesis], remaining_requests=30, protected_baseline_requests=10)
        is None
    )
    assert (
        select_hypothesis([hypothesis], remaining_requests=30, chosen_id="invented") == hypothesis
    )
    ledger = [hypothesis.model_dump()]
    assert hypotheses_from([artifact], cat, plan, ledger=ledger) == []
    for n in (2, 3):
        artifact["data"]["captures"] = [{"body_hash": str(n)}]
        next_hyp = hypotheses_from([artifact], cat, plan, ledger=ledger)[0]
        assert next_hyp.round == n
        ledger.append(next_hyp.model_dump())
    artifact["data"]["captures"] = [{"body_hash": "4"}]
    assert hypotheses_from([artifact], cat, plan, ledger=ledger) == []


def test_cross_origin_and_unsupported_model_confirmation_rejected():
    cat, plan, artifact = prepared("https://app.test")
    bad = {
        "kind": "exposure_pack",
        "data": {
            "observations": [
                {"family": "config", "url": "https://other.test/.env", "state": "exposed"}
            ]
        },
    }
    assert hypotheses_from([bad], cat, plan) == []
    hyp = hypotheses_from([artifact], cat, plan)[0]
    assert (
        verify_followup(hyp, [{"kind": "model", "data": {"confirmed": True}}])["state"]
        == "inconclusive"
    )


def test_component_followup_stays_identity_only():
    cat, plan, _ = prepared("https://app.test")
    response = {
        "kind": "response",
        "data": {
            "url": "https://app.test/app.js",
            "status": 200,
            "headers": {},
            "body_excerpt": "/*! jQuery v3.4.1 */",
            "via_proxy": True,
        },
    }
    hypothesis = hypotheses_from([response], cat, plan)[0]
    verdict = verify_followup(hypothesis, [response])
    assert verdict["state"] == "corroborated" and verdict["proof_state"] == "potential"


def test_access_and_callback_without_capabilities_are_explicit_gaps():
    cat, plan, _ = prepared("https://app.test")
    artifacts = [
        {"kind": "identity_response", "data": {"proof_type": "access", "proof_id": "rule"}},
        {
            "kind": "callback_capture",
            "source": "callback_broker",
            "data": {"recipe_id": "callback"},
        },
        {"kind": "callback_diagnostic", "data": {"recipe_id": "callback", "state": "confirmed"}},
    ]
    configuration = {
        "permission_matrix": {
            "rules": [{"id": "rule", "object_id": "record", "family": "bola"}],
            "objects": [{"id": "record", "request": {"url": "https://app.test/record"}}],
        },
        "callback_recipes": [
            {
                "id": "callback",
                "recipe": {"family": "ssrf", "target_url": "https://app.test/preview?url=baseline"},
            }
        ],
    }
    candidates = hypotheses_from(artifacts, cat, plan, configuration=configuration)
    assert {h.family for h in candidates} == {"access", "callback"}
    assert {h.control for h in candidates} == {"SL-C09-BOLA-01", "SL-C07-SSRF-02"}
    assert all(h.state == "blocked" for h in candidates)
    assert select_hypothesis(candidates, remaining_requests=100) is None
    assert hypotheses_from([artifacts[-1]], cat, plan, configuration=configuration) == []


def test_bookkeeping_changes_do_not_authorize_identical_followup():
    cat, plan, artifact = prepared("https://app.test")
    artifact["data"].update(timestamp="first", run_id="first", evidence_ref="first")
    first = hypotheses_from([artifact], cat, plan)[0]
    artifact["data"].update(timestamp="second", run_id="second", evidence_ref="second")
    assert hypotheses_from([artifact], cat, plan, ledger=[first.model_dump()]) == []


def test_unreviewed_extra_field_is_not_fresh_evidence():
    cat, plan, artifact = prepared("https://app.test")
    first = hypotheses_from([artifact], cat, plan)[0]
    artifact["data"]["new_evidence"] = "untrusted claim"
    assert hypotheses_from([artifact], cat, plan, ledger=[first.model_dump()]) == []


@pytest.mark.parametrize("state", ["outcome_unknown", "corroborated", "contradicted"])
def test_unknown_or_resolved_hypothesis_does_not_run_again(state):
    cat, plan, artifact = prepared("https://app.test")
    first = hypotheses_from([artifact], cat, plan)[0]
    artifact["data"]["captures"] = [{"body_hash": "changed"}]
    assert (
        hypotheses_from([artifact], cat, plan, ledger=[{**first.model_dump(), "state": state}])
        == []
    )


def test_changed_frozen_plan_or_task_cannot_execute_followup(active_fixture):
    origin, requests = active_fixture
    cat, plan, artifact = prepared(origin, "sql", "/bad/sql")
    hypothesis = hypotheses_from([artifact], cat, plan)[0]
    before = len(requests)
    changed_plan = plan.model_copy(update={"id": "another-plan"})
    with httpx.Client(timeout=2, trust_env=False) as client:
        blocked = execute_followup(client, hypothesis, cat, changed_plan)
        changed_task = plan.tasks[0].model_copy(update={"control_id": "different-control"})
        changed_plan = plan.model_copy(update={"tasks": (changed_task,)})
        blocked_task = execute_followup(client, hypothesis, cat, changed_plan)
    assert blocked[0]["kind"] == blocked_task[0]["kind"] == "adaptive_gap"
    assert len(requests) == before


def test_changed_catalogue_cannot_propose_or_execute_followup(active_fixture):
    origin, requests = active_fixture
    cat, plan, artifact = prepared(origin, "sql", "/bad/sql")
    hypothesis = hypotheses_from([artifact], cat, plan)[0]
    altered = cat.model_copy(update={"templates": ()})
    assert hypotheses_from([artifact], altered, plan) == []
    before = len(requests)
    with httpx.Client(timeout=2, trust_env=False) as client:
        result = execute_followup(client, hypothesis, altered, plan)
    assert result[0]["kind"] == "adaptive_gap"
    assert len(requests) == before


def test_followup_proof_requires_exact_frozen_task_and_reviewed_capture(active_fixture):
    origin, _ = active_fixture
    cat, plan, artifact = prepared(origin, "redirect", "/bad/redirect")
    hypothesis = hypotheses_from([artifact], cat, plan)[0]
    with httpx.Client(timeout=2, trust_env=False) as client:
        captures = execute_followup(client, hypothesis, cat, plan)
    assert verify_followup(hypothesis, captures)["state"] == "corroborated"
    for field, value in (
        ("plan_id", "other-plan"),
        ("template_id", "other-template"),
        ("control_id", "other-control"),
        ("kind", "sql"),
        ("reviewed", False),
    ):
        altered = [{**captures[0], "data": {**captures[0]["data"], field: value}}]
        assert verify_followup(hypothesis, altered)["state"] == "inconclusive"
