"""A review order cannot extend the frozen declarations or bypass a blocker."""

import uuid
from datetime import timedelta

import pytest
from tests.unit.test_academic_readiness import (
    NOW,
    ORIGIN,
    access_captures,
    inputs,
    scan_inputs,
    workflow_captures,
)

from scopelens.academic.planning import project_plan
from scopelens.academic.readiness import project_readiness
from scopelens.domain.capabilities import canonical_sha256


def test_plan_is_stable_private_and_reserves_all_declared_baseline_cases():
    args = inputs()
    readiness = project_readiness(**args)
    plan = project_plan(readiness)
    assert project_plan(readiness) == plan
    assert plan.readiness_revision == readiness.revision
    assert plan.configuration_hash == args["configuration_hash"]
    assert plan.budget.baseline_reserved == plan.budget.baseline_ready == 4
    assert plan.budget.baseline_blocked == 0
    assert plan.budget.followup_selected == 0
    assert plan.coverage == readiness.coverage
    assert {item.case for item in plan.agenda} == set(readiness.cases)
    assert [item.order for item in plan.agenda] == list(range(1, 5))
    assert all(item.baseline_purpose == "allowed_comparison" for item in plan.agenda[:2])
    assert all(item.priority == 0 for item in plan.agenda)
    assert not plan.execution_authority and not plan.budget.execution_budget_reserved
    for private in ("student_a", "student_b", "academic-lab-password", ORIGIN, "/marks"):
        assert private not in plan.model_dump_json()


def test_trusted_proof_can_rank_declared_cases_without_consuming_baseline_or_executing():
    args = scan_inputs(inputs())
    args["artifacts"] = access_captures(args["config"]) + workflow_captures(args["config"])
    readiness = project_readiness(**args)
    plan = project_plan(readiness, followup_limit=1)
    confirmed = {case.id for case in readiness.cases if case.proof == "confirmed_issue"}
    assert len(confirmed) == 2
    assert {item.case.id for item in plan.agenda if item.priority == 2} == confirmed
    assert plan.budget.baseline_reserved == 4
    assert plan.budget.followup_selected == plan.budget.followup_deferred == 1
    assert plan.followups[0].case_id in confirmed
    assert not plan.followups[0].executed
    assert plan.followups[0].reason == "confirmed_case_review"
    no_followup = project_plan(readiness, followup_limit=0)
    assert no_followup.agenda == plan.agenda
    assert no_followup.coverage == plan.coverage
    assert no_followup.budget.baseline_reserved == plan.budget.baseline_reserved
    assert not no_followup.followups
    assert no_followup.revision != plan.revision


def test_bad_or_partial_proof_does_not_raise_priority_to_a_confirmed_case():
    args = scan_inputs(inputs())
    args["artifacts"] = access_captures(args["config"])
    # A forged worker verdict has no bearing on production proof evaluation.
    for artifact in args["artifacts"]:
        artifact["data"].update({"confirmed": True, "severity": "critical"})
    args["artifacts"][0]["data"]["document"] = {"identity": "wrong"}
    readiness = project_readiness(**args)
    assert readiness.coverage.confirmed_issues == 0
    plan = project_plan(readiness)
    assert all(item.priority < 2 for item in plan.agenda)
    assert all(item.reason == "observed_case_missing_proof" for item in plan.followups)
    assert {item.case.id for item in plan.agenda} == {case.id for case in readiness.cases}
    assert not plan.execution_authority
    # Captures for an undeclared rule cannot create a case or a follow-up.
    for artifact in args["artifacts"]:
        artifact["data"]["proof_id"] = "undeclared-rule"
    other = project_plan(project_readiness(**args))
    assert not other.followups
    assert all(item.priority == 0 for item in other.agenda)


def test_proof_never_unblocks_missing_credentials_expiry_or_a_resource_fence():
    args = inputs()
    config = args["config"]
    args["config"] = config.model_copy(
        update={
            "identities": tuple(
                actor.model_copy(update={"login": None, "expires_at": NOW - timedelta(seconds=1)})
                for actor in config.identities
            )
        }
    )
    args["configuration_hash"] = canonical_sha256(args["config"].model_dump(mode="json"))
    args = scan_inputs(args)
    # Historical proof uses the same declared probes and actors, but current
    # configuration prerequisites still determine readiness for later work.
    args["artifacts"] = access_captures(config) + workflow_captures(config)
    args["cleanup_rows"] = [
        {
            "scan_id": str(uuid.uuid4()),
            "recipe_id": "different-property",
            "resource_id": config.workflows[0].resource_id,
            "state": "cleanup_failed",
        }
    ]
    plan = project_plan(project_readiness(**args))
    assert plan.budget.baseline_blocked == plan.budget.baseline_reserved == 4
    assert all(item.state == "blocked" for item in plan.agenda)
    assert all(item.recommendation == "resolve_declared_prerequisites" for item in plan.agenda)
    assert all("credential_setup_required" in item.case.blocked_reasons for item in plan.agenda)
    assert all("declared_identity_expired" in item.case.blocked_reasons for item in plan.agenda)
    workflow = next(item for item in plan.agenda if item.case.kind == "workflow")
    assert "resource_cleanup_fenced" in workflow.case.blocked_reasons
    assert workflow.case.proof == "confirmed_issue"
    assert all(item.state == "blocked" and item.blocked_reasons for item in plan.followups)
    assert all(not item.executed for item in plan.followups)


@pytest.mark.parametrize("limit", [-1, 21, True, 2.5, "3"])
def test_followup_limit_is_bounded(limit):
    with pytest.raises(ValueError):
        project_plan(project_readiness(**inputs()), followup_limit=limit)


def test_feature_counts_preserve_declared_transition_and_allowed_control_primitives():
    readiness = project_readiness(**inputs())
    features = {feature.code: feature for feature in readiness.features}
    assert features["single_action_workflow_transitions"].configured_cases == 1
    assert features["allowed_permission_controls"].configured_cases == 2
    assert features["approval_sequence"].reason_codes == (
        "explicit_multistep_transition_contract_not_supported",
    )
    assert "role_change_transition_not_established" in features["session_lifecycle"].reason_codes
