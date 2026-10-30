"""Accounting annotations are not URL, scope, profile or input approval grants."""

from types import SimpleNamespace

import pytest

from scopelens.broker.policy import BrokerRequest
from scopelens.broker.probe_tasks import input_reference, reviewed_request_limit
from scopelens.config import Settings
from scopelens.domain.assessment import (
    AssessmentPlanVersion,
    AssessmentTask,
    InputLocation,
    RequestTemplate,
    stable_id,
)
from scopelens.domain.enums import ProfileName
from scopelens.scope.validator import ScopeViolation


def expanded_scan(**updates):
    template = RequestTemplate(
        id="template",
        origin="https://fixture.invalid",
        path="/app/search",
        route_template="/app/search",
        method="GET",
        baseline_observed=True,
        inputs=(
            InputLocation(location="query", name="q", baseline_value="bar"),
            InputLocation(location="query", name="fixed", baseline_value="stable"),
        ),
    ).model_copy(update=updates)
    catalogue = {"templates": [template.model_dump(mode="json")]}
    task = AssessmentTask(
        id="task",
        template_id="template",
        control_id="SL-C03-SQL-01",
        input_key="query:q:0",
        state="ready",
        reason="approved",
    )
    plan = AssessmentPlanVersion(
        id="plan",
        revision=1,
        scope_version="scope",
        catalogue_hash=stable_id(catalogue),
        tasks=(task,),
        denominator=1,
    )
    return SimpleNamespace(
        scope_version_id="scope",
        assessment_plan={
            "request_catalogue": catalogue,
            "input_assessment_plan": plan.model_dump(mode="json"),
            "assessment_execution_claims": {"task:task": {"state": "admitted", "plan_id": "plan"}},
        },
    )


def request(path="/app/search?q=marker&fixed=stable", **changes):
    fields = dict(
        method="GET",
        scheme="https",
        host="fixture.invalid",
        port=443,
        path=path,
        egress_token="fixture",
        probe_task=input_reference("task"),
    )
    return BrokerRequest(**{**fields, **changes})


def limit(scan, req):
    scope = SimpleNamespace(
        origin="https://fixture.invalid", allowed_check_profile=ProfileName.EXTERNAL_ACTIVE_V2
    )
    return reviewed_request_limit(scan, scope, Settings(), req)


def test_admitted_frozen_task_uses_existing_cap():
    assert limit(expanded_scan(), request()) == 36


@pytest.mark.parametrize(
    "change", ["missing_claim", "wrong_claim_plan", "catalogue_tamper", "wrong_scope", "blocked"]
)
def test_frozen_task_binding_is_required(change):
    scan = expanded_scan()
    plan = scan.assessment_plan
    if change == "missing_claim":
        plan["assessment_execution_claims"] = {}
    elif change == "wrong_claim_plan":
        plan["assessment_execution_claims"]["task:task"]["plan_id"] = "other"
    elif change == "catalogue_tamper":
        plan["request_catalogue"]["templates"][0]["path"] = "/app/other"
    elif change == "wrong_scope":
        scan.scope_version_id = "other"
    else:
        plan["input_assessment_plan"]["tasks"][0]["state"] = "blocked"
    with pytest.raises(ScopeViolation):
        limit(scan, request())


@pytest.mark.parametrize(
    "changes",
    [
        {"authority": "resource_only"},
        {"authority": "unapproved"},
        {"baseline_complete": False},
        {
            "inputs": (
                InputLocation(location="query", name="q", baseline_value="bar", mutable=False),
            )
        },
    ],
)
def test_non_executable_template_cannot_exempt_pages(changes):
    with pytest.raises(ScopeViolation):
        limit(expanded_scan(**changes), request())


@pytest.mark.parametrize(
    "req",
    [
        request("/app/other?q=marker&fixed=stable"),
        request("/app/search?q=marker&fixed=changed"),
        request("/app/search?q=marker&extra=stable"),
        request("/app/search?q=marker&q=duplicate&fixed=stable"),
        request(host="other.invalid"),
        request(method="POST"),
        request(probe_task="input:unknown"),
    ],
)
def test_task_reference_does_not_authorize_another_request(req):
    with pytest.raises(ScopeViolation):
        limit(expanded_scan(), req)
