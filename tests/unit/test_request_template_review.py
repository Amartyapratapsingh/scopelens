"""Frozen review metadata cannot become an execution configuration or expose samples."""

from copy import deepcopy
from uuid import uuid4

import pytest

from scopelens.discovery.planner import plan_assessment
from scopelens.discovery.review import project_review
from scopelens.domain.assessment import DiscoveryCatalogue, RequestTemplate, stable_id


def snapshot():
    scope = str(uuid4())
    template = RequestTemplate(
        id="operation-1",
        origin="https://owned.invalid",
        path="/items/7",
        route_template="/items/7?token=private-query#private-fragment",
        method="GET",
        role_id="A",
        baseline_complete=False,
        baseline_observed=True,
        provenance=("https://private-provenance.invalid/?value=private-response",),
        inputs=(
            {"location": "path", "name": "id", "baseline_value": 7},
            {"location": "query", "name": "q", "baseline_value": "private-baseline"},
            {"location": "query", "name": "q", "occurrence": 1, "baseline_value": "other-value"},
            {"location": "json", "name": "name", "pointer": "/items/0/name", "required": True},
            {
                "location": "header",
                "name": "Authorization",
                "secret_ref": "credential:private-ref",
                "mutable": False,
            },
        ),
    )
    cat = DiscoveryCatalogue(origin=template.origin, templates=(template,))
    plan = plan_assessment(cat, scope_version=scope)
    frozen = {
        "assessment_plan_revisions": [
            {"plan": plan.model_dump(mode="json"), "catalogue": cat.model_dump(mode="json")}
        ]
    }
    args = dict(
        scan_id=uuid4(),
        origin=template.origin,
        scope_version_id=scope,
        profile=plan.profile,
        frozen=frozen,
        plan_id=plan.id,
    )
    return args, plan, template


def test_exact_immutable_metadata_and_stable_input_identifiers():
    args, plan, template = snapshot()
    result = project_review(**args)
    view = result.templates[0]
    assert result.catalogue_hash == plan.catalogue_hash
    assert view.route == "/items/{input}"
    assert view.role_id == "A"
    assert view.baseline_observed and not view.baseline_complete
    assert view.label_redacted
    assert view.tasks.blocked == view.tasks.planned > 0
    assert view.tasks.ready == 0
    assert view.inputs[1].id == stable_id([template.id, template.inputs[1].key])
    assert view.inputs[1].id != view.inputs[2].id
    assert view.inputs[-1].refresh_required and not view.inputs[-1].mutable
    text = result.model_dump_json()
    for forbidden in (
        "private-",
        "other-value",
        "baseline_value",
        "secret_ref",
        "provenance",
        "authority",
        "input_key",
        "approval_ref",
    ):
        assert forbidden not in text
    assert project_review(**args) == result


@pytest.mark.parametrize("change", ["catalogue", "scope", "profile", "plan", "task", "duplicate"])
def test_inconsistent_frozen_bindings_are_rejected(change):
    args, _, _ = snapshot()
    row = args["frozen"]["assessment_plan_revisions"][0]
    if change == "catalogue":
        row["catalogue"]["templates"][0]["inputs"][1]["baseline_value"] = "tampered"
    elif change == "scope":
        args["scope_version_id"] = uuid4()
    elif change == "profile":
        args["profile"] = "staging-stateful-v1"
    elif change == "plan":
        row["plan"]["revision"] += 1
    elif change == "task":
        row["plan"]["tasks"][0]["template_id"] = "missing"
    else:
        args["frozen"]["assessment_plan_revisions"].append(deepcopy(row))
    with pytest.raises(ValueError):
        project_review(**args)


def test_pagination_and_missing_legacy_revision():
    args, _, _ = snapshot()
    assert project_review(**args, offset=1).templates == ()
    assert project_review(**args, limit=1).next_offset is None
    args["frozen"] = {"request_catalogue": {"private": "not a revision"}}
    with pytest.raises(LookupError):
        project_review(**args)


def test_untrusted_display_labels_are_scrubbed_without_returning_raw_provenance():
    args, _, _ = snapshot()
    row = args["frozen"]["assessment_plan_revisions"][0]
    cat = DiscoveryCatalogue.model_validate(row["catalogue"])
    template = cat.templates[0].model_copy(
        update={
            "route_template": "https://private-provenance.invalid/secret",
            "content_type": "token=private-baseline",
        }
    )
    cat = cat.model_copy(update={"templates": (template,)})
    plan = plan_assessment(cat, scope_version=str(args["scope_version_id"]))
    row.update(plan=plan.model_dump(mode="json"), catalogue=cat.model_dump(mode="json"))
    args["plan_id"] = plan.id
    view = project_review(**args).templates[0]
    assert view.route == "[redacted]"
    assert view.content_type == "token=[redacted]"
    assert "private-" not in view.model_dump_json()


def test_multiple_pages_keep_frozen_order_and_occurrences():
    args, _, template = snapshot()
    cat = DiscoveryCatalogue(
        origin=template.origin,
        templates=tuple(template.model_copy(update={"id": ident}) for ident in ("c", "a", "b")),
    )
    plan = plan_assessment(cat, scope_version=str(args["scope_version_id"]))
    args["plan_id"] = plan.id
    args["frozen"] = {
        "assessment_plan_revisions": [
            {"plan": plan.model_dump(mode="json"), "catalogue": cat.model_dump(mode="json")}
        ]
    }
    first = project_review(**args, limit=2)
    second = project_review(**args, offset=first.next_offset, limit=2)
    assert [item.id for item in first.templates] == ["a", "b"]
    assert [item.id for item in second.templates] == ["c"]
    assert first.total == second.total == 3 and second.next_offset is None
    assert (
        len(
            {
                item.id
                for template in (*first.templates, *second.templates)
                for item in template.inputs
            }
        )
        == 15
    )
