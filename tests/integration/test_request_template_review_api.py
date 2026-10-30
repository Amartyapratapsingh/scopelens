"""Owner-bound read-only review of frozen template revisions, with private field omission."""

import uuid
from copy import deepcopy

import pytest
from tests.integration.test_expansion_api import scope
from tests.unit.test_request_template_review import snapshot

from scopelens.discovery.planner import plan_assessment
from scopelens.domain.assessment import DiscoveryCatalogue
from scopelens.persistence.models import ScanRow
from scopelens.persistence.repositories import upsert_operator
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


def stored_plan(client):
    primary = scope(client)
    config = client.post(
        "/api/assessments/configurations", json={"scope_version_id": primary["id"]}
    )
    response = client.post(
        "/api/scans",
        json={
            "scope_version_id": primary["id"],
            "assessment_configuration_id": config.json()["id"],
        },
    )
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    args, _, _ = snapshot()
    row = args["frozen"]["assessment_plan_revisions"][0]
    cat = DiscoveryCatalogue.model_validate(row["catalogue"])
    cat = cat.model_copy(
        update={
            "origin": primary["origin"],
            "templates": tuple(
                t.model_copy(update={"origin": primary["origin"]}) for t in cat.templates
            ),
        }
    )
    with session_scope() as db:
        scan = db.get(ScanRow, uuid.UUID(scan_id))
        plan = plan_assessment(cat, scope_version=primary["id"], profile=scan.profile)
        scan.assessment_plan = {
            "assessment_plan_revisions": [
                {"plan": plan.model_dump(mode="json"), "catalogue": cat.model_dump(mode="json")}
            ],
            "assessment_execution_claims": {"private": "private-claim"},
        }
    return scan_id, plan.id


def url(scan_id, plan_id):
    return f"/api/assessments/scans/{scan_id}/plans/{plan_id}/templates"


def test_review_is_typed_read_only_private_and_revision_stable(authed_client):
    scan_id, plan_id = stored_plan(authed_client)
    path = url(scan_id, plan_id)
    first = authed_client.get(path)
    assert first.status_code == 200, first.text
    assert first.json()["templates"][0]["inputs"][-1]["refresh_required"]
    for forbidden in (
        "private-",
        "baseline_value",
        "secret_ref",
        "provenance",
        "authority",
        "input_key",
        "execution_claims",
    ):
        assert forbidden not in first.text
    with session_scope() as db:
        scan = db.get(ScanRow, uuid.UUID(scan_id))
        frozen = deepcopy(scan.assessment_plan)
        previous = frozen["assessment_plan_revisions"][0]
        from scopelens.domain.assessment import AssessmentPlanVersion

        second = plan_assessment(
            DiscoveryCatalogue.model_validate(previous["catalogue"]),
            scope_version=str(scan.scope_version_id),
            profile=scan.profile,
            previous=AssessmentPlanVersion.model_validate(previous["plan"]),
        )
        frozen["assessment_plan_revisions"].append(
            {"plan": second.model_dump(mode="json"), "catalogue": previous["catalogue"]}
        )
        scan.assessment_plan = frozen
    assert authed_client.get(path).json() == first.json()
    assert authed_client.get(url(scan_id, second.id)).json()["revision"] == 2
    assert authed_client.get(path + "?offset=1&limit=1").json()["templates"] == []
    assert authed_client.get(path + "?limit=201").status_code == 422
    assert authed_client.post(path, json={}).status_code == 405
    schema = authed_client.get("/openapi.json").json()
    endpoint = schema["paths"]["/api/assessments/scans/{scan_id}/plans/{plan_id}/templates"]
    assert set(endpoint) == {"get"}
    assert endpoint["get"]["responses"]["200"]["content"]["application/json"]["schema"][
        "$ref"
    ].endswith("/PlanTemplateReviewView")


def test_review_hides_foreign_owner_and_missing_revision(authed_client):
    scan_id, plan_id = stored_plan(authed_client)
    assert authed_client.get(url(scan_id, "unknown")).status_code == 404
    assert authed_client.get(url(uuid.uuid4(), plan_id)).status_code == 404
    with session_scope() as db:
        other, _ = upsert_operator(db, username="other-review-operator", password_hash="unused")
        db.flush()
        db.get(ScanRow, uuid.UUID(scan_id)).operator_id = other.id
    response = authed_client.get(url(scan_id, plan_id))
    assert response.status_code == 404
    assert response.json() == {"detail": "scan not found"}


@pytest.mark.parametrize("corrupt", ["scope", "profile", "catalogue", "duplicate", "shape"])
def test_review_inconsistent_snapshot_returns_generic_error(authed_client, corrupt, caplog):
    scan_id, plan_id = stored_plan(authed_client)
    with session_scope() as db:
        scan = db.get(ScanRow, uuid.UUID(scan_id))
        frozen = deepcopy(scan.assessment_plan)
        row = frozen["assessment_plan_revisions"][0]
        if corrupt == "scope":
            row["plan"]["scope_version"] = str(uuid.uuid4())
        elif corrupt == "profile":
            row["plan"]["profile"] = "wrong-profile"
        elif corrupt == "catalogue":
            row["catalogue"]["templates"][0]["inputs"][1]["baseline_value"] = "private-tampered"
        elif corrupt == "duplicate":
            frozen["assessment_plan_revisions"].append(deepcopy(row))
        else:
            row["catalogue"] = {"private-invalid": "private-value"}
        scan.assessment_plan = frozen
    response = authed_client.get(url(scan_id, plan_id))
    assert response.status_code == 409
    assert response.json() == {"detail": "assessment plan snapshot is inconsistent"}
    assert "private-" not in response.text + caplog.text


def test_review_legacy_does_not_reconstruct_mutable_current_catalogue(authed_client):
    scan_id, plan_id = stored_plan(authed_client)
    with session_scope() as db:
        scan = db.get(ScanRow, uuid.UUID(scan_id))
        old = scan.assessment_plan["assessment_plan_revisions"][0]
        scan.assessment_plan = {
            "request_catalogue": old["catalogue"],
            "input_assessment_plan": old["plan"],
        }
    assert authed_client.get(url(scan_id, plan_id)).status_code == 404


def test_review_requires_operator_login(client):
    response = client.get(url(uuid.uuid4(), "unknown"))
    assert response.status_code == 401
