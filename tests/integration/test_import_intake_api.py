"""Owner-bound import intake and durable coordinator-side revision claims."""

import json
import uuid

import pytest
from sqlalchemy import select, text
from tests.integration.test_expansion_api import scope
from tests.unit.test_import_intake import imported

from scopelens.domain.assessment import ActionPolicy
from scopelens.domain.enums import ProfileName
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.execution.supervisor import (
    RESULT_MARKER,
    RecordingSupervisor,
    WorkerResult,
    WorkerSpec,
)
from scopelens.expansion.integration import run_expansion
from scopelens.persistence.models import AssessmentConfigurationRow, AuditEventRow, ScanRow
from scopelens.persistence.repositories import scope_row_to_domain
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


def envelope(primary):
    return {
        "scope_version_id": primary["id"],
        "kind": "har",
        "document": {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": primary["origin"] + "/imported?query=synthetic-private-query",
                            "method": "GET",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer synthetic-private-auth"}
                            ],
                            "cookies": [{"name": "sid", "value": "synthetic-private-cookie"}],
                            "postData": {
                                "mimeType": "application/json",
                                "text": '{"value":"synthetic-private-body"}',
                            },
                        },
                        "response": {"content": {"text": "synthetic-private-response"}},
                    }
                ]
            }
        },
    }


def test_import_to_immutable_configuration_retains_only_metadata(authed_client, caplog):
    primary = scope(authed_client)
    response = authed_client.post("/api/assessments/imports", json=envelope(primary))
    assert response.status_code == 200, response.text
    normalized = response.json()
    assert "synthetic-private" not in response.text
    frozen = authed_client.post(
        "/api/assessments/configurations",
        json={"scope_version_id": primary["id"], "imports": [normalized]},
    )
    assert frozen.status_code == 201, frozen.text
    fetched = authed_client.get("/api/assessments/configurations/" + frozen.json()["id"])
    assert fetched.json() == frozen.json()
    with session_scope() as db:
        stored = db.get(AssessmentConfigurationRow, uuid.UUID(frozen.json()["id"]))
        serialized = json.dumps(stored.configuration)
        audits = json.dumps([r.detail for r in db.scalars(select(AuditEventRow)).all()])
    assert "synthetic-private" not in fetched.text + serialized + audits + caplog.text
    assert "document" not in stored.configuration["imports"][0]
    unknown = {**envelope(primary), "scope_version_id": str(uuid.uuid4())}
    assert authed_client.post("/api/assessments/imports", json=unknown).status_code == 404


@pytest.mark.parametrize("invalid", ["scope", "shape", "json", "size", "config"])
def test_rejections_never_echo_raw_private_inputs(authed_client, invalid, caplog):
    primary = scope(authed_client)
    body = envelope(primary)
    path = "/api/assessments/imports"
    if invalid == "scope":
        body["scope_version_id"] = "synthetic-private-invalid-uuid"
    elif invalid == "shape":
        body["document"]["log"]["entries"] = "synthetic-private-invalid-entries"
    elif invalid == "config":
        path = "/api/assessments/configurations"
        body = {
            "scope_version_id": primary["id"],
            "imports": [{"document": "synthetic-private-value"}],
        }
    raw = json.dumps(body).encode()
    if invalid == "json":
        raw = b'{"synthetic-private-value":'
    elif invalid == "size":
        raw += b" " * 1_048_576
    response = authed_client.post(path, content=raw, headers={"content-type": "application/json"})
    assert response.status_code == (413 if invalid == "size" else 422)
    assert "synthetic-private" not in response.text + caplog.text


def test_cross_scope_import_cannot_be_frozen(authed_client):
    primary, other = scope(authed_client), scope(authed_client)
    normalized = authed_client.post("/api/assessments/imports", json=envelope(primary)).json()
    response = authed_client.post(
        "/api/assessments/configurations",
        json={"scope_version_id": other["id"], "imports": [normalized]},
    )
    assert response.status_code == 422


def test_runtime_persists_revision_before_dispatch_and_never_replays_admitted_task(
    queued_scan, db_session, settings, monkeypatch
):
    scan, _ = queued_scan
    target = scope_row_to_domain(scan.scope_version).model_copy(
        update={"allowed_check_profile": ProfileName.EXTERNAL_ACTIVE_V2}
    )
    item = imported("openapi")
    template = item.catalogue.templates[0].model_copy(
        update={"origin": target.origin, "baseline_complete": True, "authority": "primary"}
    )
    policy = ActionPolicy(
        template_id=template.id,
        role_id="anonymous",
        classification="read_only",
        approval_ref="fixture",
        control_ids=("SL-C04-CORS-01",),
    )
    config = AssessmentConfiguration(
        scope_version_id=scan.scope_version_id, templates=(template,), policies=(policy,)
    )
    scan.assessment_plan = {"expansion_config": config.model_dump(mode="json")}
    db_session.commit()
    count = []

    class Observe(RecordingSupervisor):
        def run(self, spec, *, run_id):
            payload = json.loads(spec.environment["SCOPELENS_EXPANSION_INPUT"])
            ready = [t for t in payload["plan"]["tasks"] if t["state"] == "ready"]
            with session_scope(settings) as db:
                # A separate connection takes the scan lock while supervisor work runs.
                db.execute(text("SET LOCAL lock_timeout = '1s'"))
                current = db.get(ScanRow, scan.id)
                db.refresh(current, with_for_update=True)
                frozen = current.assessment_plan
                assert frozen["input_assessment_plan"]["id"] == payload["plan"]["id"]
                assert all(
                    "task:" + t["id"] in frozen["assessment_execution_claims"] for t in ready
                )
            count.append(ready)
            # Deliberately unknown first outcome: not safe to infer it never ran.
            return WorkerResult(
                run_id, 1 if len(count) == 1 else 0, RESULT_MARKER + '{"ok": true}', "", 0
            )

    supervisor = Observe()
    spec = WorkerSpec(image="reviewed-fixture", command=[], environment={}, network="none")
    prior = WorkerResult("base", 0, RESULT_MARKER + '{"ok": true}', "", 0)
    run_expansion(settings, supervisor, spec, prior, run_id="first", scan_id=scan.id, scope=target)
    run_expansion(settings, supervisor, spec, prior, run_id="second", scan_id=scan.id, scope=target)
    assert len(count[0]) == 1 and count[1] == []
    with session_scope(settings) as db:
        frozen = db.get(ScanRow, scan.id).assessment_plan
        history = frozen["assessment_plan_revisions"]
        assert len(history) == 2
        assert history[0]["plan"]["denominator"] == history[1]["plan"]["denominator"]
        assert history[1]["plan"]["previous_id"] == history[0]["plan"]["id"]
        assert len(frozen["assessment_execution_claims"]) == 1


def test_history_is_typed_and_owner_bound(authed_client):
    schema = authed_client.get("/openapi.json").json()
    assert "/api/assessments/imports" in schema["paths"]
    assert schema["paths"]["/api/assessments/imports"]["post"]["requestBody"]["required"]
    response = authed_client.get(f"/api/assessments/scans/{uuid.uuid4()}/plans")
    assert response.status_code == 404


def test_history_omits_stored_baselines_and_credential_references(authed_client):
    from types import SimpleNamespace

    from scopelens.domain.assessment import RequestTemplate
    from scopelens.expansion.integration import freeze_revision, prepare_catalogue

    primary = scope(authed_client)
    config_response = authed_client.post(
        "/api/assessments/configurations", json={"scope_version_id": primary["id"]}
    )
    response = authed_client.post(
        "/api/scans",
        json={
            "scope_version_id": primary["id"],
            "assessment_configuration_id": config_response.json()["id"],
        },
    )
    assert response.status_code == 202, response.text
    ident = response.json()["id"]
    template = RequestTemplate(
        id="reviewed-template",
        origin=primary["origin"],
        path="/record",
        route_template="/record",
        method="GET",
        inputs=(
            {"location": "query", "name": "q", "baseline_value": "private-baseline-only"},
            {
                "location": "header",
                "name": "Authorization",
                "secret_ref": "private-credential-reference",
                "mutable": False,
            },
        ),
    )
    config = AssessmentConfiguration(scope_version_id=primary["id"], templates=(template,))
    target = SimpleNamespace(id=primary["id"], allowed_check_profile=ProfileName.EXTERNAL_ACTIVE_V2)
    cat = prepare_catalogue(primary["origin"], [], config)
    frozen, plan, _, _ = freeze_revision(
        {}, cat, config, scope=target, run_id="private-history-test"
    )
    with session_scope() as db:
        scan = db.get(ScanRow, uuid.UUID(ident))
        scan.assessment_plan = frozen
    history = authed_client.get(f"/api/assessments/scans/{ident}/plans")
    assert history.status_code == 200, history.text
    assert "private-baseline-only" not in history.text
    assert "private-credential-reference" not in history.text
    assert "input_key" not in history.text and "baseline_value" not in history.text
    assert history.json()["revisions"][0]["catalogue"]["template_ids"] == [template.id]
    assert history.json()["revisions"][0]["plan"]["denominator"] == plan.denominator
