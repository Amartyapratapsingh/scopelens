"""Academic projections remain owner-bound, typed, private and read-only."""

import uuid
from copy import deepcopy

import pytest
from tests.integration.test_expansion_api import scope

from scopelens.persistence.models import AssessmentConfigurationRow, ScanRow
from scopelens.persistence.repositories import upsert_operator
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


def configuration(client):
    primary = scope(client, allowed_check_profile="authenticated-api-v1")
    private = "private-academic-label"
    response = client.post(
        "/api/assessments/configurations",
        json={
            "scope_version_id": primary["id"],
            "identities": [
                {
                    "id": private,
                    "role": private,
                    "probe": {
                        "request": {"url": primary["origin"] + "/me?private_query=hidden"},
                        "expected_identity": private,
                    },
                }
            ],
            "permission_matrix": {
                "version": private,
                "objects": [
                    {
                        "id": private,
                        "owner_identity": private,
                        "request": {"url": primary["origin"] + "/record?record=hidden"},
                        "marker_pointer": "/hidden",
                        "marker": "private-academic-marker",
                    }
                ],
                "rules": [
                    {
                        "id": private,
                        "object_id": private,
                        "identity_id": private,
                        "family": "object",
                        "allowed": True,
                    }
                ],
            },
        },
    )
    assert response.status_code == 201, response.text
    return primary, response.json()


def cfg_url(ident):
    return f"/api/academic/configurations/{ident}/readiness"


def scan_url(ident):
    return f"/api/academic/scans/{ident}/readiness"


def create_scan(client, primary, config):
    response = client.post(
        "/api/scans",
        json={"scope_version_id": primary["id"], "assessment_configuration_id": config["id"]},
    )
    assert response.status_code == 202, response.text
    return response.json()["id"]


def test_config_projection_is_private_stable_and_does_not_resolve_or_dispatch(
    authed_client, monkeypatch
):
    _, config = configuration(authed_client)
    path = cfg_url(config["id"])
    monkeypatch.setattr(
        "scopelens.api.assessments.secret_store",
        lambda _: pytest.fail("readiness must not resolve secrets"),
    )
    with session_scope() as db:
        before = db.query(ScanRow).count()
    response = authed_client.get(path)
    assert response.status_code == 200, response.text
    assert authed_client.get(path).json() == response.json()
    data = response.json()
    assert data["configuration_hash"] == config["content_hash"]
    assert data["coverage"]["configured"] == data["coverage"]["blocked"] == 1
    assert data["coverage"]["executed"] == data["coverage"]["proven"] == 0
    assert data["actors"][0]["identity_evidence"] == "not_observed"
    assert "credential_setup_required" in data["cases"][0]["blocked_reasons"]
    for private in (
        "private-academic",
        "private_query",
        "hidden",
        "json_body",
        "secret_fields",
        "marker_pointer",
        "/me",
        "/record",
        "https://",
    ):
        assert private not in response.text
    assert authed_client.post(path, json={}).status_code == 405
    with session_scope() as db:
        assert db.query(ScanRow).count() == before
    schema = authed_client.get("/openapi.json").json()
    path_schema = schema["paths"]["/api/academic/configurations/{configuration_id}/readiness"]
    assert set(path_schema) == {"get"}
    assert path_schema["get"]["responses"]["200"]["content"]["application/json"]["schema"][
        "$ref"
    ].endswith("/AcademicReadiness")


def test_scan_uses_same_frozen_configuration_and_report_counts(authed_client):
    primary, config = configuration(authed_client)
    scan_id = create_scan(authed_client, primary, config)
    response = authed_client.get(scan_url(scan_id))
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["configuration_hash"] == config["content_hash"]
    assert data["scan_id"] == scan_id
    assert data["coverage"]["executed"] == data["coverage"]["proven"] == 0
    summary = authed_client.get(f"/api/scans/{scan_id}/summary").json()
    for key, value in data["capabilities"].items():
        assert value == summary["capabilities"][key]["count"]
    assert data["reach"]["planned"] == summary["reach"]["planned"]
    assert authed_client.get(scan_url(scan_id)).json() == data
    with session_scope() as db:
        scan = db.get(ScanRow, uuid.UUID(scan_id))
        frozen = deepcopy(scan.assessment_plan)
        frozen["configuration_hash"] = "0" * 64
        frozen["expansion_config"]["identities"][0]["probe"]["expected_identity"] = (
            "private-malformed"
        )
        scan.assessment_plan = frozen
    conflict = authed_client.get(scan_url(scan_id))
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "academic assessment snapshot is inconsistent"}


def test_missing_and_other_owner_configuration_and_scan_are_404(authed_client):
    primary, config = configuration(authed_client)
    scan_id = create_scan(authed_client, primary, config)
    assert authed_client.get(cfg_url(uuid.uuid4())).status_code == 404
    assert authed_client.get(scan_url(uuid.uuid4())).status_code == 404
    with session_scope() as db:
        other, _ = upsert_operator(db, username="academic-other-owner", password_hash="unused")
        scan = db.get(ScanRow, uuid.UUID(scan_id))
        scan.operator_id = other.id
    assert authed_client.get(scan_url(scan_id)).status_code == 404
    from scopelens.api.deps import require_operator

    authed_client.app.dependency_overrides[require_operator] = lambda: other
    try:
        assert authed_client.get(cfg_url(config["id"])).status_code == 404
    finally:
        authed_client.app.dependency_overrides.pop(require_operator)
    authed_client.post("/api/auth/logout")
    assert authed_client.get(cfg_url(config["id"])).status_code == 401
    assert authed_client.get(scan_url(scan_id)).status_code == 401


def test_invalid_persisted_configuration_hash_is_generic_conflict(authed_client, db_session):
    _, config = configuration(authed_client)
    # Direct SQL models storage corruption without disabling the immutability listener.
    from sqlalchemy import update

    db_session.execute(
        update(AssessmentConfigurationRow)
        .where(AssessmentConfigurationRow.id == uuid.UUID(config["id"]))
        .values(content_hash="0" * 64)
    )
    db_session.commit()
    response = authed_client.get(cfg_url(config["id"]))
    assert response.status_code == 409
    assert "private-academic" not in response.text


def test_scan_projects_only_intake_bound_test_captures_and_not_worker_verdicts(
    authed_client, settings
):
    from tests.unit.test_academic_readiness import capture, response

    from scopelens.domain.evidence import EvidenceOrigin
    from scopelens.domain.expansion import AssessmentConfiguration
    from scopelens.evidence.intake import record_json_evidence
    from scopelens.evidence.store import LocalDiskEvidenceStore
    from scopelens.persistence.models import TaskRow

    primary, config_view = configuration(authed_client)
    scan_id = create_scan(authed_client, primary, config_view)
    config = AssessmentConfiguration.model_validate(config_view["configuration"])
    matrix = config.permission_matrix
    rule, obj, actor = matrix.rules[0], matrix.objects[0], config.identities[0]
    captures = []

    def probe():
        captures.append(
            response(
                rule.id, actor.id, actor.probe.request, {"identity": actor.probe.expected_identity}
            )
        )

    probe()
    captures.append(response(rule.id, actor.id, obj.request, {"hidden": obj.marker}))
    probe()
    for _ in range(2):
        probe()
        captures.append(response(rule.id, actor.id, obj.request, {"hidden": obj.marker}))
        probe()
    store = LocalDiskEvidenceStore(settings.evidence_store_path)
    with session_scope() as db:
        scan = db.get(ScanRow, uuid.UUID(scan_id))
        task = db.query(TaskRow).filter(TaskRow.scan_id == scan.id).one()
        for artifact in captures:
            record_json_evidence(
                db,
                settings=settings,
                store=store,
                scan=scan,
                origin=EvidenceOrigin.SUPERVISOR,
                producer="reviewed_expansion_capture",
                producer_hash="a" * 64,
                payload=artifact,
                task_id=task.id,
                run_id="one",
            )
        forged = capture("identity_observation", "workflow", "forged", {"confirmed": True})
        record_json_evidence(
            db,
            settings=settings,
            store=store,
            scan=scan,
            origin=EvidenceOrigin.UNTRUSTED_OBSERVATION,
            producer="reviewed_expansion_capture",
            producer_hash="a" * 64,
            payload=forged,
            task_id=task.id,
            run_id="one",
        )
    data = authed_client.get(scan_url(scan_id)).json()
    assert data["coverage"]["executed"] == data["coverage"]["proven"] == 1
    assert data["coverage"]["confirmed_issues"] == 0
    assert data["cases"][0]["proof"] == "pass"
    assert len(data["cases"][0]["evidence_refs"]) == 9
    assert data["actors"][0]["identity_evidence"] == "verified_probe"
    assert "private-academic" not in str(data)
