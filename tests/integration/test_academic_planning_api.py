"""Planning shares readiness ownership and snapshot checks without dispatch."""

import uuid
from copy import deepcopy

import pytest
from tests.integration.test_academic_readiness_api import configuration, create_scan

from scopelens.persistence.models import ScanRow
from scopelens.persistence.repositories import upsert_operator
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


def cfg_url(ident):
    return f"/api/academic/configurations/{ident}/plan"


def scan_url(ident):
    return f"/api/academic/scans/{ident}/plan"


def test_plan_routes_are_typed_private_stable_read_only_and_budget_bounded(
    authed_client, monkeypatch
):
    primary, config = configuration(authed_client)
    scan_id = create_scan(authed_client, primary, config)
    monkeypatch.setattr(
        "scopelens.api.assessments.secret_store",
        lambda _: pytest.fail("plan must not resolve secrets"),
    )
    with session_scope() as db:
        before = db.query(ScanRow).count()
        frozen = deepcopy(db.get(ScanRow, uuid.UUID(scan_id)).assessment_plan)
    for path in (cfg_url(config["id"]), scan_url(scan_id)):
        response = authed_client.get(path)
        assert response.status_code == 200, response.text
        data = response.json()
        assert authed_client.get(path).json() == data
        assert data["configuration_hash"] == config["content_hash"]
        assert data["budget"]["baseline_reserved"] == data["budget"]["baseline_blocked"] == 1
        assert data["agenda"][0]["state"] == "blocked"
        assert data["agenda"][0]["recommendation"] == "resolve_declared_prerequisites"
        assert data["coverage"]["executed"] == 0
        assert not data["execution_authority"]
        assert "private-academic" not in response.text
        assert "hidden" not in response.text
        assert authed_client.post(path, json={}).status_code == 405
        assert authed_client.get(path + "?followup_limit=21").status_code == 422
        assert authed_client.get(path + "?followup_limit=-1").status_code == 422
        limited = authed_client.get(path + "?followup_limit=0").json()
        assert limited["agenda"] == data["agenda"]
        assert limited["budget"]["baseline_reserved"] == data["budget"]["baseline_reserved"]
    with session_scope() as db:
        assert db.query(ScanRow).count() == before
        assert db.get(ScanRow, uuid.UUID(scan_id)).assessment_plan == frozen
    schema = authed_client.get("/openapi.json").json()
    for path in (
        "/api/academic/configurations/{configuration_id}/plan",
        "/api/academic/scans/{scan_id}/plan",
    ):
        assert set(schema["paths"][path]) == {"get"}
        assert schema["paths"][path]["get"]["responses"]["200"]["content"]["application/json"][
            "schema"
        ]["$ref"].endswith("/AcademicPlan")


def test_plan_requires_owner_session_and_matching_frozen_snapshot(authed_client):
    primary, config = configuration(authed_client)
    scan_id = create_scan(authed_client, primary, config)
    assert authed_client.get(cfg_url(uuid.uuid4())).status_code == 404
    assert authed_client.get(scan_url(uuid.uuid4())).status_code == 404
    with session_scope() as db:
        other, _ = upsert_operator(db, username="academic-plan-other-owner", password_hash="unused")
    from scopelens.api.deps import require_operator

    authed_client.app.dependency_overrides[require_operator] = lambda: other
    try:
        assert authed_client.get(cfg_url(config["id"])).status_code == 404
        assert authed_client.get(scan_url(scan_id)).status_code == 404
    finally:
        authed_client.app.dependency_overrides.pop(require_operator)
    with session_scope() as db:
        scan = db.get(ScanRow, uuid.UUID(scan_id))
        frozen = deepcopy(scan.assessment_plan)
        frozen["configuration_hash"] = "0" * 64
        scan.assessment_plan = frozen
    conflict = authed_client.get(scan_url(scan_id))
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "academic assessment snapshot is inconsistent"}
    authed_client.post("/api/auth/logout")
    assert authed_client.get(cfg_url(config["id"])).status_code == 401
    assert authed_client.get(scan_url(scan_id)).status_code == 401
