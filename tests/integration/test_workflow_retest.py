"""Configuration and case binding for fresh authenticated workflow retests."""

import uuid

import pytest
from tests.integration.test_api import lab_scope_payload
from tests.integration.test_dashboard_api import add_finding

from scopelens.checks.retest import reconcile_retests
from scopelens.domain.check import ControlOutcome, ProofResult
from scopelens.domain.enums import Category, EvidenceStatus
from scopelens.domain.enums import ControlOutcome as Outcome
from scopelens.persistence.models import CheckOutcomeRow, ScanRow

pytestmark = pytest.mark.db


def configured_finding(client, db):
    scope = client.post(
        "/api/scopes", json=lab_scope_payload(allowed_check_profile="authenticated-api-v1")
    ).json()
    config = client.post(
        "/api/assessments/configurations", json={"scope_version_id": scope["id"]}
    ).json()
    response = client.post(
        "/api/scans",
        json={"scope_version_id": scope["id"], "assessment_configuration_id": config["id"]},
    )
    assert response.status_code == 202, response.text
    scan = db.get(ScanRow, uuid.UUID(response.json()["id"]))
    finding = add_finding(db, scan)
    finding.check_id = "SL-C11-WORKFLOW-01"
    finding.canonical_control = "workflow.workflow_authorization"
    finding.category = "C11"
    finding.locations = [
        {"route": scan.target_origin + "/records/test/marks", "detail": "academic-marks"}
    ]
    scan.assessment_plan = {
        **scan.assessment_plan,
        "adaptive_requested": True,
        "execution_claims": ["stale"],
    }
    original = outcome(finding, ("academic-marks", "academic-attendance"))
    db.add(
        CheckOutcomeRow(
            scan_id=scan.id,
            check_id=finding.check_id,
            canonical_control=finding.canonical_control,
            category="C11",
            status="pass",
            payload=original.model_dump(mode="json"),
        )
    )
    db.commit()
    return scan, finding, config


def outcome(finding, instances):
    return ControlOutcome(
        check_id=finding.check_id,
        canonical_control=finding.canonical_control,
        category=Category.C11_BUSINESS_RULES,
        status=Outcome.PASS,
        required_instances=instances,
        completed_instances=instances,
        proof=ProofResult(
            satisfied=True, status=EvidenceStatus.INCONCLUSIVE, evidence_refs=("fresh-proof",)
        ),
    )


def test_retest_preserves_only_immutable_configuration_not_execution_claims(
    authed_client, db_session
):
    original, finding, config = configured_finding(authed_client, db_session)
    response = authed_client.post(f"/api/findings/{finding.id}/retest")
    assert response.status_code == 202, response.text
    fresh = db_session.get(ScanRow, uuid.UUID(response.json()["scan_id"]))
    assert fresh.assessment_plan["configuration_id"] == config["id"]
    assert fresh.assessment_plan["configuration_hash"] == config["content_hash"]
    assert fresh.assessment_plan["expansion_config"] == original.assessment_plan["expansion_config"]
    assert "execution_claims" not in fresh.assessment_plan
    assert fresh.assessment_plan["adaptive_requested"] is False


@pytest.mark.parametrize(
    "changed", ["none", "case_set", "config_hash", "proof_missing", "scope", "profile"]
)
def test_fresh_workflow_proof_uses_original_cases_and_configuration(
    authed_client, db_session, changed
):
    _original, finding, _ = configured_finding(authed_client, db_session)
    response = authed_client.post(f"/api/findings/{finding.id}/retest")
    assert response.status_code == 202, response.text
    fresh = db_session.get(ScanRow, uuid.UUID(response.json()["scan_id"]))
    result = outcome(
        finding,
        ("academic-marks", "academic-attendance") if changed != "case_set" else ("unrelated",),
    )
    if changed == "proof_missing":
        result = result.model_copy(update={"proof": None})
    if changed == "config_hash":
        fresh.assessment_plan = {**fresh.assessment_plan, "configuration_hash": "different"}
    if changed == "profile":
        fresh.profile = "external-configuration"
    if changed == "scope":
        other = authed_client.post(
            "/api/scopes", json=lab_scope_payload(lab_service="labs-good")
        ).json()
        fresh.scope_version_id = uuid.UUID(other["id"])
    fresh.status = "completed_partial"
    db_session.add(
        CheckOutcomeRow(
            scan_id=fresh.id,
            check_id=finding.check_id,
            canonical_control=finding.canonical_control,
            category="C11",
            status="pass",
            payload=result.model_dump(mode="json"),
        )
    )
    db_session.flush()
    reconcile_retests(db_session, fresh)
    db_session.commit()
    db_session.refresh(finding)
    assert finding.retest_state == ("fixed" if changed == "none" else "incomplete")
    assert finding.status == ("resolved" if changed == "none" else "open")


@pytest.mark.parametrize("change", ["none", "case", "host", "profile"])
def test_retest_can_renew_authority_only_for_identical_declared_cases(
    authed_client, db_session, change
):
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import update

    from scopelens.persistence.models import ScopeVersionRow

    original, finding, config = configured_finding(authed_client, db_session)
    db_session.execute(
        update(ScopeVersionRow)
        .where(ScopeVersionRow.id == original.scope_version_id)
        .values(authorization_expires_at=datetime.now(UTC) - timedelta(hours=1))
    )
    db_session.commit()
    scope = authed_client.post(
        "/api/scopes",
        json=lab_scope_payload(
            lab_service="labs-good" if change == "host" else "labs-bad",
            allowed_check_profile="staging-stateful-v1"
            if change == "profile"
            else "authenticated-api-v1",
        ),
    ).json()
    frozen = {**original.assessment_plan["expansion_config"], "scope_version_id": scope["id"]}
    if change == "case":
        frozen["identities"] = [{"id": "new-role", "role": "new-role", "anonymous": True}]
    renewed = authed_client.post("/api/assessments/configurations", json=frozen)
    assert renewed.status_code == 201, renewed.text
    response = authed_client.post(
        f"/api/findings/{finding.id}/retest",
        json={
            "scope_version_id": scope["id"],
            "assessment_configuration_id": renewed.json()["id"],
        },
    )
    if change != "none":
        assert response.status_code == 409, response.text
        return
    assert response.status_code == 202, response.text
    fresh = db_session.get(ScanRow, uuid.UUID(response.json()["scan_id"]))
    assert (
        fresh.assessment_plan["retest_renewal"]["source_configuration_hash"]
        == config["content_hash"]
    )
    assert original.assessment_plan["configuration_hash"] == config["content_hash"]
    proved = outcome(finding, ("academic-marks", "academic-attendance"))
    db_session.add(
        CheckOutcomeRow(
            scan_id=fresh.id,
            check_id=finding.check_id,
            canonical_control=finding.canonical_control,
            category="C11",
            status="pass",
            payload=proved.model_dump(mode="json"),
        )
    )
    fresh.status = "completed_partial"
    db_session.flush()
    reconcile_retests(db_session, fresh)
    assert finding.retest_state == "fixed"
    assert finding.status == "resolved"
