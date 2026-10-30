"""Expanded scan inputs persist atomically and cannot borrow another scope's authority."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from tests.integration.test_api import lab_scope_payload

from scopelens.api.deps import settings_dependency
from scopelens.identities.secrets import EncryptedSecretStore
from scopelens.persistence.models import AssessmentConfigurationRow, ScanRow
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


def scope(client, **kwargs):
    response = client.post(
        "/api/scopes",
        json=lab_scope_payload(**{"allowed_check_profile": "external-active-v2", **kwargs}),
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_expanded_scan_requires_frozen_configuration(authed_client):
    primary = scope(authed_client)
    assert (
        authed_client.post("/api/scans", json={"scope_version_id": primary["id"]}).status_code
        == 422
    )
    created = authed_client.post(
        "/api/assessments/configurations", json={"scope_version_id": primary["id"]}
    )
    assert created.status_code == 201, created.text
    configuration = created.json()
    assert len(configuration["content_hash"]) == 64
    response = authed_client.post(
        "/api/scans",
        json={
            "scope_version_id": primary["id"],
            "assessment_configuration_id": configuration["id"],
        },
    )
    assert response.status_code == 202, response.text
    with session_scope() as db:
        scan = db.get(ScanRow, uuid.UUID(response.json()["id"]))
        assert scan.assessment_plan["configuration_hash"] == configuration["content_hash"]
        assert scan.assessment_plan["expansion_config"]["scope_version_id"] == primary["id"]
    other = scope(authed_client)
    assert (
        authed_client.post(
            "/api/scans",
            json={
                "scope_version_id": other["id"],
                "assessment_configuration_id": configuration["id"],
            },
        ).status_code
        == 404
    )


def test_related_grant_must_match_registered_scope(authed_client):
    primary = scope(authed_client)
    related = scope(authed_client, lab_service="labs-good")
    grant = {
        "origin": related["origin"],
        "purpose": "scan",
        "grant_id": "review-1",
        "scope_version_id": related["id"],
    }
    response = authed_client.post(
        "/api/assessments/configurations",
        json={"scope_version_id": primary["id"], "related_origins": [grant]},
    )
    assert response.status_code == 201, response.text
    grant["origin"] = "https://not-approved.invalid"
    assert (
        authed_client.post(
            "/api/assessments/configurations",
            json={"scope_version_id": primary["id"], "related_origins": [grant]},
        ).status_code
        == 422
    )


def test_credential_intake_is_encrypted_and_value_not_returned(authed_client, settings, tmp_path):
    key = Fernet.generate_key()
    revised = settings.model_copy(
        update={
            "identity_encryption_key": SecretStr(key.decode()),
            "identity_store_path": tmp_path / "credentials",
        }
    )
    authed_client.app.dependency_overrides[settings_dependency] = lambda: revised
    primary = scope(authed_client, allowed_methods=["GET", "HEAD", "POST"])
    value = "synthetic-credential-only-for-test"
    expiry = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
    response = authed_client.post(
        "/api/assessments/credentials",
        json={"scope_version_id": primary["id"], "value": value, "expires_at": expiry},
    )
    assert response.status_code == 201, response.text
    assert value not in response.text
    ref = response.json()["reference"]
    assert value.encode() not in (tmp_path / "credentials" / ref).read_bytes()
    with session_scope() as db:
        from scopelens.persistence.models import ScopeVersionRow

        owner = str(db.get(ScopeVersionRow, uuid.UUID(primary["id"])).operator_id)
    store = EncryptedSecretStore(tmp_path / "credentials", key)
    assert store.resolve(ref, owner=owner, scope_id=primary["id"]).get_secret_value() == value


def test_configuration_is_immutable(authed_client):
    primary = scope(authed_client)
    response = authed_client.post(
        "/api/assessments/configurations", json={"scope_version_id": primary["id"]}
    )
    with pytest.raises(ValueError, match="immutable"), session_scope() as db:
        row = db.get(AssessmentConfigurationRow, uuid.UUID(response.json()["id"]))
        row.configuration = {"changed": True}
        db.flush()


def test_identity_on_unauthenticated_profile_is_rejected(authed_client):
    primary = scope(authed_client)
    response = authed_client.post(
        "/api/assessments/configurations",
        json={
            "scope_version_id": primary["id"],
            "identities": [{"id": "anonymous", "role": "anonymous", "anonymous": True}],
        },
    )
    assert response.status_code == 422


def test_internal_credentials_need_separate_capability_and_live_lease(
    db_session, queued_scan, settings, tmp_path
):
    import hashlib

    from scopelens.broker.policy import issue_egress_token, revoke_egress
    from scopelens.execution.leases import acquire_lease
    from scopelens.expansion.control import AssessmentCommand, command

    scan, _ = queued_scan
    key = Fernet.generate_key()
    revised = settings.model_copy(
        update={
            "identity_encryption_key": SecretStr(key.decode()),
            "identity_store_path": tmp_path / "credentials",
        }
    )
    ref = EncryptedSecretStore(revised.identity_store_path, key).put(
        SecretStr("test-secret"),
        owner=str(scan.operator_id),
        scope_id=str(scan.scope_version_id),
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    capability = "independent-fixed-worker-capability"
    scan.assessment_plan = {
        "expansion_capability_hash": hashlib.sha256(capability.encode()).hexdigest(),
        "expansion_config": {
            "scope_version_id": str(scan.scope_version_id),
            "identities": [
                {
                    "id": "test",
                    "role": "reader",
                    "supplied_headers": {"Authorization": ref},
                    "probe": {
                        "request": {"url": scan.target_origin + "/me"},
                        "expected_identity": "test",
                    },
                }
            ],
        },
    }
    token = issue_egress_token(db_session, scan=scan)
    acquire_lease(db_session, scan_id=scan.id, holder="test", ttl_seconds=300)
    request = AssessmentCommand(
        egress_token=token, capability="wrong", operation="credential", reference=ref
    )
    assert command(db_session, revised, request)["allowed"] is False
    request = request.model_copy(update={"capability": capability})
    assert command(db_session, revised, request)["value"] == "test-secret"
    assert (
        command(db_session, revised, request.model_copy(update={"reference": "0" * 48}))["allowed"]
        is False
    )
    revoke_egress(db_session, scan=scan)
    assert command(db_session, revised, request)["allowed"] is False
