"""Production policy HTTP routes and PostgreSQL cleanup persistence, no target writes."""

import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from tests.integration.test_expansion_api import scope

from scopelens.api.deps import settings_dependency
from scopelens.broker.policy import issue_egress_token
from scopelens.execution.leases import acquire_lease
from scopelens.internal_app import create_policy_app
from scopelens.persistence.models import CleanupRow, ScanRow
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


def configuration(primary):
    origin = primary["origin"]
    return {
        "scope_version_id": primary["id"],
        "identities": [
            {"id": role, "role": role, "anonymous": True} for role in ("writer", "viewer")
        ],
        "browser_workflows": [
            {
                "id": "workflow-review",
                "family": "stored_xss",
                "resource_id": "disposable-review-record",
                "action_grant_id": "operator-review",
                "authority": "lab",
                "disposable": True,
                "synchronous_write": True,
                "actor_identity": "writer",
                "viewer_identity": "viewer",
                "cleanup_identity": "writer",
                "readback": {"url": origin + "/record"},
                "seed": {"pointer": "/seed", "value": "synthetic-review-marker"},
                "before": {"pointer": "/content", "value": ""},
                "mutation": {"method": "POST", "url": origin + "/mutation"},
                "mutation_field": "content",
                "cleanup": {"method": "POST", "url": origin + "/cleanup"},
                "viewer_url": origin + "/viewer",
            }
        ],
    }


def scan_with_capability(client, primary, config_id):
    response = client.post(
        "/api/scans",
        json={"scope_version_id": primary["id"], "assessment_configuration_id": config_id},
    )
    assert response.status_code == 202, response.text
    ident = uuid.UUID(response.json()["id"])
    capability = uuid.uuid4().hex
    with session_scope() as db:
        scan = db.get(ScanRow, ident)
        scan.assessment_plan = {
            **scan.assessment_plan,
            "expansion_capability_hash": hashlib.sha256(capability.encode()).hexdigest(),
        }
        token = issue_egress_token(db, scan=scan)
        acquire_lease(db, scan_id=ident, holder="review", ttl_seconds=300)
    return ident, token, capability


@pytest.mark.parametrize("last_state", ["pending", "mutation_sent"])
@pytest.mark.parametrize("renew_scope", [False, True])
def test_cancel_denies_target_and_cleanup_rpc_preserves_resource_fence(
    authed_client, settings, last_state, renew_scope
):
    primary = scope(
        authed_client,
        allowed_check_profile="staging-stateful-v1",
        allowed_methods=["GET", "HEAD", "POST"],
    )
    response = authed_client.post("/api/assessments/configurations", json=configuration(primary))
    assert response.status_code == 201, response.text
    config_id = response.json()["id"]
    ident, token, capability = scan_with_capability(authed_client, primary, config_id)
    app = create_policy_app()
    app.dependency_overrides[settings_dependency] = lambda: settings
    with TestClient(app) as policy:
        command = {
            "egress_token": token,
            "capability": capability,
            "recipe_id": "workflow-review",
            "resource_id": "disposable-review-record",
        }

        def rpc(operation, **fields):
            response = policy.post(
                "/internal/broker/assessment", json={**command, "operation": operation, **fields}
            )
            assert response.status_code == 200, response.text
            return response.json()

        assert rpc("cleanup_claim")["allowed"]
        if last_state == "mutation_sent":
            assert rpc("cleanup_mark", state="mutation_sent")["allowed"]
            assert not rpc("cleanup_mark", state="mutation_sent")["allowed"]
        assert authed_client.post(f"/api/scans/{ident}/cancel").status_code == 200
        assert not rpc("cleanup_mark", state="cleanup_failed")["allowed"]
        assert not rpc("cleanup_mark", state="clean")["allowed"]
        from urllib.parse import urlsplit

        url = urlsplit(primary["origin"])
        response = policy.post(
            "/internal/broker/authorize",
            json={
                "egress_token": token,
                "method": "GET",
                "scheme": url.scheme,
                "host": url.hostname,
                "port": url.port or 80,
                "path": "/cleanup",
            },
        )
        assert response.status_code == 200
        assert response.json()["allowed"] is False
        assert response.json()["reason"] == "revoked_egress_token"
        with session_scope() as db:
            row = db.scalar(select(CleanupRow).where(CleanupRow.scan_id == ident))
            assert row.state == last_state
        if renew_scope:
            previous_id = primary["id"]
            primary = scope(
                authed_client,
                allowed_check_profile="staging-stateful-v1",
                allowed_methods=["GET", "HEAD", "POST"],
            )
            assert primary["id"] != previous_id
            response = authed_client.post(
                "/api/assessments/configurations", json=configuration(primary)
            )
            assert response.status_code == 201, response.text
            config_id = response.json()["id"]
        _, fresh_token, fresh_capability = scan_with_capability(authed_client, primary, config_id)
        command.update(egress_token=fresh_token, capability=fresh_capability)
        result = rpc("cleanup_claim")
        assert result == {"allowed": False, "reason": "unresolved_cleanup"}
        assert not rpc("cleanup_mark", state="clean")["allowed"]


def test_browser_configuration_rejects_unapproved_viewer_and_unknown_cleanup_identity(
    authed_client,
):
    primary = scope(
        authed_client, allowed_check_profile="staging-stateful-v1", allowed_methods=["GET", "POST"]
    )
    payload = configuration(primary)
    payload["browser_workflows"][0]["viewer_url"] = "https://unapproved.invalid/view"
    assert authed_client.post("/api/assessments/configurations", json=payload).status_code == 422
    payload = configuration(primary)
    payload["browser_workflows"][0]["cleanup_identity"] = "not-configured"
    assert authed_client.post("/api/assessments/configurations", json=payload).status_code == 422
