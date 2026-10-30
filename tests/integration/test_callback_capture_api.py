"""Only live private broker requests produce durable callback request evidence."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from tests.integration.test_callback_configuration_control import enabled_settings, payload
from tests.integration.test_cleanup_revocation import scan_with_capability
from tests.integration.test_expansion_api import scope

from scopelens.api.deps import settings_dependency
from scopelens.callbacks.probes import CallbackProbeRecipe
from scopelens.callbacks.runtime import CallbackDispatchRecordRow, _expected_request
from scopelens.internal_app import create_policy_app
from scopelens.persistence.models import ScanRow, ScopeVersionRow
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


@pytest.fixture
def live_capture(authed_client, settings):
    revised = enabled_settings(authed_client, settings)
    primary = scope(authed_client, allowed_check_profile="staging-stateful-v1")
    configuration = payload(primary)
    response = authed_client.post("/api/assessments/configurations", json=configuration)
    assert response.status_code == 201, response.text
    ident, token, capability = scan_with_capability(authed_client, primary, response.json()["id"])
    app = create_policy_app()
    app.dependency_overrides[settings_dependency] = lambda: revised
    with TestClient(app) as policy:
        issued = policy.post(
            "/internal/broker/assessment",
            json={
                "egress_token": token,
                "capability": capability,
                "operation": "callback_issue",
                "callback_recipe_id": "reviewed-canary",
                "callback_purpose": "negative",
            },
        )
        assert issued.json()["allowed"], issued.text
        recipe = CallbackProbeRecipe.model_validate(configuration["callback_recipes"][0]["recipe"])
        url, body = _expected_request(recipe, issued.json()["nonce"]["url"], "negative")
        begin = {
            "operation": "begin",
            "egress_token": token,
            "method": recipe.method,
            "url": url,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        yield policy, ident, begin


def test_exact_capture_then_response_and_private_route(live_capture, authed_client):
    policy, ident, begin = live_capture
    route = "/internal/broker/callback-dispatch"
    # Same authority and budget do not make a changed request callback proof.
    for field, replacement in (("url", begin["url"] + "x"), ("body_sha256", "f" * 64)):
        result = policy.post(route, json={**begin, field: replacement})
        assert result.json() == {"allowed": True, "dispatch_id": None}
    result = policy.post(route, json=begin)
    assert result.json()["allowed"]
    dispatch_id = result.json()["dispatch_id"]
    assert dispatch_id
    complete = {
        "operation": "complete",
        "egress_token": begin["egress_token"],
        "dispatch_id": dispatch_id,
        "response_status": 204,
    }
    assert policy.post(route, json=complete).json() == {"allowed": True}
    assert policy.post(route, json=complete).json()["allowed"] is False
    with session_scope() as db:
        rows = db.scalars(
            select(CallbackDispatchRecordRow).where(CallbackDispatchRecordRow.scan_id == str(ident))
        ).all()
        assert len(rows) == 1
        assert rows[0].response_status == 204
        assert rows[0].response_at >= rows[0].sent_at
    assert authed_client.post(route, json=begin).status_code == 404
    assert route not in authed_client.get("/openapi.json").text


@pytest.mark.parametrize("revocation", ["cancel", "epoch", "expiry", "unknown"])
def test_revocation_cannot_complete_or_begin_capture(live_capture, revocation):
    policy, ident, begin = live_capture
    route = "/internal/broker/callback-dispatch"
    dispatch_id = policy.post(route, json=begin).json()["dispatch_id"]
    with session_scope() as db:
        scan = db.get(ScanRow, ident)
        if revocation == "cancel":
            scan.cancel_requested_at = datetime.now(UTC)
        elif revocation == "epoch":
            scan.cancel_epoch += 1
        elif revocation == "expiry":
            # Simulate passage past the immutable scope's expiry at the database boundary.
            db.execute(
                update(ScopeVersionRow)
                .where(ScopeVersionRow.id == scan.scope_version_id)
                .values(authorization_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )
    if revocation == "unknown":
        begin["egress_token"] = "unknown-token"
    assert policy.post(route, json=begin).json()["allowed"] is False
    assert (
        policy.post(
            route,
            json={
                "operation": "complete",
                "egress_token": begin["egress_token"],
                "dispatch_id": dispatch_id,
                "response_status": 200,
            },
        ).json()["allowed"]
        is False
    )
    with session_scope() as db:
        assert db.get(CallbackDispatchRecordRow, dispatch_id).response_at is None


def test_capture_shape_rejects_worker_asserted_proof(live_capture):
    policy, _, begin = live_capture
    route = "/internal/broker/callback-dispatch"
    for extra in ({"confirmed": True}, {"response_status": 200}, {"dispatch_id": "invented"}):
        assert policy.post(route, json={**begin, **extra}).status_code == 422
