"""Persisted callback recipes and authenticated capability RPC, no target traffic."""

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from tests.integration.test_cleanup_revocation import scan_with_capability
from tests.integration.test_expansion_api import scope

from scopelens.api.deps import settings_dependency
from scopelens.internal_app import create_policy_app

pytestmark = pytest.mark.db


def payload(primary):
    return {
        "scope_version_id": primary["id"],
        "callback_recipes": [
            {
                "id": "reviewed-canary",
                "recipe": {
                    "family": "ssrf",
                    "target_url": primary["origin"] + "/preview?url=baseline",
                    "parameter": "url",
                    "callback_origin": "http://collector.test",
                    "expected_target_peers": ["192.0.2.10"],
                    "scanner_peers": ["192.0.2.20"],
                    "approved_staging": True,
                    "unexpected_external_fetch": True,
                },
            }
        ],
    }


def enabled_settings(client, settings):
    revised = settings.model_copy(
        update={
            "callback_collector_origins": ("http://collector.test",),
            "callback_signing_key": SecretStr("test-callback-signing-key-with-32-bytes"),
        }
    )
    client.app.dependency_overrides[settings_dependency] = lambda: revised
    return revised


def test_disabled_by_default(authed_client):
    primary = scope(authed_client, allowed_check_profile="staging-stateful-v1")
    response = authed_client.post("/api/assessments/configurations", json=payload(primary))
    assert response.status_code == 503


@pytest.mark.parametrize(
    "change", ["profile", "origin", "target", "ambiguous", "method", "duplicate"]
)
def test_callback_configuration_rejects_unbound_authority(authed_client, settings, change):
    enabled_settings(authed_client, settings)
    primary = scope(
        authed_client,
        allowed_check_profile="external-active-v2"
        if change == "profile"
        else "staging-stateful-v1",
    )
    value = payload(primary)
    recipe = value["callback_recipes"][0]["recipe"]
    if change == "origin":
        recipe["callback_origin"] = "http://other.test"
    elif change == "target":
        recipe["target_url"] = "http://other.test/preview?url=baseline"
    elif change == "ambiguous":
        recipe["scanner_peers"] = ["::ffff:192.0.2.10"]
    elif change == "method":
        recipe.update(family="xxe", method="POST", parameter=None)
    elif change == "duplicate":
        value["callback_recipes"].append(value["callback_recipes"][0])
    response = authed_client.post("/api/assessments/configurations", json=value)
    assert response.status_code == 422, response.text


def test_callback_rpc_bound_to_frozen_task_and_revocation(authed_client, settings):
    revised = enabled_settings(authed_client, settings)
    primary = scope(authed_client, allowed_check_profile="staging-stateful-v1")
    created = authed_client.post("/api/assessments/configurations", json=payload(primary))
    assert created.status_code == 201, created.text
    ident, token, capability = scan_with_capability(authed_client, primary, created.json()["id"])
    app = create_policy_app()
    app.dependency_overrides[settings_dependency] = lambda: revised
    base = {
        "egress_token": token,
        "capability": capability,
        "operation": "callback_issue",
        "callback_recipe_id": "reviewed-canary",
        "callback_purpose": "negative",
    }
    with TestClient(app) as policy:
        route = "/internal/broker/assessment"
        denied = policy.post(route, json={**base, "capability": "wrong"})
        assert not denied.json()["allowed"]
        assert not policy.post(route, json={**base, "callback_recipe_id": "other"}).json()[
            "allowed"
        ]
        assert (
            policy.post(route, json={**base, "expected_target_peers": ["192.0.2.99"]}).status_code
            == 422
        )
        issued = policy.post(route, json=base)
        assert issued.status_code == 200, issued.text
        assert issued.json()["allowed"], issued.text
        nonce = issued.json()["nonce"]
        assert nonce["scan_id"] == str(ident)
        assert nonce["task_id"].startswith("callback:reviewed-canary:")
        assert not policy.post(route, json=base).json()["allowed"]
        assert authed_client.post(f"/api/scans/{ident}/cancel").status_code == 200
        query = {
            **base,
            "operation": "callback_query",
            "callback_purpose": None,
            "callback_nonce_id": nonce["id"],
        }
        assert not policy.post(route, json=query).json()["allowed"]
        assert not policy.post(route, json={**query, "operation": "callback_revoke"}).json()[
            "allowed"
        ]
