"""CORS frozen recipes require exact live scope grants and read-only requests."""

import uuid

import pytest
from scripts.verify_credentialed_cors_lab import configuration
from tests.integration.test_expansion_api import scope

pytestmark = pytest.mark.db


def pair(client, **foreign_options):
    primary = scope(
        client,
        allowed_check_profile="authenticated-api-v1",
        allowed_methods=["GET", "HEAD", "POST"],
    )
    foreign = scope(
        client,
        lab_service="labs-good",
        allowed_check_profile="authenticated-api-v1",
        **foreign_options,
    )
    payload = configuration(primary, foreign, "bad", "synthetic-reference")
    payload["identities"][0]["login"] = None  # No stored credential is needed to test admission.
    return primary, foreign, payload


def test_cors_configuration_persists_exact_related_scope_without_mutation_recipe(authed_client):
    primary, foreign, payload = pair(authed_client, allowed_path_prefixes=["/foreign"])
    response = authed_client.post("/api/assessments/configurations", json=payload)
    assert response.status_code == 201, response.text
    frozen = response.json()["configuration"]
    assert frozen["cors_recipes"][0]["foreign_scope_version_id"] == foreign["id"]
    assert frozen["scope_version_id"] == primary["id"]
    assert frozen["workflows"] == frozen["browser_workflows"] == []


@pytest.mark.parametrize(
    "change,expected",
    [
        ("foreign_path", 422),
        ("target_path", 422),
        ("unknown_scope", 404),
        ("origin_mismatch", 422),
        ("resource_only", 422),
        ("profile", 422),
    ],
)
def test_invalid_cors_scope_binding_is_rejected(authed_client, change, expected):
    primary, foreign, payload = pair(authed_client, allowed_path_prefixes=["/foreign"])
    recipe = payload["cors_recipes"][0]
    if change == "foreign_path":
        recipe["foreign_url"] = foreign["origin"] + "/not-approved"
    elif change == "target_path":
        primary = scope(
            authed_client,
            allowed_check_profile="authenticated-api-v1",
            allowed_path_prefixes=["/bad/identity"],
        )
        payload["scope_version_id"] = primary["id"]
    elif change == "unknown_scope":
        unknown = str(uuid.uuid4())
        recipe["foreign_scope_version_id"] = unknown
        payload["related_origins"][0]["scope_version_id"] = unknown
    elif change == "origin_mismatch":
        recipe["foreign_url"] = "http://not-approved.invalid/foreign"
    elif change == "resource_only":
        payload["related_origins"][0]["purpose"] = "resource_only"
    else:
        primary = scope(authed_client)
        payload["scope_version_id"] = primary["id"]
    response = authed_client.post("/api/assessments/configurations", json=payload)
    assert response.status_code == expected, response.text
