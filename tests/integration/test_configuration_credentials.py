"""Configuration intake rejects unavailable credentials before persisting a plan."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr
from sqlalchemy import func, select
from tests.integration.test_expansion_api import scope

from scopelens.api.deps import settings_dependency
from scopelens.identities.secrets import EncryptedSecretStore
from scopelens.persistence.models import AssessmentConfigurationRow, ScopeVersionRow
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


@pytest.fixture
def credential_context(authed_client, settings, tmp_path):
    key = Fernet.generate_key()
    revised = settings.model_copy(
        update={
            "identity_encryption_key": SecretStr(key.decode()),
            "identity_store_path": tmp_path / "credentials",
        }
    )
    authed_client.app.dependency_overrides[settings_dependency] = lambda: revised
    primary = scope(
        authed_client,
        allowed_check_profile="authenticated-api-v1",
        allowed_methods=["GET", "HEAD", "POST"],
    )
    with session_scope() as db:
        owner = str(db.get(ScopeVersionRow, uuid.UUID(primary["id"])).operator_id)
    store = EncryptedSecretStore(revised.identity_store_path, key)
    return primary, owner, store


def configuration(primary, reference, location):
    request = {"url": primary["origin"] + "/me"}
    identity = {
        "id": "reader",
        "role": "reader",
        "probe": {"request": request, "expected_identity": "fixture-reader"},
    }
    payload = {"scope_version_id": primary["id"], "identities": [identity]}
    if location == "supplied_headers":
        identity["supplied_headers"] = {"Authorization": reference}
    elif location == "secret_fields":
        identity["login"] = {
            "request": {
                "url": primary["origin"] + "/login",
                "method": "POST",
                "secret_fields": {"password": reference},
            }
        }
    elif location == "secret_headers":
        request["secret_headers"] = {"Authorization": reference}
    elif location == "logout":
        payload["session_policies"] = [
            {
                "identity_id": "reader",
                "cookie_name": "session",
                "logout": {
                    "url": primary["origin"] + "/logout",
                    "method": "POST",
                    "secret_headers": {"X-CSRF-Token": reference},
                },
            }
        ]
    elif location == "secret_ref":
        payload["templates"] = [
            {
                "id": "read-profile",
                "origin": primary["origin"],
                "path": "/me",
                "route_template": "/me",
                "method": "GET",
                "role_id": "reader",
                "inputs": [
                    {
                        "location": "header",
                        "name": "Authorization",
                        "secret_ref": reference,
                        "mutable": False,
                    }
                ],
            }
        ]
    else:
        raise AssertionError("unknown credential location")
    return payload


@pytest.mark.parametrize(
    "location", ["supplied_headers", "secret_fields", "secret_headers", "logout", "secret_ref"]
)
def test_each_reference_location_is_validated_and_never_returns_secret(
    authed_client, credential_context, location, caplog
):
    primary, owner, store = credential_context
    value = "synthetic-credential-not-for-return"
    reference = store.put(
        SecretStr(value),
        owner=owner,
        scope_id=primary["id"],
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    response = authed_client.post(
        "/api/assessments/configurations", json=configuration(primary, reference, location)
    )
    assert response.status_code == 201, response.text
    assert value not in response.text + caplog.text

    (store.root / reference).unlink()
    response = authed_client.post(
        "/api/assessments/configurations", json=configuration(primary, reference, location)
    )
    assert response.status_code == 422
    assert reference not in response.text + caplog.text
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(AssessmentConfigurationRow)) == 1


@pytest.mark.parametrize("failure", ["owner", "scope", "expired", "corrupt", "invalid"])
def test_bad_reference_rejected_without_persisting_or_disclosing_credential(
    authed_client, credential_context, failure, caplog
):
    primary, owner, store = credential_context
    value = "synthetic-private-credential-marker"
    reference = store.put(
        SecretStr(value),
        owner=str(uuid.uuid4()) if failure == "owner" else owner,
        scope_id=str(uuid.uuid4()) if failure == "scope" else primary["id"],
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    if failure == "expired":
        path = store.root / reference
        record = json.loads(store.cipher.decrypt(path.read_bytes()))
        record["expires"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        path.write_bytes(store.cipher.encrypt(json.dumps(record).encode()))
    elif failure == "corrupt":
        (store.root / reference).write_bytes(b"damaged-encrypted-record")
    elif failure == "invalid":
        reference = "not-a-reference"
    response = authed_client.post(
        "/api/assessments/configurations",
        json=configuration(primary, reference, "supplied_headers"),
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "credential reference is unavailable for this scope"}
    assert value not in response.text + caplog.text
    assert reference not in response.text + caplog.text
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(AssessmentConfigurationRow)) == 0
