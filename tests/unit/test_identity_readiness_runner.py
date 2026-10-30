from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from scripts.verify_identity_readiness_configuration import validate

from scopelens.domain.capabilities import canonical_sha256
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import IdentityProfile, IdentityRequest, SessionProbe


def fixture():
    scope_id = uuid4()
    configuration = AssessmentConfiguration(
        scope_version_id=scope_id,
        identities=(
            IdentityProfile(
                id="student",
                role="student",
                supplied_headers={"Cookie": "synthetic-encrypted-reference"},
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
                probe=SessionProbe(
                    request=IdentityRequest(url="https://owned.example.com/auerp/home"),
                    identity_pointer="/identity",
                    expected_identity="synthetic-student",
                ),
            ),
        ),
    )
    payload = configuration.model_dump(mode="json")
    saved = {"configuration": payload, "content_hash": canonical_sha256(payload)}
    scope = {
        "expired": False,
        "allowed_methods": ["GET", "HEAD"],
        "allowed_check_profile": "authenticated-api-v1",
    }
    return scope_id, scope, saved


def test_runner_accepts_only_the_fresh_readiness_configuration():
    scope_id, scope, saved = fixture()
    assert validate(scope, saved, scope_id).identities[0].id == "student"


@pytest.mark.parametrize(
    "case",
    [
        "expired-scope",
        "write-method",
        "active-profile",
        "wrong-scope",
        "changed-hash",
        "expired-session",
    ],
)
def test_runner_rejects_unsafe_or_stale_execution_before_scan_creation(case):
    scope_id, scope, saved = fixture()
    if case == "expired-scope":
        scope["expired"] = True
    if case == "write-method":
        scope["allowed_methods"].append("POST")
    if case == "active-profile":
        scope["allowed_check_profile"] = "external-dast"
    if case == "wrong-scope":
        scope_id = uuid4()
    if case == "changed-hash":
        saved["content_hash"] = "a" * 64
    if case == "expired-session":
        saved["configuration"]["identities"][0]["expires_at"] = (
            datetime.now(UTC) - timedelta(minutes=1)
        ).isoformat()
        saved["content_hash"] = canonical_sha256(saved["configuration"])
    with pytest.raises(ValueError):
        validate(scope, saved, scope_id)
