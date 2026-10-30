"""Session proof never accepts erased, raw, or malformed cookie fingerprints."""

import pytest

from scopelens.domain.identity import (
    IdentityProfile,
    IdentityRequest,
    LoginRecipe,
    SessionPolicy,
    SessionProbe,
)
from scopelens.identities.lifecycle import evaluate_session_proof


def session_policy():
    profile = IdentityProfile(
        id="student",
        role="student",
        login=LoginRecipe(request=IdentityRequest(method="POST", url="https://lab.invalid/login")),
        probe=SessionProbe(
            request=IdentityRequest(url="https://lab.invalid/me"),
            expected_identity="student",
            unauthenticated_pointer="/error",
            unauthenticated_value="unauthenticated",
        ),
    )
    policy = SessionPolicy(
        identity_id=profile.id,
        cookie_name="sid",
        old_session_revoked_on_login=True,
        logout=IdentityRequest(method="POST", url="https://lab.invalid/logout"),
    )
    return policy, profile


def session_record(check="rotation"):
    return {
        "kind": "session_policy",
        "identity_id": "student",
        "check": check,
        "proof_type": "session",
        "proof_id": "student",
        "initial_probe_status": 200,
        "initial_identity": "student",
        "login_status": 200,
        "new_probe_status": 200,
        "new_identity": "student",
        "old_cookie_hash": "a" * 64,
        "new_cookie_hash": "b" * 64,
        "replayed_cookie_hash": "a" * 64 if check == "old_session" else "b" * 64,
        "logout_status": 200,
        "replay_probe_status": 200,
        "replay_identity": "student",
    }


@pytest.mark.parametrize("check", ["rotation", "old_session", "logout"])
@pytest.mark.parametrize("field", ["old_cookie_hash", "new_cookie_hash", "replayed_cookie_hash"])
@pytest.mark.parametrize(
    "invalid",
    [
        None,
        "",
        "[redacted]",
        "raw-session-value",
        "a" * 63,
        "a" * 65,
        "g" * 64,
        "A" * 64,
        "a" * 64 + "\n",
        123,
        ["a" * 64],
    ],
)
def test_malformed_fingerprint_cannot_prove_a_lifecycle_result(check, field, invalid):
    policy, profile = session_policy()
    record = session_record(check)
    record[field] = invalid
    assert evaluate_session_proof(policy, profile, record)[0] == "inconclusive"


@pytest.mark.parametrize("check", ["rotation", "old_session", "logout"])
def test_equal_redaction_markers_do_not_prove_rotation_or_revocation(check):
    policy, profile = session_policy()
    record = session_record(check)
    for field in ("old_cookie_hash", "new_cookie_hash", "replayed_cookie_hash"):
        record[field] = "[redacted]"
    assert evaluate_session_proof(policy, profile, record)[0] == "inconclusive"


def test_profile_must_match_declared_policy_identity():
    policy, profile = session_policy()
    profile = profile.model_copy(update={"id": "other"})
    assert evaluate_session_proof(policy, profile, session_record())[0] == "inconclusive"
