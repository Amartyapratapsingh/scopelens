"""Strict expiry proofs cannot pass from failed requests, hashes, or an insufficient wait."""

import json
from copy import deepcopy

import pytest
from pydantic import ValidationError

from scopelens.domain.identity import (
    IdentityProfile,
    IdentityRequest,
    LoginRecipe,
    SessionPolicy,
    SessionProbe,
)
from scopelens.evidence.intake import _redact_json_or_text
from scopelens.identities.lifecycle import _wait_for_expiry, evaluate_session_proof
from scopelens.identities.sessions import SessionUnavailable


def contract(origin="http://127.0.0.1:8788"):
    profile = IdentityProfile(
        id="student",
        role="student",
        login=LoginRecipe(
            request=IdentityRequest(
                method="POST",
                url=origin + "/login",
                json_body={"username": "student"},
                secret_fields={"password": "expiry-password-reference"},
            )
        ),
        probe=SessionProbe(
            request=IdentityRequest(url=origin + "/me"),
            expected_identity="student",
            unauthenticated_pointer="/error",
            unauthenticated_value="unauthenticated",
        ),
    )
    return SessionPolicy(
        identity_id="student", cookie_name="sid", login_rotates=False, expiry_after_seconds=1
    ), profile


def expiry_record():
    return {
        "kind": "session_policy",
        "identity_id": "student",
        "check": "expiry",
        "proof_type": "session",
        "proof_id": "student",
        "initial_probe_status": 200,
        "initial_identity": "student",
        "login_status": 200,
        "new_probe_status": 200,
        "new_identity": "student",
        "old_cookie_hash": "a" * 64,
        "new_cookie_hash": "b" * 64,
        "replayed_cookie_hash": "b" * 64,
        "expiry_after_seconds": 1,
        "expiry_waited_seconds": 1.001,
        "expiry_replays": [
            {
                "elapsed_seconds": elapsed,
                "replay_probe_status": 401,
                "replay_identity": None,
                "replay_denial_observed": True,
                "replay_denial": "unauthenticated",
            }
            for elapsed in (1.002, 1.003)
        ],
    }


@pytest.mark.parametrize("value", [0, 61, -1, True, False, 1.0, "1"])
def test_expiry_interval_is_strict_and_bounded(value):
    with pytest.raises(ValidationError):
        SessionPolicy(identity_id="student", cookie_name="sid", expiry_after_seconds=value)


def test_expiry_remains_opt_in():
    original = {
        "identity_id": "student",
        "cookie_name": "sid",
        "login_rotates": True,
        "old_session_revoked_on_login": False,
        "logout": None,
        "logout_revokes": True,
    }
    legacy_policy = SessionPolicy.model_validate(original)
    assert legacy_policy.expiry_after_seconds is None
    assert legacy_policy.model_dump(mode="json") == original
    assert "expiry_after_seconds" not in legacy_policy.model_dump()
    policy, profile = contract()
    assert policy.model_dump(mode="json")["expiry_after_seconds"] == 1
    assert (
        evaluate_session_proof(
            policy.model_copy(update={"expiry_after_seconds": None}), profile, expiry_record()
        )[0]
        == "inconclusive"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("initial_probe_status", 401),
        ("initial_identity", "other"),
        ("login_status", 500),
        ("new_probe_status", 401),
        ("new_identity", "other"),
        ("old_cookie_hash", "[redacted]"),
        ("new_cookie_hash", "[redacted]"),
        ("replayed_cookie_hash", "a" * 64),
        ("replayed_cookie_hash", "B" * 64),
        ("expiry_after_seconds", 2),
        ("expiry_after_seconds", True),
        ("expiry_waited_seconds", 0.999),
        ("expiry_waited_seconds", True),
        ("expiry_waited_seconds", float("nan")),
        ("expiry_waited_seconds", float("inf")),
        ("expiry_waited_seconds", 10**400),
        ("expiry_replays", []),
        ("expiry_replays", [{}]),
    ],
)
def test_invalid_expiry_record_is_inconclusive(field, value):
    record = expiry_record()
    record[field] = value
    assert evaluate_session_proof(*contract(), record)[0] == "inconclusive"


@pytest.mark.parametrize(
    "field,value",
    [
        ("elapsed_seconds", 0.999),
        ("elapsed_seconds", True),
        ("elapsed_seconds", float("nan")),
        ("elapsed_seconds", float("inf")),
        ("elapsed_seconds", 10**400),
        ("replay_probe_status", None),
        ("replay_probe_status", 0),
        ("replay_probe_status", 403),
        ("replay_probe_status", 500),
        ("replay_probe_status", 302),
        ("replay_denial_observed", False),
        ("replay_denial", "waf"),
    ],
)
@pytest.mark.parametrize("index", [0, 1])
def test_each_post_wait_replay_must_repeat_declared_denial(index, field, value):
    record = expiry_record()
    record["expiry_replays"][index][field] = value
    assert evaluate_session_proof(*contract(), record)[0] == "inconclusive"


def test_expiry_accepts_repeat_denial_or_repeat_verified_access_only():
    record = expiry_record()
    assert evaluate_session_proof(*contract(), record)[0] == "pass"
    for replay in record["expiry_replays"]:
        replay.update(
            replay_probe_status=200,
            replay_identity="student",
            replay_denial_observed=False,
            replay_denial=None,
        )
    assert evaluate_session_proof(*contract(), record)[0] == "confirmed"
    record["expiry_replays"][1]["replay_identity"] = "other"
    assert evaluate_session_proof(*contract(), record)[0] == "inconclusive"


def test_expiry_replay_times_must_follow_measured_wait_in_order():
    record = expiry_record()
    record["expiry_replays"].reverse()
    assert evaluate_session_proof(*contract(), record)[0] == "inconclusive"
    record["expiry_replays"] = deepcopy(expiry_record()["expiry_replays"])
    record["expiry_waited_seconds"] = 1.01
    assert evaluate_session_proof(*contract(), record)[0] == "inconclusive"


def test_expiry_uses_existing_top_level_trusted_fingerprint_exception():
    artifact = {"source": "expansion", "kind": "identity_observation", "data": expiry_record()}
    stored = json.loads(
        _redact_json_or_text(json.dumps(artifact), preserve_session_fingerprints=True)
    )
    assert evaluate_session_proof(*contract(), stored["data"])[0] == "pass"
    ordinary = json.loads(_redact_json_or_text(json.dumps(artifact)))
    assert evaluate_session_proof(*contract(), ordinary["data"])[0] == "inconclusive"


def test_monotonic_wait_checks_cancellation_before_sleep(monkeypatch):
    monkeypatch.setattr(
        "scopelens.identities.lifecycle.time.sleep",
        lambda seconds: pytest.fail("cancelled wait must not sleep"),
    )
    with pytest.raises(SessionUnavailable, match="cancelled"):
        _wait_for_expiry(0, 1, lambda: True)
