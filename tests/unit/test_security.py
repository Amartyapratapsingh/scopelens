"""Password hashing, session signing and redaction (Build Plan §5.1, §6.1)."""

from __future__ import annotations

import time

import pytest

from scopelens.security.passwords import (
    MAX_PASSWORD_BYTES,
    PasswordError,
    hash_password,
    verify_password,
)
from scopelens.security.redaction import REDACTED, redact
from scopelens.security.sessions import SessionError, SessionSigner

# bcrypt is deliberately slow; keep test cost down without weakening the assertions.
ROUNDS = 4


class TestPasswords:
    def test_hash_and_verify_round_trip(self) -> None:
        digest = hash_password("correct horse battery staple", rounds=ROUNDS)
        assert verify_password("correct horse battery staple", digest)

    def test_wrong_password_is_rejected(self) -> None:
        digest = hash_password("right", rounds=ROUNDS)
        assert not verify_password("wrong", digest)

    def test_hashes_are_salted(self) -> None:
        assert hash_password("same", rounds=ROUNDS) != hash_password("same", rounds=ROUNDS)

    def test_hash_is_bcrypt_shaped(self) -> None:
        assert hash_password("x", rounds=ROUNDS).startswith("$2b$")

    def test_empty_password_is_refused(self) -> None:
        with pytest.raises(PasswordError):
            hash_password("")

    def test_over_long_password_is_refused_rather_than_truncated(self) -> None:
        """Silent truncation would make two different passwords interchangeable."""
        with pytest.raises(PasswordError, match="bcrypt"):
            hash_password("a" * (MAX_PASSWORD_BYTES + 1))

    def test_exactly_max_length_is_accepted(self) -> None:
        digest = hash_password("a" * MAX_PASSWORD_BYTES, rounds=ROUNDS)
        assert verify_password("a" * MAX_PASSWORD_BYTES, digest)

    @pytest.mark.parametrize("bad", ["", "not-a-hash", "$2b$99$garbage"])
    def test_verification_against_a_bad_hash_returns_false(self, bad: str) -> None:
        assert not verify_password("anything", bad)

    def test_over_long_candidate_returns_false_without_raising(self) -> None:
        digest = hash_password("short", rounds=ROUNDS)
        assert not verify_password("a" * 200, digest)


class TestSessions:
    def test_sign_and_verify_round_trip(self) -> None:
        signer = SessionSigner("secret-value", max_age_seconds=60)
        token = signer.sign({"sub": "abc", "username": "operator"})
        assert signer.verify(token)["sub"] == "abc"

    def test_tampered_token_is_rejected(self) -> None:
        signer = SessionSigner("secret-value", max_age_seconds=60)
        token = signer.sign({"sub": "abc"})
        with pytest.raises(SessionError, match="invalid"):
            signer.verify(token[:-3] + "xyz")

    def test_token_signed_with_another_secret_is_rejected(self) -> None:
        token = SessionSigner("secret-one", max_age_seconds=60).sign({"sub": "abc"})
        with pytest.raises(SessionError):
            SessionSigner("secret-two", max_age_seconds=60).verify(token)

    def test_expired_token_is_rejected(self) -> None:
        signer = SessionSigner("secret-value", max_age_seconds=1)
        token = signer.sign({"sub": "abc"})
        time.sleep(2)
        with pytest.raises(SessionError, match="expired"):
            signer.verify(token)

    def test_payload_without_subject_is_rejected(self) -> None:
        signer = SessionSigner("secret-value", max_age_seconds=60)
        with pytest.raises(SessionError, match="malformed"):
            signer.verify(signer.sign({"username": "operator"}))

    def test_empty_secret_is_refused(self) -> None:
        with pytest.raises(SessionError, match="session secret"):
            SessionSigner("", max_age_seconds=60)

    def test_tokens_are_not_plaintext(self) -> None:
        signer = SessionSigner("secret-value", max_age_seconds=60)
        assert "operator" not in signer.sign({"sub": "abc", "username": "operator"})


class TestRedaction:
    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "api_key",
            "session_secret",
            "Authorization",
            "cookie",
            "token",
            "private_key",
        ],
    )
    def test_sensitive_keys_are_redacted(self, key: str) -> None:
        assert redact({"outer": {key: "value"}})["outer"][key] == REDACTED

    def test_nested_structures_are_walked(self) -> None:
        payload = {"a": [{"password": "p"}, {"safe": "keep"}], "b": {"token": "t"}}
        result = redact(payload)
        assert result["a"][0]["password"] == REDACTED
        assert result["a"][1]["safe"] == "keep"
        assert result["b"]["token"] == REDACTED

    @pytest.mark.parametrize(
        "value",
        [
            "Bearer abc123",
            "Basic YWJjZGVmZ2g=",
            "eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "sk-abcdefghijklmnopqrstuvwxyz",
            "$2b$12$abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyza",
        ],
    )
    def test_credential_shaped_values_are_redacted_without_a_sensitive_key(
        self, value: str
    ) -> None:
        assert redact({"comment": value})["comment"] == REDACTED

    def test_ordinary_values_survive(self) -> None:
        payload = {"origin": "https://example.com", "count": 3, "ok": True}
        assert redact(payload) == payload

    def test_deep_nesting_is_bounded(self) -> None:
        deep: dict = {}
        node = deep
        for _ in range(30):
            node["child"] = {}
            node = node["child"]
        assert "nesting too deep" in str(redact(deep))


@pytest.mark.parametrize("key", ["cookie_present", "authorization_present"])
@pytest.mark.parametrize("value", [True, False])
def test_browser_credential_presence_boolean_survives_redaction(key, value):
    assert redact({"requests": [{key: value}]}) == {"requests": [{key: value}]}


@pytest.mark.parametrize(
    "key",
    [
        "cookie_present",
        "authorization_present",
        "cookie_present_value",
        "authorization_present_value",
    ],
)
@pytest.mark.parametrize("value", ["sid=private", 1, None, {"value": "private"}, ["private"]])
def test_presence_fact_exception_never_exposes_non_boolean_values(key, value):
    assert redact({key: value}) == {key: REDACTED}
