from __future__ import annotations

import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer

import httpx
import pytest
from cryptography.fernet import Fernet
from labs.expansion_identity.app import MARKER, handler
from pydantic import SecretStr, ValidationError

from scopelens.domain.identity import (
    IdentityProfile,
    IdentityRequest,
    LoginRecipe,
    OwnedTestObject,
    PermissionMatrix,
    PermissionRule,
    SessionPolicy,
    SessionProbe,
)
from scopelens.identities.assessment import as_control_outcome, run_access_comparisons
from scopelens.identities.lifecycle import check_session_policy
from scopelens.identities.secrets import EncryptedSecretStore
from scopelens.identities.sessions import IdentitySessions, SessionUnavailable


@contextmanager
def lab(**kwargs):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(**kwargs))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def profiles(base):
    return tuple(
        IdentityProfile(
            id=name,
            role="user",
            tenant=name,
            login=LoginRecipe(
                request=IdentityRequest(
                    method="POST",
                    url=base + "/login",
                    json_body={"username": name},
                    secret_fields={"password": "password_ref"},
                )
            ),
            probe=SessionProbe(
                request=IdentityRequest(url=base + "/me"),
                expected_identity=name,
                unauthenticated_pointer="/error",
                unauthenticated_value="unauthenticated",
            ),
        )
        for name in ("a", "b")
    )


def session_factory(base):
    return IdentitySessions(
        profiles(base),
        lambda _: SecretStr("synthetic-password"),
        lambda _: httpx.Client(timeout=2, trust_env=False),
    )


def matrix(base, family="object", allowed=False, shared=False):
    path = {
        "object": "/objects/a",
        "function": "/admin/export",
        "tenant": "/tenant/a",
        "property": "/property/a",
    }[family]
    return PermissionMatrix(
        version="fixture-v1",
        objects=(
            OwnedTestObject(
                id="seed-a",
                owner_identity="a",
                request=IdentityRequest(url=base + path),
                marker_pointer="/private",
                marker=MARKER,
            ),
        ),
        rules=(
            PermissionRule(
                id="rule-a",
                object_id="seed-a",
                identity_id="a" if allowed else "b",
                family=family,
                allowed=allowed,
                redacted_pointer="/private" if shared else "/error",
                redacted_value=None if shared else "forbidden",
            ),
        ),
    )


def capture(records):
    def add(value):
        records.append(value)
        return f"artifact-{len(records)}"

    return add


@pytest.mark.parametrize("family", ["object", "function", "tenant", "property"])
@pytest.mark.parametrize("vulnerable", [False, True])
def test_real_http_comparisons(family, vulnerable):
    records = []
    with lab(vulnerable=vulnerable) as base, session_factory(base) as sessions:
        plan = matrix(base, family)
        (result,) = run_access_comparisons(plan, sessions, capture(records))
        assert result.state == ("confirmed" if vulnerable else "pass")
        assert len(result.evidence_refs) == 3
        assert result.authorized_baseline
        assert as_control_outcome(result, plan).is_fully_assessed
        assert sessions.client("a").cookies.get("sid") != sessions.client("b").cookies.get("sid")
        assert "synthetic-password" not in str(records)
        assert MARKER not in str(records)


def test_authorized_and_shared_view_not_false_positive():
    with lab(shared=True) as base, session_factory(base) as sessions:
        assert (
            run_access_comparisons(matrix(base, allowed=True), sessions, capture([]))[0].state
            == "pass"
        )
        assert (
            run_access_comparisons(matrix(base, shared=True), sessions, capture([]))[0].state
            == "pass"
        )


@pytest.mark.parametrize(
    ("mode", "expected"), [("expire_on_object", "blocked"), ("waf", "inconclusive")]
)
def test_expiry_and_waf_not_clean(mode, expected):
    with lab(**{mode: True}) as base, session_factory(base) as sessions:
        assert run_access_comparisons(matrix(base), sessions, capture([]))[0].state == expected


def test_no_evidence_cannot_confirm():
    with lab(vulnerable=True) as base, session_factory(base) as sessions:
        assert run_access_comparisons(matrix(base), sessions, lambda _: "")[0].state == "blocked"


@pytest.mark.parametrize("vulnerable", [False, True])
def test_real_session_rotation_and_logout(vulnerable):
    with lab(vulnerable=vulnerable) as base, session_factory(base) as sessions:
        policy = SessionPolicy(
            identity_id="a",
            cookie_name="sid",
            old_session_revoked_on_login=True,
            logout=IdentityRequest(method="POST", url=base + "/logout"),
        )
        results = check_session_policy(policy, sessions, capture([]))
        assert len(results) == 3
        assert {r.state for r in results} == ({"confirmed"} if vulnerable else {"pass"})


def test_restart_never_reuses_session():
    with lab() as base:
        with session_factory(base) as first:
            assert first.verify("a")
            token = first.client("a").cookies.get("sid")
        with session_factory(base) as second:
            assert not second.client("a").cookies
            assert second.verify("a")
            assert second.client("a").cookies.get("sid") != token


def test_client_reuse_rejected():
    with httpx.Client() as client:
        sessions = IdentitySessions(
            profiles("https://lab.invalid"), lambda _: SecretStr("none"), lambda _: client
        )
        sessions.client("a")
        with pytest.raises(SessionUnavailable):
            sessions.client("b")


def test_secret_storage_scope_owner_expiry_and_no_plaintext(tmp_path):
    store = EncryptedSecretStore(tmp_path, Fernet.generate_key())
    ref = store.put(
        SecretStr("private-test-password"),
        owner="operator",
        scope_id="scope1",
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    assert b"private-test-password" not in (tmp_path / ref).read_bytes()
    assert (tmp_path / ref).stat().st_mode & 0o777 == 0o600
    assert (
        store.resolve(ref, owner="operator", scope_id="scope1").get_secret_value()
        == "private-test-password"
    )
    for owner, scope in [("other", "scope1"), ("operator", "scope2")]:
        with pytest.raises(PermissionError):
            store.resolve(ref, owner=owner, scope_id=scope)
    with pytest.raises(ValueError):
        store.resolve("../x", owner="operator", scope_id="scope1")
    with pytest.raises(ValueError):
        store.put(
            SecretStr("x"),
            owner="operator",
            scope_id="scope1",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
    store.delete(ref, owner="operator", scope_id="scope1")
    assert not (tmp_path / ref).exists()


def test_cancelled_and_unknown_identity_blocked():
    with lab() as base, session_factory(base) as sessions:
        sessions.cancelled = lambda: True
        assert run_access_comparisons(matrix(base), sessions, capture([]))[0].state == "blocked"
        with pytest.raises(SessionUnavailable):
            sessions.verify("missing")


def test_model_invariants():
    with pytest.raises(ValidationError):
        IdentityProfile(id="a", role="user")
    with pytest.raises(ValidationError):
        IdentityRequest(url="https://user:pass@example.org")
    with pytest.raises(ValidationError):
        IdentityRequest(url="https://example.org", secret_headers={"Proxy-Authorization": "ref"})
    with pytest.raises(ValidationError):
        matrix("https://lab.invalid").model_copy(update={}).__class__.model_validate(
            {
                "version": "v",
                "objects": [],
                "rules": [matrix("https://lab.invalid").rules[0].model_dump()],
            }
        )


def test_proof_is_reevaluated_from_trusted_responses():
    from scopelens.identities.proof import CapturedIdentityResponse, evaluate_access_proof

    records = []

    def observe(identity, request, response):
        records.append(
            CapturedIdentityResponse(
                identity_id=identity,
                method=request.method,
                url=request.url,
                status=response.status_code,
                document=response.json(),
                evidence_ref=f"broker-{len(records)}",
            )
        )

    with lab(vulnerable=True) as base, session_factory(base) as sessions:
        sessions.response_observer = observe
        plan = matrix(base)
        (collected,) = run_access_comparisons(plan, sessions, capture([]))
        assert collected.state == "confirmed"
        assert (
            evaluate_access_proof(plan, profiles(base), "rule-a", tuple(records)).state
            == "confirmed"
        )
        # Removing all authenticated comparison probes invalidates even genuine marker bodies.
        without_b_probes = tuple(
            r for r in records if not (r.identity_id == "b" and r.url.endswith("/me"))
        )
        assert (
            evaluate_access_proof(plan, profiles(base), "rule-a", without_b_probes).state
            == "inconclusive"
        )
        assert evaluate_access_proof(plan, profiles(base), "rule-a", ()).state == "inconclusive"


@pytest.mark.parametrize("state", ["confirmed", "pass", "blocked", "error", "inconclusive"])
def test_identity_outcome_obeys_engine_invariants(state):
    from scopelens.checks.engine import validate_outcome
    from scopelens.domain.identity import RoleComparison

    result = RoleComparison(
        rule_id="rule-a",
        object_id="seed-a",
        identity_id="b",
        family="object",
        state=state,
        reason="fixture",
        evidence_refs=("trusted-evidence",),
    )
    validate_outcome(as_control_outcome(result, matrix("https://lab.invalid")))


def test_selected_response_drops_unrelated_secret_fields():
    from scopelens.identities.proof import select_identity_response

    base = "https://lab.invalid"
    plan = matrix(base)
    response = httpx.Response(
        200,
        json={
            "private": MARKER,
            "password": "must-not-persist",
            "other": {"token": "must-not-persist"},
        },
    )
    selected = select_identity_response(
        "a", plan.objects[0].request, response, profiles(base), plan, evidence_ref="broker-ref"
    )
    assert selected.document == {"private": MARKER}
    assert "must-not-persist" not in selected.model_dump_json()


def test_credentials_never_sent_to_another_origin_and_body_cap():
    profiles_ = profiles("https://lab.invalid")
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, content=b"x" * 1048577)

    with IdentitySessions(
        profiles_,
        lambda _: SecretStr("secret"),
        lambda _: httpx.Client(transport=httpx.MockTransport(handle)),
    ) as sessions:
        with pytest.raises(SessionUnavailable, match="origin"):
            sessions.request("a", IdentityRequest(url="https://other.invalid/me"))
        assert not requests
        with pytest.raises(SessionUnavailable, match="cap"):
            sessions.request("a", IdentityRequest(url="https://lab.invalid/me"))


def test_policy_json_values_do_not_conflate_booleans_and_numbers():
    from scopelens.identities.sessions import same_value

    assert not same_value(0, False)
    assert not same_value(1, True)
    assert same_value(None, None)


def test_session_proof_rejects_wrong_cookie_replay_and_missing_probe():
    from scopelens.identities.lifecycle import evaluate_session_proof

    base = "https://lab.invalid"
    profile = profiles(base)[0]
    policy = SessionPolicy(
        identity_id="a",
        cookie_name="sid",
        logout=IdentityRequest(method="POST", url=base + "/logout"),
    )
    record = {
        "identity_id": "a",
        "check": "logout",
        "initial_probe_status": 200,
        "initial_identity": "a",
        "new_probe_status": 200,
        "new_identity": "a",
        "login_status": 200,
        "logout_status": 200,
        "old_cookie_hash": "a" * 64,
        "new_cookie_hash": "b" * 64,
        "replayed_cookie_hash": "c" * 64,
        "replay_probe_status": 200,
        "replay_identity": "a",
    }
    assert evaluate_session_proof(policy, profile, record)[0] == "inconclusive"
    record["replayed_cookie_hash"] = "b" * 64
    assert evaluate_session_proof(policy, profile, record)[0] == "confirmed"
    record["new_probe_status"] = 401
    assert evaluate_session_proof(policy, profile, record)[0] == "inconclusive"


def test_form_login_uses_secret_refs_without_json_encoding():
    with lab() as base:
        form_profiles = tuple(
            p.model_copy(
                update={
                    "login": p.login.model_copy(
                        update={
                            "request": p.login.request.model_copy(update={"body_encoding": "form"})
                        }
                    )
                }
            )
            for p in profiles(base)
        )
        with IdentitySessions(
            form_profiles,
            lambda _: SecretStr("synthetic-password"),
            lambda _: httpx.Client(timeout=2, trust_env=False),
        ) as sessions:
            assert sessions.verify("a")
            assert sessions.verify("b")


def test_tenant_check_requires_distinct_declared_tenants():
    with lab(vulnerable=True) as base:
        same_tenant = tuple(p.model_copy(update={"tenant": "shared"}) for p in profiles(base))
        with IdentitySessions(
            same_tenant,
            lambda _: SecretStr("synthetic-password"),
            lambda _: httpx.Client(timeout=2, trust_env=False),
        ) as sessions:
            (result,) = run_access_comparisons(matrix(base, family="tenant"), sessions, capture([]))
            assert result.state == "blocked"
            assert not result.evidence_refs


def test_login_plaintext_credentials_are_rejected():
    with pytest.raises(ValidationError, match="encrypted secret_fields"):
        LoginRecipe(
            request=IdentityRequest(
                method="POST",
                url="https://lab.invalid/login",
                json_body={"username": "a", "password": "not-for-storage"},
            )
        )
    with pytest.raises(ValidationError, match="encrypted secret_fields"):
        LoginRecipe(
            request=IdentityRequest(
                method="POST",
                url="https://lab.invalid/login",
                json_body={"user": {"client_secret": "not-for-storage"}},
            )
        )
