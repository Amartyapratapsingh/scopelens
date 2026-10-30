"""Existing input probes over independent identities on an owned loopback fixture."""

import copy
import json
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from pydantic import SecretStr

from scopelens.discovery import discover_catalogue, plan_assessment
from scopelens.domain.assessment import ActionPolicy, InputLocation
from scopelens.domain.identity import IdentityProfile
from scopelens.expansion.authenticated_inputs import (
    evaluate_input_identity,
    run_authenticated_inputs,
)


@pytest.fixture
def identity_input_site():
    records, revoked = [], set()

    class App(BaseHTTPRequestHandler):
        def handle_request(self):
            path = urlsplit(self.path).path
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            cookie = self.headers.get("Cookie", "").removeprefix("sid=")
            identity = token.split("-", 1)[0] if token else cookie or "anonymous"
            records.append((identity, path, self.command))
            status, headers, body = 200, {}, {"identity": identity}
            if path == "/login":
                supplied = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                username = supplied.get("username")
                if supplied.get("password") != "fixture-password-" + str(username):
                    status = 401
                else:
                    headers["Set-Cookie"] = f"sid={username}; Path=/; HttpOnly; SameSite=Strict"
            elif path == "/me":
                if identity == "anonymous" or identity in revoked:
                    status, body = 401, {"identity": "anonymous"}
            elif path.endswith("redirect"):
                if identity == "anonymous" or identity in revoked:
                    status = 401
                else:
                    value = parse_qs(urlsplit(self.path).query).get("next", ["/safe"])[0]
                    status = 302
                    headers["Location"] = "/safe" if path.startswith("/fixed") else value
                    if path.startswith("/lose") and sum(p == path for _, p, _ in records) == 3:
                        revoked.add(identity)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        do_GET = handle_request
        do_POST = handle_request

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), App)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", records
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def configured(origin, path="/bad/redirect", role="alice", *, cookie=False, expires_at=None):
    catalogue = discover_catalogue(
        origin,
        role_id=role,
        browser_requests=({"url": origin + path + "?next=/safe", "method": "GET"},),
    )
    policies = tuple(
        ActionPolicy(
            template_id=t.id, role_id=role, classification="read_only", approval_ref="owned-fixture"
        )
        for t in catalogue.templates
    )
    plan = plan_assessment(
        catalogue,
        scope_version="owned-fixture",
        policies=policies,
        reviewed_control_ids=("SL-C04-REDIRECT-01",),
        profile="authenticated-api-v1",
    )
    identity = {
        "id": role,
        "role": role,
        "probe": {"request": {"url": origin + "/me"}, "expected_identity": role},
        "expires_at": expires_at,
    }
    if cookie:
        identity["login"] = {
            "request": {
                "method": "POST",
                "url": origin + "/login",
                "json_body": {"username": role},
                "secret_fields": {"password": role + "-password-ref"},
            }
        }
    else:
        identity["supplied_headers"] = {"Authorization": role + "-header-ref"}
    return catalogue, plan, IdentityProfile.model_validate(identity)


def collect(catalogue, plan, profiles, *, resolver=None, **kwargs):
    clients, resolutions = [], []

    def factory(_):
        client = httpx.Client(trust_env=False, timeout=2)
        clients.append(client)
        return client

    def resolve(reference):
        resolutions.append(reference)
        if resolver:
            return resolver(reference, len(resolutions))
        role = reference.split("-", 1)[0]
        return SecretStr(
            "fixture-password-" + role
            if reference.endswith("password-ref")
            else f"Bearer {role}-{len(resolutions)}"
        )

    with httpx.Client(trust_env=False, timeout=2) as anonymous:
        result = run_authenticated_inputs(
            catalogue, plan, anonymous, profiles, factory, resolve, **kwargs
        )
    assert all(client.is_closed for client in clients)
    return result, resolutions


@pytest.mark.parametrize("cookie", [False, True])
@pytest.mark.parametrize(
    "path,state", [("/bad/redirect", "confirmed"), ("/fixed/redirect", "pass")]
)
def test_reviewed_probe_preserves_identity_and_capture_facts(
    identity_input_site, cookie, path, state
):
    origin, records = identity_input_site
    catalogue, plan, profile = configured(origin, path, cookie=cookie)
    result, resolutions = collect(catalogue, plan, (profile,))
    data = result[0]["data"]
    assert data["state"] == state, data
    assert data["requests_used"] == (6 if cookie else 5)
    assert len(resolutions) == (1 if cookie else 5)
    proof = data["identity_proof"]
    assert [p["phase"] for p in proof["probes"]] == ["before", "after"]
    assert evaluate_input_identity(profile, plan.tasks[0], catalogue.templates[0], plan.id, proof)[
        0
    ]
    assert {identity for identity, path, _ in records if path != "/login"} == {"alice"}
    assert "Bearer " not in json.dumps(result)
    assert "fixture-password" not in json.dumps(result)
    assert all(
        path in {"/login", "/me", "/bad/redirect", "/fixed/redirect"} for _, path, _ in records
    )


@pytest.mark.parametrize("missing", [False, True])
def test_missing_or_expired_identity_is_not_anonymous_fallback(identity_input_site, missing):
    origin, records = identity_input_site
    catalogue, plan, profile = configured(
        origin, expires_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    result, _ = collect(catalogue, plan, () if missing else (profile,))
    assert result[0]["data"]["state"] == "blocked"
    assert records == []


def test_post_probe_failure_retains_results_but_cannot_confirm(identity_input_site):
    origin, _ = identity_input_site
    catalogue, plan, profile = configured(origin, "/lose/redirect")
    result, _ = collect(catalogue, plan, (profile,))
    data = result[0]["data"]
    assert data["state"] == "inconclusive"
    assert len(data["captures"]) == 3
    assert data["identity_proof"]["probes"][-1]["status"] == 401
    assert not evaluate_input_identity(
        profile, plan.tasks[0], catalogue.templates[0], plan.id, data["identity_proof"]
    )[0]


@pytest.mark.parametrize(
    "tamper", [None, "missing", "other_role", "failed_after", "route", "method", "no_catalogue"]
)
def test_report_recomputes_authenticated_proof(identity_input_site, tamper):
    from pathlib import Path
    from uuid import uuid4

    from scopelens.domain.expansion import AssessmentConfiguration
    from scopelens.domain.registry import load_registry
    from scopelens.expansion.analysis import expansion_controls

    origin, _ = identity_input_site
    catalogue, plan, profile = configured(origin)
    artifacts, _ = collect(catalogue, plan, (profile,))
    artifact = artifacts[0]
    artifact.update(source="expansion", run_id="reviewed-worker", evidence_ref="trusted-capture")
    data = artifact["data"]
    if tamper == "missing":
        data.pop("identity_proof")
    elif tamper == "other_role":
        data["role_id"] = "anonymous"
    elif tamper == "failed_after":
        data["identity_proof"]["probes"][-1]["status"] = 401
    elif tamper == "route":
        data["route"] = "/unrelated"
    elif tamper == "method":
        data["method"] = "DELETE"
    # Worker verdicts cannot repair missing or contradicted identity evidence.
    data["state"] = "confirmed"
    config = AssessmentConfiguration(scope_version_id=uuid4(), identities=(profile,))
    frozen = {
        "expansion_config": config.model_dump(mode="json"),
        "request_catalogue": catalogue.model_dump(mode="json"),
        "input_assessment_plan": plan.model_dump(mode="json"),
    }
    if tamper == "no_catalogue":
        frozen.pop("request_catalogue")
    controls = expansion_controls(
        artifacts,
        frozen,
        load_registry(Path("checks_registry")),
        trusted_refs={"trusted-capture"},
    )
    outcome = next(c for c in controls if c.check_id == "SL-C04-REDIRECT-01").evaluate(None)
    assert outcome.status.value == ("confirmed_issue" if tamper is None else "inconclusive")
    assert bool(outcome.completed_instances) is (tamper is None)


def test_secret_revocation_mid_probe_preserves_partial_capture(identity_input_site):
    origin, _ = identity_input_site
    catalogue, plan, profile = configured(origin)

    def resolver(_, count):
        if count == 3:
            raise PermissionError("sensitive-secret-never-return-this")
        return SecretStr("Bearer alice-fixture")

    result, _ = collect(catalogue, plan, (profile,), resolver=resolver)
    data = result[0]["data"]
    assert data["state"] == "inconclusive"
    assert len(data["captures"]) == 1
    assert "sensitive-secret" not in json.dumps(result)


def test_cancellation_stops_probe_and_retains_incomplete_evidence(identity_input_site):
    origin, records = identity_input_site
    catalogue, plan, profile = configured(origin)
    result, _ = collect(catalogue, plan, (profile,), cancelled=lambda: len(records) >= 3)
    data = result[0]["data"]
    assert data["state"] == "inconclusive"
    assert data["error"] == "cancelled"
    assert len(records) == data["requests_used"] == 3
    assert len(data["captures"]) >= 1


def test_local_budget_includes_before_and_after_identity_checks(identity_input_site):
    origin, records = identity_input_site
    catalogue, plan, profile = configured(origin)
    result, _ = collect(catalogue, plan, (profile,), max_requests=4)
    data = result[0]["data"]
    assert len(records) == data["requests_used"] == 4
    assert len(data["captures"]) == 3
    assert data["state"] == "inconclusive"
    assert data["error"] == "request_budget_exhausted"


def test_identity_confined_to_probe_origin_before_any_request(identity_input_site):
    origin, records = identity_input_site
    catalogue, plan, profile = configured(origin)
    other = profile.model_copy(
        update={
            "probe": profile.probe.model_copy(
                update={
                    "request": profile.probe.request.model_copy(
                        update={"url": "https://unapproved.invalid/me"}
                    )
                }
            )
        }
    )
    result, _ = collect(catalogue, plan, (other,))
    assert result[0]["data"]["reason"] == "identity_credential_origin_mismatch"
    assert records == []


@pytest.mark.parametrize(
    "location,name", [("header", "Authorization"), ("header", "Cookie"), ("cookie", "sid")]
)
def test_templates_cannot_replace_verified_identity_headers(identity_input_site, location, name):
    origin, records = identity_input_site
    catalogue, plan, profile = configured(origin)
    template = catalogue.templates[0]
    template = template.model_copy(
        update={
            "inputs": (
                *template.inputs,
                InputLocation(
                    location=location, name=name, baseline_value="other-account", mutable=False
                ),
            )
        }
    )
    catalogue = catalogue.model_copy(update={"templates": (template,)})
    result, _ = collect(catalogue, plan, (profile,))
    assert result[0]["data"]["reason"] == "template_overrides_identity_headers"
    assert records == []


@pytest.mark.parametrize(
    "change", ["binding", "boolean_only", "role", "wrong_identity", "missing_after"]
)
def test_identity_proof_requires_bound_observed_facts(identity_input_site, change):
    origin, _ = identity_input_site
    catalogue, plan, profile = configured(origin)
    result, _ = collect(catalogue, plan, (profile,))
    proof = copy.deepcopy(result[0]["data"]["identity_proof"])
    if change == "binding":
        proof["task_id"] = "other-task"
    elif change == "boolean_only":
        proof["probes"] = [
            {"phase": "before", "verified": True},
            {"phase": "after", "verified": True},
        ]
    elif change == "role":
        proof["role_id"] = "other-account"
    elif change == "wrong_identity":
        proof["probes"][1]["observed_identity"] = "other-account"
    else:
        proof["probes"].pop()
    assert not evaluate_input_identity(
        profile, plan.tasks[0], catalogue.templates[0], plan.id, proof
    )[0]


def test_actual_rendered_url_is_checked_before_sending_credentials(
    identity_input_site, monkeypatch
):
    from scopelens.checks import expanded_active

    origin, records = identity_input_site
    catalogue, plan, profile = configured(origin)
    original = expanded_active.render_request

    def redirected_render(*args, **kwargs):
        rendered = original(*args, **kwargs)
        rendered["url"] = "http://127.0.0.1:1/unapproved"
        return rendered

    monkeypatch.setattr(expanded_active, "render_request", redirected_render)
    result, _ = collect(catalogue, plan, (profile,))
    assert result[0]["data"]["state"] == "inconclusive"
    assert result[0]["data"]["error"] == "identity_credential_origin_mismatch"
    assert [path for _, path, _ in records] == ["/me", "/me"]


def test_two_cookie_identities_use_independent_clients_and_task_proofs(identity_input_site):
    origin, records = identity_input_site
    cat_a, plan_a, alice = configured(origin, "/fixed/redirect", role="alice", cookie=True)
    cat_b, plan_b, bob = configured(origin, "/fixed/redirect", role="bob", cookie=True)
    catalogue = cat_a.model_copy(update={"templates": (*cat_a.templates, *cat_b.templates)})
    plan = plan_a.model_copy(
        update={
            "tasks": (*plan_a.tasks, *plan_b.tasks),
            "denominator": plan_a.denominator + plan_b.denominator,
        }
    )
    result, _ = collect(catalogue, plan, (alice, bob))
    assert [r["data"]["state"] for r in result] == ["pass", "pass"]
    assert [r["data"]["role_id"] for r in result] == ["alice", "bob"]
    assert [r[0] for r in records if r[1] == "/fixed/redirect"] == ["alice"] * 3 + ["bob"] * 3
    for profile, task, template, artifact in zip(
        (alice, bob), plan.tasks, catalogue.templates, result, strict=True
    ):
        assert evaluate_input_identity(
            profile, task, template, plan.id, artifact["data"]["identity_proof"]
        )[0]


def test_profile_expiry_mid_task_preserves_completed_captures(identity_input_site, monkeypatch):
    from scopelens.expansion import authenticated_inputs

    origin, records = identity_input_site
    expiry = datetime.now(UTC) + timedelta(minutes=10)
    catalogue, plan, profile = configured(origin, expires_at=expiry)

    class Clock:
        @staticmethod
        def now(tz):
            return expiry + timedelta(seconds=1) if len(records) >= 2 else datetime.now(tz)

        fromisoformat = datetime.fromisoformat

    monkeypatch.setattr(authenticated_inputs, "datetime", Clock)
    result, _ = collect(catalogue, plan, (profile,))
    data = result[0]["data"]
    assert data["state"] == "inconclusive"
    assert len(data["captures"]) == 1
    assert sum(path == "/bad/redirect" for _, path, _ in records) == 1


def test_anonymous_task_does_not_initialize_identity_session(identity_input_site):
    origin, records = identity_input_site
    catalogue, plan, _ = configured(origin, role="anonymous")

    def forbidden_factory(_):
        raise AssertionError("anonymous task must keep its original client")

    with httpx.Client(trust_env=False, timeout=2) as anonymous:
        result = run_authenticated_inputs(
            catalogue, plan, anonymous, (), forbidden_factory, lambda _: SecretStr("unused")
        )
    assert result[0]["data"]["role_id"] == "anonymous"
    assert "identity_proof" not in result[0]["data"]
    assert len(records) == 3
    assert all(role == "anonymous" for role, _, _ in records)


@pytest.mark.parametrize(
    "tamper", [None, "missing_revision", "scope", "template", "task", "identity_plan"]
)
def test_revision_retains_only_identically_bound_prior_proof(identity_input_site, tamper):
    from pathlib import Path
    from uuid import uuid4

    from scopelens.domain.expansion import AssessmentConfiguration
    from scopelens.domain.registry import load_registry
    from scopelens.expansion.analysis import expansion_controls

    origin, records = identity_input_site
    catalogue, first, profile = configured(origin)
    artifacts, _ = collect(catalogue, first, (profile,))
    artifacts[0].update(source="expansion", run_id="first-run", evidence_ref="trusted-first")
    second = plan_assessment(
        catalogue,
        scope_version=first.scope_version,
        previous=first,
        policies=tuple(
            ActionPolicy(
                template_id=t.id,
                role_id=t.role_id,
                classification="read_only",
                approval_ref="owned-fixture",
            )
            for t in catalogue.templates
        ),
        reviewed_control_ids=("SL-C04-REDIRECT-01",),
        profile=first.profile,
    )
    assert first.id != second.id
    frozen = {
        "expansion_config": AssessmentConfiguration(
            scope_version_id=uuid4(), identities=(profile,)
        ).model_dump(mode="json"),
        "input_assessment_plan": second.model_dump(mode="json"),
        "request_catalogue": catalogue.model_dump(mode="json"),
        "assessment_plan_revisions": [
            {
                "plan": first.model_dump(mode="json"),
                "catalogue": catalogue.model_dump(mode="json"),
                "run_id": "first-run",
            }
        ],
    }
    revision = frozen["assessment_plan_revisions"][0]
    if tamper == "missing_revision":
        frozen["assessment_plan_revisions"] = []
    elif tamper == "scope":
        revision["plan"]["scope_version"] = "different-scope"
    elif tamper == "template":
        revision["catalogue"]["templates"][0]["path"] = "/different"
    elif tamper == "task":
        revision["plan"]["tasks"][0]["input_key"] = "unrelated"
    elif tamper == "identity_plan":
        artifacts[0]["data"]["identity_proof"]["plan_id"] = second.id
    # A newer skipped capture must not replace the original trusted observations.
    skipped = copy.deepcopy(artifacts[0])
    skipped["evidence_ref"] = "trusted-skipped"
    skipped["data"].update(
        state="blocked", reason="prior_execution_not_replayed", plan_id=second.id
    )
    artifacts.append(skipped)
    before = len(records)
    controls = expansion_controls(
        artifacts,
        frozen,
        load_registry(Path("checks_registry")),
        trusted_refs={"trusted-first", "trusted-skipped"},
    )
    outcome = next(c for c in controls if c.check_id == "SL-C04-REDIRECT-01").evaluate(None)
    assert outcome.status.value == ("confirmed_issue" if tamper is None else "inconclusive")
    assert bool(outcome.completed_instances) is (tamper is None)
    assert len(records) == before
