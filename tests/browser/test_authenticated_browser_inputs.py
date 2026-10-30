"""Generic browser identity evidence against synthetic owned loopback pages."""

import copy
import html
import json
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest
from playwright.sync_api import sync_playwright
from pydantic import SecretStr

from scopelens.browser.expanded_active import run_expanded_browser_checks
from scopelens.discovery import discover_catalogue, plan_assessment
from scopelens.domain.assessment import ActionPolicy, InputLocation
from scopelens.domain.identity import IdentityProfile
from scopelens.expansion.authenticated_browser import (
    AuthenticatedBrowserLifecycle,
    evaluate_browser_input_identity,
)
from scopelens.identities.sessions import SessionUnavailable


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def site():
    events, state = [], {"revoked": False}

    class App(BaseHTTPRequestHandler):
        def respond(self):
            path = urlsplit(self.path).path
            token = self.headers.get("X-Identity-Token")
            cookie = self.headers.get("Cookie")
            identity = (
                "alice" if token == "synthetic-alice" or cookie == "sid=alice" else "anonymous"
            )
            events.append((path, identity, token, cookie))
            status, headers = 200, {"Content-Type": "application/json"}
            if path == "/login":
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                status = 200 if data.get("password") == "synthetic-password" else 401
                headers["Set-Cookie"] = "sid=alice; Path=/; HttpOnly; SameSite=Strict"
                body = "{}"
            elif path == "/me":
                status = 401 if identity == "anonymous" or state["revoked"] else 200
                body = json.dumps({"identity": "wrong" if state.get("wrong") else identity})
            elif path == "/redirect":
                status, body = 302, "redirect"
                headers["Location"] = state["redirect"]
            elif path == "/asset":
                body = "asset"
                if state.get("resource_redirect"):
                    status, headers["Location"] = 302, state["redirect"]
            else:
                value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
                if path == "/fixed":
                    value = html.escape(value)
                body = f'<html><body>{value}<img src="/asset"></body></html>'
                headers["Content-Type"] = "text/html"
                if state.get("revoke_on_action"):
                    state["revoked"] = True
                if state.get("fail_secret_on_action"):
                    state["secret_failed"] = True
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body.encode())

        do_GET = respond
        do_POST = respond

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), App)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", events, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def configuration(origin, path="/bad", *, cookie=False, expires_at=None):
    catalogue = discover_catalogue(
        origin,
        role_id="alice",
        browser_requests=({"url": origin + path + "?q=ordinary", "method": "GET"},),
    )
    policies = tuple(
        ActionPolicy(
            template_id=t.id,
            role_id="alice",
            classification="read_only",
            approval_ref="owned-loopback",
        )
        for t in catalogue.templates
    )
    plan = plan_assessment(
        catalogue,
        scope_version="fixture",
        policies=policies,
        reviewed_control_ids=("SL-C03-XSS-01",),
    )
    profile = IdentityProfile.model_validate(
        {
            "id": "alice",
            "role": "member",
            "expires_at": expires_at,
            "probe": {"request": {"url": origin + "/me"}, "expected_identity": "alice"},
            **(
                {
                    "login": {
                        "request": {
                            "method": "POST",
                            "url": origin + "/login",
                            "secret_fields": {"password": "password-ref"},
                        }
                    }
                }
                if cookie
                else {"supplied_headers": {"X-Identity-Token": "token-ref"}}
            ),
        }
    )
    return catalogue, plan, profile


def run(
    site,
    browser,
    *,
    path="/bad",
    profiles=None,
    cookie=False,
    expires_at=None,
    cancelled=lambda: False,
    lifecycle=True,
):
    origin, _, state = site
    catalogue, plan, profile = configuration(origin, path, cookie=cookie, expires_at=expires_at)
    resolved = []

    def secret(ref):
        resolved.append(ref)
        if state.get("secret_failed"):
            raise PermissionError("DO-NOT-EXPOSE-secret")
        return SecretStr("synthetic-password" if ref == "password-ref" else "synthetic-alice")

    def factory(role):
        return browser.new_context(service_workers="block")

    hooks = AuthenticatedBrowserLifecycle(
        catalogue,
        plan,
        (profile,) if profiles is None else profiles,
        factory,
        secret,
        cancelled=cancelled,
    )
    artifacts = run_expanded_browser_checks(
        catalogue,
        plan,
        factory,
        secret_resolver=lambda ref: secret(ref).get_secret_value(),
        probe_lifecycle=hooks if lifecycle else None,
        cancelled=cancelled,
    )
    assert not browser.contexts
    data = artifacts[0]["data"]
    template = next(t for t in catalogue.templates if t.id == plan.tasks[0].template_id)
    verified = evaluate_browser_input_identity(
        profile,
        plan.tasks[0],
        template,
        plan.id,
        data.get("browser_identity_proofs"),
        data["captures"],
    )
    return data, verified, (profile, plan.tasks[0], template, plan.id), resolved


@pytest.mark.parametrize("cookie", [False, True])
def test_authenticated_marker_and_fixed_page_have_three_fresh_identity_pairs(site, browser, cookie):
    data, verified, _, resolved = run(site, browser, cookie=cookie)
    assert data["state"] == "confirmed", data
    assert verified[0], verified
    assert [p["name"] for p in data["browser_identity_proofs"]] == ["baseline", "probe1", "probe2"]
    assert len({p["context_id"] for p in data["browser_identity_proofs"]}) == 3
    assert all(
        [p["phase"] for p in group["identity_proof"]["probes"]] == ["before", "after"]
        for group in data["browser_identity_proofs"]
    )
    if cookie:
        assert sum(path == "/login" for path, *_ in site[1]) == 3
    else:
        assert len(resolved) == 9  # Fresh before, initial target, after for each context.
        assert all(token is None for path, _, token, _ in site[1] if path == "/asset")
    fixed, verified, _, _ = run(site, browser, cookie=cookie, path="/fixed")
    assert fixed["state"] == "pass" and verified[0]


@pytest.mark.parametrize(
    "case", ["missing", "wrong", "expired", "revoked", "control", "no_lifecycle"]
)
def test_identity_failure_never_completes_and_retains_partial_facts(site, browser, case):
    options = {}
    if case == "missing":
        options["profiles"] = ()
    elif case == "wrong":
        site[2]["wrong"] = True
    elif case == "expired":
        options["expires_at"] = datetime.now(UTC) - timedelta(seconds=1)
    elif case == "revoked":
        site[2]["revoke_on_action"] = True
        options["cookie"] = True
    elif case == "control":
        site[2]["fail_secret_on_action"] = True
    else:
        options["lifecycle"] = False
    data, valid, _, _ = run(site, browser, **options)
    assert data["state"] == "inconclusive" and not valid[0]
    assert "DO-NOT-EXPOSE" not in json.dumps(data)
    if case in {"revoked", "control"}:
        assert len(data["captures"]) == 1
        assert (
            data["browser_identity_proofs"][0]["identity_proof"]["probes"][0]["phase"] == "before"
        )
    elif case in {"missing", "expired", "no_lifecycle"}:
        assert not site[1]
    if case == "revoked":
        assert sum(path == "/login" for path, *_ in site[1]) == 1


def test_cancel_between_contexts_keeps_finished_context_evidence(site, browser):
    data, valid, _, _ = run(
        site, browser, cancelled=lambda: sum(path == "/me" for path, *_ in site[1]) >= 2
    )
    assert data["state"] == "inconclusive" and not valid[0]
    assert len(data["captures"]) == 1
    assert len(data["browser_identity_proofs"]) == 1
    assert len(data["browser_identity_proofs"][0]["identity_proof"]["probes"]) == 2


@pytest.mark.parametrize("cookie", [False, True])
@pytest.mark.parametrize("resource", [False, True])
def test_redirect_canary_never_receives_supplied_credentials(site, browser, cookie, resource):
    canary_requests = []

    class Canary(BaseHTTPRequestHandler):
        def do_GET(self):
            canary_requests.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Canary)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    site[2]["redirect"] = f"http://127.0.0.1:{server.server_port}/canary"
    try:
        site[2]["resource_redirect"] = resource
        data, valid, _, _ = run(
            site, browser, path="/bad" if resource else "/redirect", cookie=cookie
        )
        assert data["state"] == "inconclusive" and not valid[0]
        assert not canary_requests
        assert (
            data["browser_identity_proofs"][0]["failure_reason"]
            == "authenticated_browser_redirect_not_followed"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    "tamper",
    [
        "missing_pair",
        "wrong_role",
        "wrong_task",
        "wrong_plan",
        "wrong_template",
        "expired",
        "wrong_identity",
        "duplicate_context",
        "wrong_name",
        "capture_context",
        "booleans",
    ],
)
def test_trusted_evaluator_rechecks_each_context_against_frozen_binding(site, browser, tamper):
    data, verified, frozen, _ = run(site, browser)
    assert verified[0]
    proofs, captures = (
        copy.deepcopy(data["browser_identity_proofs"]),
        copy.deepcopy(data["captures"]),
    )
    inner = proofs[1]["identity_proof"]
    if tamper == "missing_pair":
        inner["probes"].pop()
    elif tamper.startswith("wrong_") and tamper not in {"wrong_identity", "wrong_name"}:
        inner[tamper.removeprefix("wrong_") + "_id"] = "different"
    elif tamper == "expired":
        inner["probes"][0]["observed_at"] = "not-a-time"
    elif tamper == "wrong_identity":
        inner["probes"][1]["observed_identity"] = "someone-else"
    elif tamper == "duplicate_context":
        proofs[1]["context_id"] = proofs[0]["context_id"]
    elif tamper == "wrong_name":
        proofs[1]["name"] = "baseline"
    elif tamper == "capture_context":
        captures[1]["context_id"] = "other-context"
    else:
        inner["probes"] = [
            {"phase": "before", "verified": True},
            {"phase": "after", "verified": True},
        ]
    assert not evaluate_browser_input_identity(*frozen, proofs, captures)[0]


@pytest.mark.parametrize(
    "location,name",
    [("header", "Authorization"), ("header", "x-identity-token"), ("cookie", "sid")],
)
def test_template_cannot_override_identity_before_secret_resolution(site, browser, location, name):
    catalogue, plan, profile = configuration(site[0])
    template = catalogue.templates[0]
    modified = template.model_copy(
        update={
            "inputs": (
                *template.inputs,
                InputLocation(
                    location=location, name=name, secret_ref="forbidden-secret", mutable=False
                ),
            )
        }
    )
    catalogue = catalogue.model_copy(update={"templates": (modified,)})
    calls = []

    def resolver(ref):
        calls.append(ref)
        return SecretStr("no")

    def factory(role):
        return browser.new_context()

    hooks = AuthenticatedBrowserLifecycle(catalogue, plan, (profile,), factory, resolver)
    data = run_expanded_browser_checks(
        catalogue,
        plan,
        factory,
        secret_resolver=lambda ref: resolver(ref).get_secret_value(),
        probe_lifecycle=hooks,
    )[0]["data"]
    assert data["state"] == "inconclusive" and not calls and not site[1]


def test_actual_rendered_url_origin_is_checked_before_context_creation(site, browser):
    catalogue, plan, profile = configuration(site[0])
    hooks = AuthenticatedBrowserLifecycle(
        catalogue,
        plan,
        (profile,),
        lambda role: pytest.fail("must not create context"),
        lambda ref: pytest.fail("must not resolve secret"),
    )
    with pytest.raises(SessionUnavailable):
        hooks.open(
            plan.tasks[0],
            catalogue.templates[0],
            plan.id,
            "baseline",
            {"url": "http://localhost:1/other", "headers": {}},
        )


def test_captured_identity_expired_after_action_is_rejected(site, browser):
    data, verified, frozen, _ = run(site, browser)
    assert verified[0]
    profile, task, template, plan_id = frozen
    expiry = datetime.fromisoformat(
        data["browser_identity_proofs"][1]["identity_proof"]["probes"][1]["observed_at"]
    )
    profile = profile.model_copy(update={"expires_at": expiry})
    valid, reason = evaluate_browser_input_identity(
        profile, task, template, plan_id, data["browser_identity_proofs"], data["captures"]
    )
    assert not valid and reason == "authenticated_identity_probe_expired"


def test_expiry_during_secret_resolution_stops_before_target_io(site, browser, monkeypatch):
    import scopelens.expansion.authenticated_browser as implementation

    start = datetime.now(UTC)
    expires = start + timedelta(hours=1)
    catalogue, plan, profile = configuration(site[0], expires_at=expires)
    clock, resolved = [start], []

    class Clock:
        @staticmethod
        def now(_zone):
            return clock[0]

    monkeypatch.setattr(implementation, "datetime", Clock)

    def secret(ref):
        resolved.append(ref)
        clock[0] = expires + timedelta(seconds=1)
        return SecretStr("synthetic-alice")

    def factory(role):
        return browser.new_context()

    hooks = AuthenticatedBrowserLifecycle(catalogue, plan, (profile,), factory, secret)
    data = run_expanded_browser_checks(catalogue, plan, factory, probe_lifecycle=hooks)[0]["data"]
    assert data["state"] == "inconclusive"
    assert resolved == ["token-ref"]
    assert not site[1] and not browser.contexts
