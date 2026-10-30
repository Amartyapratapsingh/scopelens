"""Real Chromium confirmation distinguishes rendered markers from escaped reflection."""

import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import pytest
from playwright.sync_api import sync_playwright

from scopelens.browser.expanded_active import run_expanded_browser_checks
from scopelens.discovery import discover_catalogue, plan_assessment
from scopelens.domain.assessment import ActionPolicy


@pytest.fixture(scope="module")
def browser_fixture():
    requests = []

    class App(BaseHTTPRequestHandler):
        def respond(self):
            params = parse_qs(urlsplit(self.path).query)
            if self.command == "POST":
                params = parse_qs(
                    self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                )
            value = params.get("q", [""])[0]
            requests.append((self.command, urlsplit(self.path).path))
            if self.path.startswith("/dom/"):
                sink = "innerHTML" if "/bad" in self.path else "textContent"
                body = f'<html><body><div id="result"></div><script>document.getElementById("result").{sink}=new URLSearchParams(location.search).get("q") || "";</script></body></html>'
            else:
                body = (
                    "<html><body>"
                    + (value if self.path.startswith("/bad") else html.escape(value))
                    + "</body></html>"
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

        do_GET = respond
        do_POST = respond

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), App)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                yield f"http://127.0.0.1:{server.server_port}", browser, requests
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def assess(fixture, path, control, method="GET", **capture_limits):
    origin, browser, _ = fixture
    request = {"url": origin + path + ("?q=ordinary" if method == "GET" else ""), "method": method}
    if method == "POST":
        request.update(content_type="application/x-www-form-urlencoded", post_data="q=ordinary")
    catalogue = discover_catalogue(origin, browser_requests=(request,))
    policies = tuple(
        ActionPolicy(
            template_id=t.id,
            role_id=t.role_id,
            classification="read_only",
            approval_ref="fixture-operator",
        )
        for t in catalogue.templates
    )
    plan = plan_assessment(
        catalogue, scope_version="fixture", policies=policies, reviewed_control_ids=(control,)
    )
    results = run_expanded_browser_checks(
        catalogue, plan, lambda role: browser.new_context(service_workers="block"), **capture_limits
    )
    assert len(results) == 1
    assert len(browser.contexts) == 0
    return results[0]["data"]


@pytest.mark.parametrize("control", ["SL-C03-XSS-01", "SL-C03-HTML-01"])
def test_real_browser_vulnerable_and_escaped_negative(browser_fixture, control):
    bad = assess(browser_fixture, "/bad", control)
    fixed = assess(browser_fixture, "/fixed", control)
    assert bad["state"] == "confirmed", bad
    assert fixed["state"] == "pass", fixed
    assert len({c["nonce"] for c in bad["captures"]}) == 3


def test_real_browser_dom_only_execution(browser_fixture):
    bad = assess(browser_fixture, "/dom/bad", "SL-C03-DOMXSS-01")
    fixed = assess(browser_fixture, "/dom/fixed", "SL-C03-DOMXSS-01")
    assert bad["state"] == "confirmed", bad
    assert fixed["state"] == "pass", fixed
    assert not any(c["marker_in_response"] for c in bad["captures"])
    reflected = assess(browser_fixture, "/bad", "SL-C03-DOMXSS-01")
    assert reflected["state"] == "inconclusive"


def test_real_browser_approved_form_post(browser_fixture):
    start = len(browser_fixture[2])
    result = assess(browser_fixture, "/bad", "SL-C03-XSS-01", method="POST")
    assert result["state"] == "confirmed", result
    assert [method for method, path in browser_fixture[2][start:] if path == "/bad"] == ["POST"] * 3


def test_expanded_get_captures_use_durable_admission_before_navigation(browser_fixture):
    from types import SimpleNamespace

    from scopelens.browser.admission import ReviewedCaptureAdmission
    from scopelens.browser.worker import ActionDenied

    calls = []
    controller = SimpleNamespace(sequence=40)

    def admit(op, **fields):
        calls.append((op, fields))
        if op == "admit" and fields["sequence"] == 43:
            raise ActionDenied("active_action_budget")
        return {"reviewed_probe": op == "admit"}

    controller.command = admit
    before = len(browser_fixture[2])
    result = assess(
        browser_fixture,
        "/bad",
        "SL-C03-XSS-01",
        action_admission=ReviewedCaptureAdmission(controller).capture,
        max_actions=500,
    )
    assert result["state"] == "inconclusive"
    assert result["reason"] == "browser_action_not_admitted"
    assert len(result["captures"]) == 2
    assert len(browser_fixture[2]) - before == 2
    assert controller.sequence == 42
    assert [op for op, _ in calls] == ["admit", "complete", "admit", "complete", "admit"]
    assert all(
        fields["probe_task"] == "input:" + result["task_id"]
        for op, fields in calls
        if op == "admit"
    )


def test_active_ceiling_does_not_raise_legacy_post_capture_cap(browser_fixture):
    result = assess(
        browser_fixture,
        "/bad",
        "SL-C03-HTML-01",
        method="POST",
        max_actions=500,
        max_exploration_actions=2,
    )
    assert result["state"] == "inconclusive"
    assert result["reason"] == "browser_action_budget_exhausted"
    assert len(result["captures"]) == 2


@pytest.mark.parametrize("admission", ["absent", "unvalidated"])
def test_unreviewed_get_keeps_local_exploration_cap(browser_fixture, admission):
    from types import SimpleNamespace

    from scopelens.browser.admission import ReviewedCaptureAdmission

    controller = SimpleNamespace(sequence=0, command=lambda *a, **k: {"reviewed_probe": False})
    result = assess(
        browser_fixture,
        "/bad",
        "SL-C03-HTML-01",
        max_actions=500,
        max_exploration_actions=2,
        action_admission=(
            None if admission == "absent" else ReviewedCaptureAdmission(controller).capture
        ),
    )
    assert result["state"] == "inconclusive"
    assert result["reason"] == "browser_action_budget_exhausted"
    assert len(result["captures"]) == 2


@pytest.mark.parametrize("ceiling,expected", [(500, 42), (41, 41)])
def test_expanded_reviewed_captures_exceed_40_with_bounded_task_usage(
    browser_fixture, settings, ceiling, expected
):
    from collections import Counter
    from types import SimpleNamespace

    from scopelens.browser.admission import ReviewedCaptureAdmission
    from scopelens.domain.registry import load_registry

    origin, browser, _ = browser_fixture
    catalogue = discover_catalogue(
        origin,
        browser_requests=tuple(
            {"url": origin + f"/bad/{index}?q=ordinary", "method": "GET"} for index in range(14)
        ),
    )
    policies = tuple(
        ActionPolicy(
            template_id=t.id,
            role_id=t.role_id,
            classification="read_only",
            approval_ref="fixture-operator",
        )
        for t in catalogue.templates
    )
    plan = plan_assessment(
        catalogue,
        scope_version="fixture",
        policies=policies,
        reviewed_control_ids=("SL-C03-HTML-01",),
    )
    counts = Counter()
    controller = SimpleNamespace(sequence=40)

    def admit(op, **fields):
        if op == "admit":
            counts[fields["probe_task"]] += 1
        return {"reviewed_probe": op == "admit"}

    controller.command = admit
    results = run_expanded_browser_checks(
        catalogue,
        plan,
        lambda role: browser.new_context(service_workers="block"),
        max_actions=ceiling,
        max_exploration_actions=2,
        action_admission=ReviewedCaptureAdmission(controller).capture,
    )
    assert sum(len(a["data"]["captures"]) for a in results) == expected
    assert sum(counts.values()) == expected
    cap = (
        load_registry(settings.checks_registry_dir)
        .get("SL-C03-HTML-01")
        .allowed_action.max_requests
    )
    assert all(count <= cap for count in counts.values())
    assert controller.sequence == 40 + expected
    assert len(browser.contexts) == 0
    if ceiling == 41:
        assert results[-1]["data"]["reason"] == "browser_action_budget_exhausted"
