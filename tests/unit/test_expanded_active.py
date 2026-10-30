"""Real HTTP proof acceptance for discovered query, form and JSON inputs."""

import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from scopelens.checks.expanded_active import run_expanded_checks
from scopelens.discovery import discover_catalogue, plan_assessment
from scopelens.domain.assessment import ActionPolicy


@pytest.fixture
def active_fixture():
    requests = []

    class App(BaseHTTPRequestHandler):
        def handle_request(self):
            query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if body:
                if "json" in self.headers.get("Content-Type", ""):
                    query = {k: [v] for k, v in json.loads(body).items()}
                else:
                    query.update(parse_qs(body.decode(), keep_blank_values=True))
            value = str(query.get("q", query.get("next", [""]))[0])
            path = urlsplit(self.path).path
            requests.append((self.command, path, value))
            broken = "/bad/" in path
            headers = {}
            status = 200
            result = {"result": "found" if value == "apple" else "none", "timestamp": len(requests)}
            if "sql" in path:
                with sqlite3.connect(":memory:") as db:
                    db.execute("CREATE TABLE fruit (name TEXT)")
                    db.execute("INSERT INTO fruit VALUES ('apple')")
                    try:
                        rows = (
                            db.execute(f"SELECT name FROM fruit WHERE name = '{value}'").fetchall()
                            if broken
                            else db.execute(
                                "SELECT name FROM fruit WHERE name = ?", (value,)
                            ).fetchall()
                        )
                        result["result"] = "found" if rows else "none"
                    except sqlite3.Error:
                        status = 400
                        result["result"] = "invalid input"
            elif "redirect" in path:
                status = 302
                headers["Location"] = value if broken else "/safe"
            elif "cors" in path:
                headers["Access-Control-Allow-Origin"] = (
                    self.headers.get("Origin", "https://primary.example") if broken else "*"
                )
                headers["Access-Control-Allow-Credentials"] = "true"
            elif "header" in path and broken and "\r\nX-Scopelens-Probe: " in value:
                headers["X-Scopelens-Probe"] = value.split("\r\nX-Scopelens-Probe: ", 1)[1]
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for name, header_value in headers.items():
                self.send_header(name, header_value)
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

        do_GET = handle_request
        do_POST = handle_request

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), App)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def run_case(origin, path, control, *, method="GET", body_type=None, budget=100):
    request = {
        "url": origin + path + ("?next=/safe" if "redirect" in path else "?q=apple")
        if not body_type
        else origin + path,
        "method": method,
    }
    if body_type == "json":
        request.update(content_type="application/json", json={"q": "apple"})
    if body_type == "form":
        request.update(content_type="application/x-www-form-urlencoded", post_data="q=apple")
    cat = discover_catalogue(origin, browser_requests=(request,))
    policies = tuple(
        ActionPolicy(
            template_id=t.id,
            role_id=t.role_id,
            classification="read_only",
            approval_ref="fixture-reviewed",
        )
        for t in cat.templates
    )
    plan = plan_assessment(
        cat, scope_version="fixture", policies=policies, reviewed_control_ids=(control,)
    )
    with httpx.Client(trust_env=False, timeout=2) as client:
        results = run_expanded_checks(cat, plan, client, max_requests=budget)
    return results


@pytest.mark.parametrize(
    "path,control",
    [
        ("sql", "SL-C03-SQL-01"),
        ("redirect", "SL-C04-REDIRECT-01"),
        ("cors", "SL-C04-CORS-01"),
        ("header", "SL-C04-HDRINJECT-01"),
    ],
)
def test_http_vulnerable_and_fixed_workflows(active_fixture, path, control):
    origin, _ = active_fixture
    bad = run_case(origin, "/bad/" + path, control)
    fixed = run_case(origin, "/fixed/" + path, control)
    assert len(bad) == len(fixed) == 1
    assert bad[0]["data"]["state"] == "confirmed", bad
    assert fixed[0]["data"]["state"] == "pass", fixed
    assert all(c["response_url_matches"] for c in bad[0]["data"]["captures"])
    if path == "sql":
        assert bad[0]["data"]["captures"][0]["ignored_noise_fields"] == ("/timestamp",)


@pytest.mark.parametrize("body_type", ["json", "form"])
def test_sql_on_operator_classified_post(active_fixture, body_type):
    origin, requests = active_fixture
    result = run_case(origin, "/bad/sql", "SL-C03-SQL-01", method="POST", body_type=body_type)
    assert result[0]["data"]["state"] == "confirmed"
    assert all(method == "POST" for method, _, _ in requests)


def test_budget_exhaustion_preserves_incomplete_task(active_fixture):
    origin, requests = active_fixture
    result = run_case(origin, "/bad/sql", "SL-C03-SQL-01", budget=3)
    assert result[0]["data"]["state"] == "inconclusive"
    assert result[0]["data"]["reason"] == "request_budget_exhausted"
    assert len(requests) == result[0]["data"]["requests_used"] == 3
    assert len(result[0]["data"]["captures"]) == 3


def test_cancelled_task_sends_nothing(active_fixture):
    origin, requests = active_fixture
    cat = discover_catalogue(origin, browser_requests=({"url": origin + "/bad/sql?q=apple"},))
    plan = plan_assessment(cat, scope_version="fixture", reviewed_control_ids=("SL-C03-SQL-01",))
    with httpx.Client(trust_env=False) as client:
        result = run_expanded_checks(cat, plan, client, cancelled=lambda: True)
    assert result[0]["data"]["reason"] == "cancelled"
    assert requests == []


def test_browser_execution_never_inferred_from_http_reflection(active_fixture):
    origin, requests = active_fixture
    result = run_case(origin, "/bad/xss", "SL-C03-XSS-01")
    assert result[0]["data"]["state"] == "blocked"
    assert result[0]["data"]["reason"] == "controlled_browser_confirmation_required"
    assert not requests


def test_unclassified_post_does_not_execute(active_fixture):
    origin, requests = active_fixture
    cat = discover_catalogue(
        origin,
        browser_requests=(
            {
                "url": origin + "/bad/sql",
                "method": "POST",
                "content_type": "application/json",
                "json": {"q": "apple"},
            },
        ),
    )
    plan = plan_assessment(cat, scope_version="fixture", reviewed_control_ids=("SL-C03-SQL-01",))
    with httpx.Client(trust_env=False) as client:
        result = run_expanded_checks(cat, plan, client)
    assert result[0]["data"]["state"] == "blocked"
    assert requests == []


def test_authenticated_template_cannot_silently_use_anonymous_client(active_fixture):
    origin, requests = active_fixture
    cat = discover_catalogue(
        origin,
        role_id="operator-account",
        browser_requests=({"url": origin + "/bad/redirect?next=/safe", "method": "GET"},),
    )
    policies = tuple(
        ActionPolicy(
            template_id=t.id, role_id=t.role_id, classification="read_only", approval_ref="fixture"
        )
        for t in cat.templates
    )
    plan = plan_assessment(
        cat,
        scope_version="fixture",
        policies=policies,
        reviewed_control_ids=("SL-C04-REDIRECT-01",),
    )
    assert plan.tasks
    with httpx.Client(trust_env=False, timeout=2) as client:
        result = run_expanded_checks(cat, plan, client)
    assert result[0]["data"]["state"] == "blocked"
    assert result[0]["data"]["reason"] == "authenticated_input_transport_not_integrated"
    assert requests == []
