"""Real explorer interception retains metadata for blocked SPA POST intentions."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from playwright.sync_api import sync_playwright

from scopelens.browser.discovery import request_templates
from scopelens.browser.worker import ARTIFACT, Controller
from scopelens.checks.crawl import CrawlConfig
from scopelens.discovery import plan_assessment
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.integration import prepare_catalogue


def test_request_shape_is_bounded_and_secrets_become_references():
    templates = request_templates(
        "https://owned.example",
        url="https://owned.example/hidden?token=query-secret&q=ordinary",
        method="POST",
        headers={
            "content-type": "application/json",
            "Cookie": "sid=session-secret",
            "Authorization": "Bearer header-secret",
        },
        post_data=json.dumps({"search": {"text": "ordinary"}, "password": "body-secret"}),
    )
    template = templates[0]
    serialized = template.model_dump_json()
    for secret in ("query-secret", "session-secret", "header-secret", "body-secret"):
        assert secret not in serialized
    assert not template.baseline_observed
    assert (
        next(i for i in template.inputs if i.pointer == "/search/text").baseline_value == "ordinary"
    )
    assert all(not i.mutable and i.baseline_value is None for i in template.inputs if i.secret_ref)
    with pytest.raises(ValueError, match="capture limit"):
        request_templates(
            "https://owned.example",
            url="https://owned.example/",
            method="POST",
            headers={},
            post_data="x" * 65_537,
        )


def test_spa_post_is_discovered_but_not_sent(monkeypatch, capsys):
    received = []

    class App(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append((self.command, self.path))
            body = (
                b"""<!doctype html><html><body><script>
            Promise.allSettled([
              fetch('/unlisted-jade?filter=blue'),
              fetch('/unlisted-iris', {method: 'POST', headers: {'content-type': 'application/json'},
                body: JSON.stringify({search:{text:'ordinary'}, csrf_token:'fixture-secret'})}),
              fetch('/unlisted-fern', {method: 'POST',
                headers: {'content-type':'application/x-www-form-urlencoded'}, body:'q=ordinary&password=fixture-password'})
            ]).then(() => document.body.dataset.finished='yes');
            </script></body></html>"""
                if self.path == "/"
                else b"{}"
            )
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/html" if self.path == "/" else "application/json"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            received.append((self.command, self.path))
            self.send_response(500)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), App)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    config = CrawlConfig(
        origin=origin,
        scheme="http",
        host="127.0.0.1",
        port=server.server_port,
        max_pages=4,
        max_depth=2,
        timeout=3,
        max_body_bytes=65536,
        user_agent="owned-fixture",
    )
    monkeypatch.setenv("SCOPELENS_EGRESS_TOKEN", "synthetic-test-token")
    controller = Controller(config, "http://127.0.0.1:9", "test-owner")
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context(service_workers="block")
                context.route("**/*", controller.route)
                page = context.new_page()
                page.goto(origin + "/")
                page.wait_for_function("document.body.dataset.finished === 'yes'")
                context.close()
            finally:
                browser.close()
    finally:
        controller.http.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    output = capsys.readouterr().out
    assert "fixture-secret" not in output and "fixture-password" not in output
    artifacts = [
        json.loads(line[len(ARTIFACT) :])
        for line in output.splitlines()
        if line.startswith(ARTIFACT)
    ]
    configuration = AssessmentConfiguration(scope_version_id=uuid4())
    catalogue = prepare_catalogue(origin, artifacts, configuration)
    by_path = {t.path: t for t in catalogue.templates}
    assert {"/unlisted-jade", "/unlisted-iris", "/unlisted-fern"} <= by_path.keys()
    assert (
        next(
            i for i in by_path["/unlisted-iris"].inputs if i.pointer == "/search/text"
        ).baseline_value
        == "ordinary"
    )
    plan = plan_assessment(catalogue, scope_version="owned-browser-fixture")
    posts = {t.id for t in catalogue.templates if t.method == "POST"}
    assert posts and all(t.state == "blocked" for t in plan.tasks if t.template_id in posts)
    assert not any(method == "POST" for method, _ in received)
    assert {urlsplit(url).path for _, url in received} == {"/", "/unlisted-jade"}
