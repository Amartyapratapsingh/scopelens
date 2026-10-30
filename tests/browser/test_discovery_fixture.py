"""Discover unlisted operations before a reviewed local read-only assessment."""

import json
from threading import Thread
from uuid import uuid4

import httpx
import pytest
from labs.discovery.app import make_server, routes
from playwright.sync_api import sync_playwright

from scopelens.browser.worker import ARTIFACT, Controller
from scopelens.checks.crawl import CrawlConfig
from scopelens.checks.expanded_active import run_expanded_checks
from scopelens.discovery import discover_catalogue, plan_assessment
from scopelens.domain.assessment import ActionPolicy
from scopelens.domain.collection import CollectedResponse
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.integration import prepare_catalogue


@pytest.mark.parametrize("variant,expected", [("bad", "confirmed"), ("fixed", "pass")])
def test_discovery_to_query_form_json_path_assessment(variant, expected, monkeypatch, capsys):
    server = make_server(variant=variant)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    config = CrawlConfig(
        origin=origin,
        scheme="http",
        host="127.0.0.1",
        port=server.server_port,
        max_pages=8,
        max_depth=2,
        timeout=3,
        max_body_bytes=65536,
        user_agent="owned-fixture",
    )
    monkeypatch.setenv("SCOPELENS_EGRESS_TOKEN", "synthetic-test-token")
    controller = Controller(config, "http://127.0.0.1:9", "discovery-fixture-owner")
    try:
        with httpx.Client(timeout=3, trust_env=False) as client:
            responses = []
            for path in ("/", "/openapi.json"):
                response = client.get(origin + path)
                responses.append(
                    CollectedResponse(
                        url=str(response.url),
                        route=path,
                        status=response.status_code,
                        content_type=response.headers["content-type"],
                        body_excerpt=response.text,
                    )
                )
            static = discover_catalogue(origin, responses=responses)
            assert not any(t.path == routes()["json"] for t in static.templates)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    context = browser.new_context(service_workers="block")
                    context.route("**/*", controller.route)
                    page = context.new_page()
                    page.goto(origin + "/", wait_until="networkidle")
                    context.close()
                finally:
                    browser.close()
            captures = [
                json.loads(line[len(ARTIFACT) :])
                for line in capsys.readouterr().out.splitlines()
                if line.startswith(ARTIFACT)
            ]
            catalogue = prepare_catalogue(
                origin,
                captures,
                AssessmentConfiguration(scope_version_id=uuid4()),
                prior=static,
            )
            selected = tuple(
                t
                for t in catalogue.templates
                if t.path
                in {
                    routes()["query"],
                    routes()["form"],
                    routes()["json"],
                    routes()["path"] + "/apple",
                }
                and t.inputs
            )
            assert {i.location for t in selected for i in t.inputs} == {
                "query",
                "form",
                "json",
                "path",
            }
            json_template = next(t for t in selected if t.path == routes()["json"])
            assert not json_template.baseline_observed
            assert json_template.inputs[0].pointer == "/search/text"
            catalogue = catalogue.model_copy(update={"templates": selected})
            unreviewed = plan_assessment(
                catalogue, scope_version="fixture", reviewed_control_ids=("SL-C03-SQL-01",)
            )
            post_ids = {t.id for t in selected if t.method == "POST"}
            assert post_ids and all(
                t.state == "blocked" for t in unreviewed.tasks if t.template_id in post_ids
            )
            policies = tuple(
                ActionPolicy(
                    template_id=t.id,
                    role_id=t.role_id,
                    classification="read_only",
                    approval_ref="owned-memory-only-read-query",
                    control_ids=("SL-C03-SQL-01",),
                )
                for t in selected
            )
            plan = plan_assessment(
                catalogue,
                scope_version="fixture",
                policies=policies,
                reviewed_control_ids=("SL-C03-SQL-01",),
            )
            results = run_expanded_checks(catalogue, plan, client)
            assert len(results) == 4
            assert {r["data"]["state"] for r in results} == {expected}
            assert all(r["data"]["requests_used"] == 16 for r in results)
    finally:
        controller.http.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
