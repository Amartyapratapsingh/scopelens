"""Local owned fixture plus the deployed gate's report assertions, without deployment."""

import copy
from http.server import ThreadingHTTPServer
from threading import Thread
from uuid import uuid4

import httpx
import pytest
from labs.expansion_browser.app import FIXTURE_PASSWORD, handler
from playwright.sync_api import sync_playwright
from pydantic import SecretStr
from scripts.verify_authenticated_browser_lab import CONTROL, configuration, verify_report

from scopelens.browser.expanded_active import run_expanded_browser_checks
from scopelens.discovery.planner import plan_assessment
from scopelens.domain.assessment import DiscoveryCatalogue
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.authenticated_browser import AuthenticatedBrowserLifecycle
from scopelens.writer.report import _capabilities, _reach_summary


@pytest.fixture
def app():
    records = {"bad": "untouched-bad", "fixed": "untouched-fixed"}
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(records))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", records
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("variant", ["bad", "fixed"])
def test_protected_html_requires_role_and_renders_or_escapes_only_query(app, variant):
    base = app[0] + "/" + variant
    marker = '<span data-fixture="owned">example</span>'
    with httpx.Client(follow_redirects=False) as client:
        assert client.get(base + "/protected-html", params={"q": marker}).status_code == 403
        client.cookies.set("sid", "B")
        assert client.get(base + "/protected-html").status_code == 403
        client.cookies.clear()
        client.post(
            base + "/credential-login", json={"role": "A", "password": FIXTURE_PASSWORD}
        ).raise_for_status()
        response = client.get(base + "/protected-html", params={"q": marker})
        assert response.status_code == 200 and response.headers["content-type"] == "text/html"
        assert (marker in response.text) == (variant == "bad")
        assert ("&lt;span" in response.text) == (variant == "fixed")
        assert client.post(base + "/protected-html").status_code == 405
    assert app[1] == {"bad": "untouched-bad", "fixed": "untouched-fixed"}


@pytest.mark.parametrize("variant,expected", [("bad", "confirmed_issue"), ("fixed", "pass")])
def test_existing_browser_collector_and_deployed_assertions_on_local_fixture(
    app, variant, expected
):
    frozen = configuration({"id": str(uuid4()), "origin": app[0]}, variant, "fixture-secret-ref")
    config = AssessmentConfiguration.model_validate(frozen)
    assert FIXTURE_PASSWORD not in config.model_dump_json()
    assert config.policies[0].control_ids == (CONTROL,)
    catalogue = DiscoveryCatalogue(origin=app[0], templates=config.templates)
    plan = plan_assessment(
        catalogue,
        scope_version=str(config.scope_version_id),
        policies=config.policies,
        reviewed_control_ids=(CONTROL,),
        profile="authenticated-api-v1",
    )
    resolved = []

    def secret(ref):
        assert ref == "fixture-secret-ref"
        resolved.append(ref)
        return SecretStr(FIXTURE_PASSWORD)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:

            def factory(role):
                return browser.new_context(service_workers="block")

            lifecycle = AuthenticatedBrowserLifecycle(
                catalogue, plan, config.identities, factory, secret
            )
            artifacts = run_expanded_browser_checks(
                catalogue, plan, factory, probe_lifecycle=lifecycle
            )
            assert not browser.contexts
        finally:
            browser.close()
    assert len(artifacts) == 1 and len(resolved) == 3
    assert artifacts[0]["data"]["state"] == ("confirmed" if variant == "bad" else "pass")
    outcome = {
        "check_id": CONTROL,
        "status": expected,
        "summary": "fixture",
        "required_instances": [plan.tasks[0].id],
        "completed_instances": [plan.tasks[0].id],
        "evidence_refs": ["trusted-fixture-ref"],
    }
    frozen_plan = {
        "request_catalogue": catalogue.model_dump(mode="json"),
        "input_assessment_plan": plan.model_dump(mode="json"),
        "expansion_config": frozen,
    }
    report = {
        "profile": "authenticated-api-v1",
        "check_outcomes": [outcome],
        "capabilities": _capabilities(frozen_plan, "authenticated-api-v1"),
        "reach": _reach_summary(frozen_plan, [outcome], "authenticated-api-v1", []),
    }
    evidence = [
        {
            "id": "trusted-fixture-ref",
            "trusted": True,
            "producer": "reviewed_expansion_browser_capture",
        }
    ]
    captures = {"trusted-fixture-ref": artifacts[0]}
    html = "authenticated-api-v1 " + CONTROL
    verify_report(report, html, evidence, captures, variant, frozen)
    with pytest.raises(AssertionError, match="secret leaked"):
        verify_report(report, html + FIXTURE_PASSWORD, evidence, captures, variant, frozen)
    with pytest.raises(AssertionError, match="cookie leaked"):
        verify_report(report, html, evidence, {**captures, "unrelated": "sid=A"}, variant, frozen)
    misleading = copy.deepcopy(report)
    misleading["capabilities"]["installed_tools"]["count"] = 3
    with pytest.raises(AssertionError, match="unmeasured capability"):
        verify_report(misleading, html, evidence, captures, variant, frozen)
    leaked = copy.deepcopy(report)
    leaked["assessment_plan"] = {"request_catalogue": frozen_plan["request_catalogue"]}
    with pytest.raises(AssertionError, match="private assessment inputs"):
        verify_report(leaked, html, evidence, captures, variant, frozen)
    altered = copy.deepcopy(captures)
    altered["trusted-fixture-ref"]["data"]["browser_identity_proofs"][1]["identity_proof"][
        "probes"
    ].pop()
    with pytest.raises(AssertionError, match="before_after_identity_probes_required"):
        verify_report(report, html, evidence, altered, variant, frozen)
    assert app[1] == {"bad": "untouched-bad", "fixed": "untouched-fixed"}
