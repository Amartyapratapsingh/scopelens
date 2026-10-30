"""Reviewed annotations stay on active transport and never leak to target traffic."""

import json
from types import SimpleNamespace

import httpx
import pytest

from scopelens.broker.probe_tasks import PROBE_HEADER, conditional_reference
from scopelens.browser.worker import Controller
from scopelens.checks import active, conditional
from scopelens.discovery.requests import render_request
from scopelens.domain.assessment import InputLocation, RequestTemplate

ENTRY = {"kind": "sql", "path": "/search", "parameter": "q"}


def test_http_input_capture_tags_every_comparison_without_changing_values(monkeypatch):
    observed = []

    def response(request):
        observed.append(request)
        return httpx.Response(200, text="fixture")

    client = httpx.Client(transport=httpx.MockTransport(response))
    monkeypatch.setenv("SCOPELENS_CONDITIONAL_PROBES", json.dumps([ENTRY]))
    monkeypatch.setattr(
        active,
        "Crawler",
        lambda config: SimpleNamespace(
            _http=lambda: client,
            _in_scope=lambda url: True,
        ),
    )
    artifacts = list(
        active.http_probes(SimpleNamespace(origin="https://fixture.invalid", max_body_bytes=1024))
    )
    assert len(observed) == 18
    assert all(r.headers[PROBE_HEADER] == conditional_reference(ENTRY) for r in observed)
    assert [r.url.params["q"] for r in observed] == [v for _, _, v in active.sql_probes(ENTRY)]
    assert artifacts[0]["kind"] == "active_probe"
    assert artifacts[0]["data"]["error"] is None


def test_configuration_capture_uses_same_frozen_reference(monkeypatch):
    entry = {"kind": "cors", "path": "/"}
    observed = []
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: observed.append(request) or httpx.Response(200)
        )
    )
    monkeypatch.setenv("SCOPELENS_CONDITIONAL_PROBES", json.dumps([entry]))
    monkeypatch.setattr(
        conditional,
        "Crawler",
        lambda config: SimpleNamespace(
            _http=lambda: client,
            _in_scope=lambda url: True,
        ),
    )
    conditional.collect(SimpleNamespace(origin="https://fixture.invalid"))
    assert len(observed) == 2
    assert all(r.headers[PROBE_HEADER] == conditional_reference(entry) for r in observed)


def test_browser_annotation_is_only_for_reviewed_navigation(monkeypatch):
    monkeypatch.setenv("SCOPELENS_EGRESS_TOKEN", "fixture")
    instance = Controller.__new__(Controller)
    instance.in_scope = lambda url: True
    instance.capture_request_intent = lambda request: None
    url = "https://fixture.invalid/search?q=marker"
    instance.probe_request = (url, conditional_reference(ENTRY))
    observed = []
    for request_url in (url, "https://fixture.invalid/script.js", url):
        route = SimpleNamespace(
            request=SimpleNamespace(
                url=request_url, method="GET", headers={PROBE_HEADER: "forged"}
            ),
            continue_=lambda **fields: observed.append(fields["headers"]),
        )
        instance.route(route)
    assert observed[0][PROBE_HEADER] == conditional_reference(ENTRY)
    assert all(PROBE_HEADER not in headers for headers in observed[1:])


def test_target_template_cannot_supply_accounting_authority():
    template = RequestTemplate(
        id="fixture",
        origin="https://fixture.invalid",
        path="/",
        route_template="/",
        method="GET",
        inputs=(InputLocation(location="header", name=PROBE_HEADER, baseline_value="forged"),),
    )
    with pytest.raises(ValueError, match="transport authority"):
        render_request(template)
