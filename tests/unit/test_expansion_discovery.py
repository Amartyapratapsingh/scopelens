"""Discovery acceptance on previously unlisted routes, with no executable target list."""

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from scopelens.discovery import discover_catalogue, plan_assessment
from scopelens.discovery.catalogue import changing_json_fields
from scopelens.discovery.requests import render_request
from scopelens.domain.assessment import ActionPolicy, RelatedOriginGrant
from scopelens.domain.collection import CollectedResponse

ORIGIN = "https://fixture.example"


def response(path, body, ctype="text/html"):
    return CollectedResponse(
        url=ORIGIN + path,
        route=path,
        status=200,
        content_type=ctype,
        body_excerpt=body,
        via_proxy=True,
    )


def fixture_catalogue():
    return discover_catalogue(
        ORIGIN,
        responses=(
            response(
                "/",
                """
        <a href="/unlisted-rose?q=ordinary">search</a>
        <form action="/unlisted-lilac" method="post">
        <input name="message" value="hello"><input name="csrf_token" value="do-not-store">
        <select name="choice"><option selected value="one">One</option></select>
        <input name="ignored" value="no" disabled></form>
        <script>fetch('/unlisted-jasmine?value=seed')</script>
        """,
            ),
        ),
        browser_requests=(
            {
                "url": ORIGIN + "/unlisted-orchid",
                "method": "POST",
                "content_type": "application/json",
                "json": {"search": {"text": "ordinary"}, "page": 1},
            },
        ),
    )


def test_discovery_acceptance_from_html_and_spa_capture():
    cat = fixture_catalogue()
    by_path = {t.path: t for t in cat.templates}
    assert {
        "/",
        "/unlisted-rose",
        "/unlisted-lilac",
        "/unlisted-jasmine",
        "/unlisted-orchid",
    } <= by_path.keys()
    assert by_path["/unlisted-rose"].inputs[0].baseline_value == "ordinary"
    assert by_path["/unlisted-orchid"].method == "POST"
    assert {i.pointer for i in by_path["/unlisted-orchid"].inputs} == {"/search/text", "/page"}
    assert "do-not-store" not in cat.model_dump_json()
    assert not any(i.name == "ignored" for i in by_path["/unlisted-lilac"].inputs)
    plan = plan_assessment(cat, scope_version="scope-1")
    post_ids = {t.id for t in cat.templates if t.method == "POST"}
    assert all(t.state == "blocked" for t in plan.tasks if t.template_id in post_ids)
    get_id = by_path["/unlisted-rose"].id
    assert {t.control_id for t in plan.tasks if t.template_id == get_id and t.state == "ready"} >= {
        "SL-C03-SQL-01",
        "SL-C03-XSS-01",
        "SL-C03-HTML-01",
    }


def test_policy_is_exact_method_role_and_template():
    cat = fixture_catalogue()
    target = next(t for t in cat.templates if t.path == "/unlisted-orchid")
    policies = (
        ActionPolicy(
            template_id=target.id,
            role_id="anonymous",
            classification="read_only",
            approval_ref="operator:1",
            control_ids=("SL-C03-SQL-01",),
        ),
    )
    plan = plan_assessment(cat, scope_version="1", policies=policies)
    selected = [t for t in plan.tasks if t.template_id == target.id]
    assert any(t.state == "ready" for t in selected)
    assert all(t.state == "blocked" for t in selected if t.control_id != "SL-C03-SQL-01")
    assert all(
        t.state == "blocked"
        for t in plan.tasks
        if t.template_id != target.id
        and next(x for x in cat.templates if x.id == t.template_id).method == "POST"
    )


def test_har_secrets_are_references_and_duplicate_query_fields_survive():
    cat = discover_catalogue(
        ORIGIN,
        har_documents=(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "url": ORIGIN + "/search?q=a&q=b&access_token=query-secret",
                                "method": "GET",
                                "headers": [
                                    {"name": "Authorization", "value": "Bearer header-secret"}
                                ],
                                "cookies": [{"name": "sid", "value": "cookie-secret"}],
                            }
                        }
                    ]
                }
            },
        ),
    )
    data = cat.model_dump_json()
    for secret in ("query-secret", "header-secret", "cookie-secret"):
        assert secret not in data
    template = cat.templates[0]
    with pytest.raises(ValueError, match="secret refresh"):
        render_request(template)
    rendered = render_request(template, {"query:q:1": "changed"}, lambda ref: "fresh")
    assert parse_qs(urlsplit(rendered["url"]).query)["q"] == ["a", "changed"]
    assert rendered["headers"]["Cookie"] == "sid=fresh"
    with pytest.raises(ValueError, match="cannot mutate"):
        render_request(template, {"query:access_token:0": "x"}, lambda ref: "fresh")


def test_json_render_nested_arrays_and_types():
    cat = discover_catalogue(
        ORIGIN,
        browser_requests=(
            {
                "url": ORIGIN + "/api",
                "method": "POST",
                "content_type": "application/json",
                "json": {"rows": [{"q": "base", "enabled": True}], "count": 4},
            },
        ),
    )
    rendered = render_request(cat.templates[0], {"json:/rows/0/q:0": "probe"})
    assert rendered["json"] == {"rows": [{"q": "probe", "enabled": True}], "count": 4}


def test_openapi_preserves_path_query_json_examples_and_does_not_follow_remote_refs():
    doc = {
        "openapi": "3.0.3",
        "paths": {
            "/items/{item}": {
                "parameters": [
                    {"in": "path", "name": "item", "required": True, "example": "canary"}
                ],
                "get": {"parameters": [{"in": "query", "name": "filter", "example": "blue"}]},
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"text": {"type": "string", "example": "hello"}},
                                }
                            }
                        }
                    }
                },
            },
            "/unknown/{id}": {
                "get": {
                    "parameters": [
                        {"in": "path", "name": "id", "required": True, "schema": {"type": "string"}}
                    ]
                }
            },
            "/remote": {"$ref": "https://evil.example/spec"},
        },
    }
    cat = discover_catalogue(ORIGIN, openapi_documents=(doc,))
    get = next(t for t in cat.templates if t.path == "/items/canary" and t.method == "GET")
    assert (
        render_request(get, {"path:item:0": "new value"})["url"]
        == ORIGIN + "/items/new%20value?filter=blue"
    )
    assert not any(t.path == "/remote" for t in cat.templates)
    plan = plan_assessment(cat, scope_version="1")
    unresolved = next(t.id for t in cat.templates if "{id}" in t.path)
    assert all(t.state == "blocked" for t in plan.tasks if t.template_id == unresolved)


def test_no_host_inherits_authority_and_resource_grant_cannot_scan():
    responses = (
        response(
            "/",
            '<a href="https://cdn.example/a?q=a">a</a><a href="https://other.example/b?q=b">b</a>',
        ),
    )
    grants = (
        RelatedOriginGrant(
            origin="https://cdn.example",
            purpose="resource_only",
            grant_id="g",
            scope_version_id="s",
        ),
    )
    cat = discover_catalogue(ORIGIN, responses=responses, grants=grants)
    plan = plan_assessment(cat, scope_version="1")
    foreign = {t.id for t in cat.templates if t.origin != ORIGIN}
    assert all(t.state == "blocked" for t in plan.tasks if t.template_id in foreign)
    assert {t.authority for t in cat.templates} == {"primary", "resource_only", "unapproved"}


def test_revision_never_drops_failed_or_missing_prior_tasks():
    first = plan_assessment(fixture_catalogue(), scope_version="1")
    second = plan_assessment(discover_catalogue(ORIGIN), scope_version="1", previous=first)
    assert second.denominator == first.denominator
    assert second.tasks == first.tasks
    assert second.previous_id == first.id
    assert second.revision == 2
    with pytest.raises(ValueError, match="cannot change"):
        plan_assessment(discover_catalogue(ORIGIN), scope_version="other", previous=first)


def test_dedup_keeps_method_role_content_type_and_structure():
    requests = tuple(
        {
            "url": ORIGIN + "/api",
            "method": method,
            "role_id": role,
            "content_type": ctype,
            "json": {"a": "x"} if ctype else None,
        }
        for method, role, ctype in [
            ("GET", "a", None),
            ("GET", "b", None),
            ("POST", "a", "application/json"),
            ("POST", "a", "text/plain"),
        ]
    )
    cat = discover_catalogue(ORIGIN, browser_requests=requests)
    assert len(cat.templates) == 4
    assert len({t.id for t in cat.templates}) == 4


def test_side_effect_get_is_not_automatically_admitted():
    cat = discover_catalogue(ORIGIN, responses=(response("/logout", "bye"),))
    assert all(t.state == "blocked" for t in plan_assessment(cat, scope_version="1").tasks)


def test_changing_json_fields_record_noise_without_changing_evidence():
    samples = [
        {"data": {"q": "same"}, "timestamp": 1},
        {"data": {"q": "same"}, "timestamp": 2, "new": 1},
    ]
    before = json.dumps(samples)
    assert changing_json_fields(samples) == ("/new", "/timestamp")
    assert json.dumps(samples) == before


def test_unknown_mutation_is_rejected():
    template = fixture_catalogue().templates[0]
    with pytest.raises(ValueError, match="unknown mutation"):
        render_request(template, {"query:invented:0": "probe"})


def test_secret_path_is_not_written_in_url():
    doc = {
        "openapi": "3.0.3",
        "paths": {
            "/reset/{token}": {
                "get": {
                    "parameters": [
                        {
                            "in": "path",
                            "name": "token",
                            "example": "private-reset",
                            "required": True,
                        }
                    ]
                }
            }
        },
    }
    cat = discover_catalogue(ORIGIN, openapi_documents=(doc,))
    assert "private-reset" not in cat.model_dump_json()
    assert all(t.state == "blocked" for t in plan_assessment(cat, scope_version="1").tasks)


def test_json_empty_containers_and_numeric_object_keys_round_trip():
    payload = {"empty": [], "object": {}, "numeric": {"0": "value"}, "nested": [{"blank": []}]}
    cat = discover_catalogue(
        ORIGIN,
        browser_requests=(
            {
                "url": ORIGIN + "/api",
                "method": "POST",
                "content_type": "application/json",
                "json": payload,
            },
        ),
    )
    assert render_request(cat.templates[0])["json"] == payload


def test_js_literal_post_is_inventory_and_remains_blocked():
    cat = discover_catalogue(
        ORIGIN,
        responses=(
            response(
                "/bundle.js",
                "axios.post('/change');fetch('/other', {method:'POST'});",
                "application/javascript",
            ),
        ),
    )
    posts = {t.id for t in cat.templates if t.method == "POST"}
    assert len(posts) == 2
    plan = plan_assessment(cat, scope_version="1")
    assert all(t.state == "blocked" for t in plan.tasks if t.template_id in posts)


def test_actual_crawler_discovers_inputs_from_loopback_fixture():
    # A real HTTP fixture tests the parser/crawler boundary. Broker admission remains
    # covered by the deployment integration suite, not claimed by this loopback test.
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    import httpx

    from scopelens.checks.crawl import CrawlConfig, Crawler

    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (
                b'<a href="/unlisted-cedar?query=seed">search</a><form method="POST" action="/unlisted-pine"><input name="text" value="hello"></form>'
                if self.path == "/"
                else b"ordinary response"
            )
            self.send_response(
                200 if self.path == "/" or self.path.startswith("/unlisted-cedar") else 404
            )
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(trust_env=False, timeout=2) as client:
            crawler = Crawler(
                CrawlConfig(
                    origin=origin,
                    scheme="http",
                    host="127.0.0.1",
                    port=server.server_port,
                    max_pages=30,
                    max_depth=3,
                    timeout=1,
                    max_body_bytes=10000,
                    user_agent="ScopeLens-fixture",
                ),
                client=client,
            )
            result = crawler.run()
        cat = discover_catalogue(origin, surface=result.surface, responses=tuple(result.responses))
        reached = next(t for t in cat.templates if t.path == "/unlisted-cedar")
        assert reached.baseline_observed
        assert any(t.method == "POST" and t.path == "/unlisted-pine" for t in cat.templates)
        plan = plan_assessment(cat, scope_version="fixture")
        assert any(
            t.control_id == "SL-C03-SQL-01" and t.template_id == reached.id and t.state == "ready"
            for t in plan.tasks
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
