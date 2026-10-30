import httpx
import pytest
from tests.m2_helpers import response
from tests.unit.test_m2_crawler import crawler


@pytest.mark.parametrize(
    "body,name,version",
    [
        ("/*! jQuery v3.4.1 | MIT */", "jquery", "3.4.1"),
        ("/*! Bootstrap v5.3.3 */", "bootstrap", "5.3.3"),
        ("/*! Vue.js v2.6.14 */", "vue.js", "2.6.14"),
        ('<div ng-version="17.2.1"></div>', "angular", "17.2.1"),
        ("We recommend jquery. Current site release 1.2.3", "jquery", None),
    ],
)
def test_version_requires_named_banner_or_runtime_attribute(body, name, version):
    c = crawler(lambda _: httpx.Response(404))
    c._fingerprint_from_body(response(body=body))
    assert next(t for t in c._tech if t.name == name).version == version


def test_not_found_routes_and_html_fallback_do_not_prove_api_technology():
    c = crawler(lambda _: httpx.Response(404))
    for route in ["/api", "/graphql", "/openapi.json", "/swagger.json"]:
        c._extract(response(route, "<html>Page not found</html>", 404))
        c._extract(response(route, "<html>SPA fallback</html>", 200))
    assert not c._classification.has_graphql
    assert not c._classification.has_openapi
    assert not c._classification.has_rest_api


def test_real_json_openapi_document_is_inventoried():
    c = crawler(lambda _: httpx.Response(404))
    c._extract(
        response("/openapi.json", '{"openapi":"3.0.0","paths":{}}', content_type="application/json")
    )
    assert c._classification.has_openapi
    assert c._classification.has_rest_api
