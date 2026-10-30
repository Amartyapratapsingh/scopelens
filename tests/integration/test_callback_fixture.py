"""Synthetic fixture requests on loopback; collector calls are injected and counted."""

from http.server import ThreadingHTTPServer
from threading import Thread

import httpx
import pytest
from labs.callbacks.app import COLLECTOR_ORIGIN, allowed_callback, fetch_collector, handler

from scopelens.callbacks.probes import CallbackProbeRecipe
from scopelens.callbacks.runtime import _expected_request

CANARY = COLLECTOR_ORIGIN + "/callback/" + "a" * 32


@pytest.fixture
def site():
    calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(lambda url: calls.append(url)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("family", ["ssrf", "xxe"])
@pytest.mark.parametrize("variant", ["bad", "fixed"])
def test_exact_existing_reviewed_probes_and_inert_negative(site, family, variant):
    origin, calls = site
    recipe = CallbackProbeRecipe(
        family=family,
        target_url=origin + f"/{variant}/{family}" + ("?url=baseline" if family == "ssrf" else ""),
        method="GET" if family == "ssrf" else "POST",
        parameter="url" if family == "ssrf" else None,
        callback_origin=COLLECTOR_ORIGIN,
        expected_target_peers={"192.0.2.10"},
        scanner_peers={"192.0.2.20"},
        approved_staging=True,
        unexpected_external_fetch=True,
    )
    with httpx.Client() as client:
        for purpose in ("negative", "positive", "positive"):
            url, body = _expected_request(recipe, CANARY, purpose)
            assert client.request(recipe.method, url, content=body).status_code == 200
    assert calls == ([CANARY, CANARY] if variant == "bad" else [])


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8091/callback/" + "a" * 32,
        "http://172.28.0.17:8092/callback/" + "a" * 32,
        COLLECTOR_ORIGIN + "/elsewhere",
        CANARY + "?redirect=https://other.test",
        "https://172.28.0.17:8091/callback/" + "a" * 32,
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_alternative_destinations_never_call_network(site, url, monkeypatch):
    origin, calls = site

    def forbidden(*args, **kwargs):
        raise AssertionError("network call attempted")

    monkeypatch.setattr("labs.callbacks.app.http.client.HTTPConnection", forbidden)
    assert allowed_callback(url) is None
    assert not fetch_collector(url)
    assert httpx.get(origin + "/bad/ssrf", params={"url": url}).status_code == 200
    assert calls == []


def test_collector_redirect_is_not_followed(monkeypatch):
    requests = []

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("172.28.0.17", 8091)

        def request(self, method, path, headers):
            requests.append((method, path))

        def getresponse(self):
            return self

        status = 302

        def read(self, cap):
            return b""

        def close(self):
            pass

    monkeypatch.setattr("labs.callbacks.app.http.client.HTTPConnection", Connection)
    assert not fetch_collector(CANARY)
    assert requests == [("GET", "/callback/" + "a" * 32)]
