import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from labs.expansion_tools.app import create_app

from scopelens.checks.packs.exposure import (
    classify,
    collect_exposure_pack,
    evaluate_exposure_pack,
    identify_components,
)

ORIGIN = "http://testserver"
TECH = ("php", "wordpress", "apache", "spring")


def test_vulnerable_and_fixed_real_application_contracts():
    for vulnerable in (True, False):
        with TestClient(create_app(vulnerable)) as client:
            result = collect_exposure_pack(
                client, ORIGIN, technologies=TECH, discovered_urls=["/app.js.map"]
            )
        outcomes = evaluate_exposure_pack(result, "trusted-artifact")
        confirmed = {o.check_id for o in outcomes if o.proof and o.proof.is_confirmed}
        assert confirmed == (
            {"SL-C05-CONFIG-02", "SL-C05-DEBUG-02", "SL-C05-MANAGEMENT-01"} if vulnerable else set()
        )
        assert result.requests <= 24
        assert "synthetic-only" not in result.model_dump_json()
        if vulnerable:
            source = next(o for o in outcomes if o.check_id == "SL-C05-SOURCEMAP-01")
            assert source.proof.status.value == "potential"
        else:
            assert all(o.status.value == "pass" for o in outcomes)


def test_no_trusted_artifact_cannot_confirm_or_pass():
    with TestClient(create_app()) as client:
        result = collect_exposure_pack(client, ORIGIN, technologies=TECH)
    assert all(not o.is_conclusive for o in evaluate_exposure_pack(result, None))


def test_soft404_and_matching_signature_cannot_confirm():
    with TestClient(create_app(fallback=True)) as client:
        result = collect_exposure_pack(client, ORIGIN)
    assert not any(
        o.proof and o.proof.is_confirmed for o in evaluate_exposure_pack(result, "trusted")
    )


@pytest.mark.parametrize(
    "family,body,content_type",
    [
        ("config", "<html>DB_PASSWORD=whatever</html>", "text/html"),
        ("debug", "<html><title>phpinfo()</title>Login required</html>", "text/html"),
        ("management", '{"contexts": {"password": "********"}}', "application/json"),
        ("private", "-----BEGIN PUBLIC KEY-----xyz-----END PUBLIC KEY-----", "text/plain"),
        (
            "source_map",
            '{"version":3,"sources":["public"],"sourcesContent":["public"]}',
            "application/json",
        ),
    ],
)
def test_lookalikes_are_not_exposures(family, body, content_type):
    assert classify(family, body, content_type)[0] == "clear"


def test_key_requires_parse_and_never_authenticates():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    assert classify("private", pem, "text/plain")[0] == "exposed"
    assert (
        classify(
            "private", "-----BEGIN PRIVATE KEY-----xyz-----END PRIVATE KEY-----", "text/plain"
        )[0]
        == "candidate"
    )


def test_capped_budget_cancel_cross_origin_and_approval():
    with TestClient(create_app()) as client:
        result = collect_exposure_pack(
            client, ORIGIN, max_requests=1, discovered_urls=["https://foreign.invalid/app.js.map"]
        )
        assert result.requests == 1
        assert not any("foreign" in o.url for o in result.observations)
        assert result.gaps
        result = collect_exposure_pack(client, ORIGIN, cancelled=lambda: True)
        assert result.requests == 0
        assert result.gaps
        result = collect_exposure_pack(client, ORIGIN, approved_urls=[ORIGIN + "/.env"])
        assert {o.url for o in result.observations} == {ORIGIN + "/.env"}


def test_truncated_or_redirected_response_is_not_clean():
    def serve(request):
        if "scopelens-absent" in request.url.path:
            return httpx.Response(404, text="missing")
        if request.url.path == "/.env":
            return httpx.Response(200, text="DB_PASSWORD=hello-world\nAPP_NAME=lab\n" * 1000)
        return httpx.Response(302, headers={"Location": "https://foreign.invalid/"})

    with httpx.Client(transport=httpx.MockTransport(serve)) as client:
        result = collect_exposure_pack(client, ORIGIN, max_body_bytes=128)
    assert all(o.state == "inconclusive" for o in result.observations)
    assert result.observations[0].bytes_read == 128


def test_multiple_component_signals_corroborate_identity_only():
    rows = identify_components(
        "https://example.test/jquery/3.4.1/jquery.js", {}, "/*! jQuery v3.4.1 */"
    )
    assert len(rows) == 2
    assert all(row.identity_corroborated for row in rows)


@contextmanager
def actual_fixture():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = (
                b"APP_NAME=fixture\nDB_PASSWORD=synthetic-not-live\n"
                if self.path == "/.env"
                else b"not found"
            )
            self.send_response(200 if self.path == "/.env" else 404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_real_loopback_http_collection():
    with actual_fixture() as origin, httpx.Client(timeout=2, trust_env=False) as client:
        result = collect_exposure_pack(client, origin)
    outcome = evaluate_exposure_pack(result, "trusted-loopback-test")[0]
    assert outcome.proof.is_confirmed
    assert "synthetic-not-live" not in json.dumps(result.model_dump())


def test_publishable_api_identifier_is_not_private_configuration():
    assert (
        classify("config", '{"api_key":"pk_live_public_client_identifier"}', "application/json")[0]
        == "clear"
    )


def test_narrow_scope_filters_root_probes_before_target_io():
    requests = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: requests.append(request.url.path) or httpx.Response(404)
        )
    ) as client:
        result = collect_exposure_pack(
            client, ORIGIN, admit_url=lambda url: url.startswith(ORIGIN + "/app/")
        )
    assert requests == []
    assert result.requests == 0
    assert result.selected_families == []


def test_narrow_scope_keeps_discovered_map_and_negative_control_inside_application():
    requests = []
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: requests.append(request.url.path) or httpx.Response(404)
        )
    ) as client:
        result = collect_exposure_pack(
            client,
            ORIGIN,
            discovered_urls=["/app/front.js.map", "/elsewhere/front.js.map"],
            admit_url=lambda url: url.startswith(ORIGIN + "/app/"),
        )
    assert result.requests == 2
    assert result.selected_families == ["source_map"]
    assert all(path.startswith("/app/") for path in requests)
    assert requests[-1] == "/app/front.js.map"
