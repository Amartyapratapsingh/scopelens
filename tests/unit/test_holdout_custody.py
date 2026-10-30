"""Protect evaluator-only labels and the exact-route benchmark ingress."""

import importlib.util
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def serving(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_compose_never_mounts_labels_or_exposes_upstream():
    compose = yaml.safe_load((ROOT / "labs/holdout.compose.yml").read_text())
    for name, service in compose["services"].items():
        assert service["profiles"] == ["holdout"]
        assert "@sha256:" in service["image"]
        for volume in service.get("volumes", []):
            assert "evaluation/" not in volume
            assert "oracle" not in volume
            assert "expectedresults" not in volume
        if not name.startswith("labs-holdout-"):
            assert "ports" not in service
            assert service["networks"] == ["private"]
        else:
            assert all(port.startswith("127.0.0.1:") for port in service["ports"])
    assert compose["networks"]["private"]["internal"] is True


def test_runtime_contracts_do_not_include_labels():
    for path in (ROOT / "labs/holdout").glob("routes-*.json"):
        for route, entry in json.loads(path.read_text()).items():
            assert route.startswith("/r/")
            assert set(entry) <= {
                "upstream_path",
                "parameter",
                "upstream_parameter",
                "baseline",
                "fixed_parameters",
            }
    pack = json.loads((ROOT / "checks_registry/tooling/conditional-pack.json").read_text())
    for name, entries in pack["lab_services"].items():
        if name.startswith("labs-holdout-"):
            for entry in entries:
                assert set(entry) <= {"kind", "path", "parameter", "baseline_value"}
                assert "BenchmarkTest" not in entry["parameter"]


def test_selection_has_no_duplicate_measurements_or_duplicate_benchmark_functions():
    cases = json.loads((ROOT / "evaluation/holdout/oracle.json").read_text())
    keys = [(c["source"], c["family"], c["upstream_path"]) for c in cases]
    assert len(keys) == len(set(keys))
    benchmark = [c for c in cases if c["source"] == "benchmarkjava"]
    signatures = [(c["family"], c["canonical_source_sha256"]) for c in benchmark]
    assert len(signatures) == len(set(signatures))


def test_gateway_blocks_answer_keys_redirects_and_preserves_sink(monkeypatch, tmp_path):
    calls = []

    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.path)
            if "redirect" in self.path:
                self.send_response(302)
                self.send_header("Location", "https://outside.invalid/marker")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'<title>False positive: answer</title><b id="sink">raw</b>')

        def log_message(self, *args):
            pass

    mapping = tmp_path / "routes.json"
    mapping.write_text(
        json.dumps(
            {
                "/r/opaque": {"upstream_path": "/handler", "parameter": "q"},
                "/r/jump": {"upstream_path": "/redirect", "parameter": "q"},
            }
        )
    )
    with serving(Upstream) as upstream:
        monkeypatch.setenv("UPSTREAM", upstream)
        monkeypatch.setenv("ROUTES_FILE", str(mapping))
        spec = importlib.util.spec_from_file_location(
            "holdout_gateway_test", ROOT / "labs/holdout/gateway.py"
        )
        gateway = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gateway)
        with (
            serving(gateway.Handler) as origin,
            httpx.Client(base_url=origin, trust_env=False, follow_redirects=False) as client,
        ):
            for path in [
                "/scanner/dast",
                "/oracle.json",
                "/r/opaque?q=a&path=/scanner/dast",
                "/r/opaque?q=a&q=b",
                "/r/opaque/../scanner/dast",
            ]:
                assert client.get(path).status_code == 404
            assert calls == []
            response = client.get("/r/opaque", params={"q": "<tag>"})
            assert "server" not in response.headers
            assert response.text == '<b id="sink">raw</b>'
            assert calls == ["/handler?q=%3Ctag%3E"]
            response = client.get("/r/jump", params={"q": "local"})
            assert response.status_code == 302
            assert response.headers["location"] == "https://outside.invalid/marker"
            assert len(calls) == 2


def test_gateway_redacts_native_identities_in_forms_errors_and_local_redirects(
    monkeypatch, tmp_path
):
    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/bad"):
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"/benchmark/xss/BenchmarkTest00001 source stack trace")
                return
            if self.path.startswith("/jump"):
                self.send_response(302)
                self.send_header("Location", "/benchmark/xss/BenchmarkTest00001")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("X-Powered-By", "native engine")
            self.send_header("Set-Cookie", "session=synthetic; Path=/benchmark")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b'<title>answer</title><form action="BenchmarkTest00001"><input name="BenchmarkTest00001"></form><mark>sink</mark>'
            )

        def log_message(self, *args):
            pass

    mapping = tmp_path / "routes.json"
    mapping.write_text(
        json.dumps(
            {
                "/r/opaque": {
                    "upstream_path": "/benchmark/xss/BenchmarkTest00001",
                    "parameter": "input",
                    "upstream_parameter": "BenchmarkTest00001",
                },
                "/r/error": {"upstream_path": "/bad", "parameter": "input"},
                "/r/redirect": {"upstream_path": "/jump", "parameter": "input"},
            }
        )
    )
    with serving(Upstream) as upstream:
        monkeypatch.setenv("UPSTREAM", upstream)
        monkeypatch.setenv("ROUTES_FILE", str(mapping))
        spec = importlib.util.spec_from_file_location(
            "holdout_gateway_redaction_test", ROOT / "labs/holdout/gateway.py"
        )
        gateway = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gateway)
        with (
            serving(gateway.Handler) as origin,
            httpx.Client(base_url=origin, trust_env=False, follow_redirects=False) as client,
        ):
            for path in [
                "/",
                "/r/opaque?input=hello",
                "/r/error?input=hello",
                "/r/redirect?input=hello",
                "/missing",
            ]:
                response = client.get(path)
                assert "BenchmarkTest" not in response.text
                assert "/benchmark/" not in response.text
                assert "server" not in response.headers
                assert "x-powered-by" not in response.headers
                assert "set-cookie" not in response.headers
                assert "BenchmarkTest" not in response.headers.get("location", "")
                assert "/benchmark/" not in response.headers.get("location", "")
            response = client.get("/r/opaque?input=hello")
            assert 'action="/r/opaque"' in response.text
            assert 'name="input"' in response.text
            assert "<mark>sink</mark>" in response.text
            assert client.get("/r/redirect").headers["location"] == "/r/opaque"
