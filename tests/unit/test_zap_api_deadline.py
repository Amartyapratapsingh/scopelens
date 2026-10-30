"""Slow local operations share the absolute task deadline and retain safe telemetry."""

import json
import threading
import time
from contextlib import nullcontext, suppress
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import httpx
import pytest

from scopelens.adapters import zap_active_worker as worker
from scopelens.execution import zap_active as launcher


@pytest.mark.parametrize("body_delay", [False, True])
@pytest.mark.parametrize(("delay", "budget", "expired"), [(1.15, 3, False), (0.15, 0.05, True)])
def test_synchronous_access_url_uses_remaining_deadline(
    tmp_path, monkeypatch, delay, budget, expired, body_delay
):
    monkeypatch.setattr(worker, "IPC", tmp_path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if not body_delay:
                time.sleep(delay)
            self.send_response(200)
            self.end_headers()
            if body_delay:
                time.sleep(delay)
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(b'{"ok":true}')

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        with httpx.Client(trust_env=False) as real_client:

            def stream(method, url, **kwargs):
                assert url.endswith("/core/action/accessUrl/")
                assert 0 < kwargs["timeout"] <= budget
                return real_client.stream(
                    method, f"http://127.0.0.1:{server.server_port}/", **kwargs
                )

            client = SimpleNamespace(stream=stream)
            deadline = time.monotonic() + budget
            if expired:
                with pytest.raises(TimeoutError, match="native task deadline"):
                    worker.local_api(
                        client, deadline, "core", "action", "accessUrl", apikey="private"
                    )
            else:
                assert worker.local_api(
                    client, deadline, "core", "action", "accessUrl", apikey="private"
                ) == {"ok": True}
    finally:
        thread.join(timeout=5)
        server.server_close()
    diagnostic = json.loads((tmp_path / "local-api.json").read_text())
    assert diagnostic["phase"] == "local_api"
    assert diagnostic["operation"] == "core/action/accessUrl"
    assert diagnostic["deadline_expired"] is expired
    assert diagnostic["http_status"] == (None if expired and not body_delay else 200)
    assert diagnostic["exception_class"] == ("ReadTimeout" if expired else None)
    assert "private" not in json.dumps(diagnostic) and "apikey" not in json.dumps(diagnostic)
    assert not (tmp_path / "local-api.tmp").exists()


def test_response_arriving_past_deadline_retains_observed_status(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "IPC", tmp_path)
    clock = [10.0]
    monkeypatch.setattr(worker.time, "monotonic", lambda: clock[0])

    def stream(*args, **kwargs):
        assert kwargs["timeout"] == 2
        clock[0] = 12.1
        return nullcontext(httpx.Response(200, json={"ok": True}))

    with pytest.raises(TimeoutError, match="native task deadline"):
        worker.local_api(SimpleNamespace(stream=stream), 12, "core", "action", "accessUrl")
    assert json.loads((tmp_path / "local-api.json").read_text()) == {
        "phase": "local_api",
        "operation": "core/action/accessUrl",
        "http_status": 200,
        "exception_class": "TimeoutError",
        "deadline_expired": True,
    }


def test_expired_deadline_makes_no_api_request(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "IPC", tmp_path)
    client = SimpleNamespace(stream=lambda *a, **k: pytest.fail("expired operation made a request"))
    with pytest.raises(TimeoutError):
        worker.local_api(client, time.monotonic() - 1, "core", "view", "version")
    diagnostic = json.loads((tmp_path / "local-api.json").read_text())
    assert diagnostic["deadline_expired"] and diagnostic["http_status"] is None


@pytest.mark.parametrize(
    "fault", [None, "status", "extra", "phase", "operation", "size", "channel"]
)
def test_api_telemetry_reader_is_bounded_and_validated(fault):
    diagnostic = {
        "phase": "local_api",
        "operation": "core/action/accessUrl",
        "http_status": None,
        "exception_class": "ReadTimeout",
        "deadline_expired": True,
    }
    if fault == "status":
        diagnostic["http_status"] = True
    if fault == "extra":
        diagnostic["apikey"] = "secret"
    if fault == "phase":
        diagnostic["phase"] = "broker_allowed"
    if fault == "operation":
        diagnostic["operation"] = "https://secret.example/key"
    raw = json.dumps(diagnostic).encode() if fault != "size" else b"x" * 1025

    def exec_run(command):
        assert command == ["python", "-I", "-c", launcher.READ_FILE, "local-api.json"]
        return (2 if fault == "channel" else 0), raw

    container = SimpleNamespace(exec_run=exec_run)
    if fault:
        with pytest.raises(ValueError):
            launcher._read_worker_api(container)
    else:
        assert launcher._read_worker_api(container) == diagnostic
