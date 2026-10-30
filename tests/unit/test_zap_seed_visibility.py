"""Only an explicit pre-scan history refusal can retry, within the task deadline."""

import json
import time
from types import SimpleNamespace

import httpx
import pytest

from scopelens.adapters import zap_active_worker as worker


@pytest.mark.parametrize(
    "error",
    [
        worker.NativeApiRefusal("ascan/action/scan", 400),
        worker.NativeApiRefusal("ascan/action/scan", 500, "url_not_found"),
        httpx.ReadTimeout("ambiguous completion"),
        ValueError("other refusal"),
    ],
)
def test_ambiguous_or_other_scan_failure_never_retries(error):
    calls = []

    def api(*args, **params):
        calls.append((args, params))
        raise error

    with pytest.raises(type(error)):
        worker.start_native_scan(api, time.monotonic() + 60, url="http://fixture/xss?q=seed")
    assert len(calls) == 1


@pytest.mark.parametrize("budget", [0.07, 60])
def test_unregistered_seed_stops_at_visibility_or_task_deadline(monkeypatch, budget):
    clock = [10.0]
    calls = []
    monkeypatch.setattr(
        worker,
        "time",
        SimpleNamespace(
            monotonic=lambda: clock[0],
            sleep=lambda delay: clock.__setitem__(0, clock[0] + delay),
        ),
    )

    def api(*args, **params):
        calls.append((args, params))
        raise worker.NativeApiRefusal("ascan/action/scan", 400, "url_not_found")

    with pytest.raises(worker.NativeApiRefusal):
        worker.start_native_scan(api, 10 + budget, url="http://fixture/xss?q=seed")
    assert clock[0] == min(10 + budget, 12)
    assert len(calls) <= 42
    assert all(args == ("ascan", "action", "scan") for args, params in calls)
    assert all(params == {"url": "http://fixture/xss?q=seed"} for args, params in calls)


def test_safe_refusal_code_does_not_retain_error_body(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "IPC", tmp_path)
    private = "private-api-key-or-target-url"
    with (
        httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    400, json={"code": "url_not_found", "message": private}
                )
            )
        ) as client,
        pytest.raises(worker.NativeApiRefusal) as captured,
    ):
        worker.local_api(client, time.monotonic() + 60, "ascan", "action", "scan")
    assert captured.value.code == "url_not_found"
    assert private not in str(captured.value)
    diagnostic = json.loads((tmp_path / "local-api.json").read_text())
    assert diagnostic["http_status"] == 400
    assert private not in json.dumps(diagnostic)
