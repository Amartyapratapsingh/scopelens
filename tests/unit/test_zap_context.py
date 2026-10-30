"""Exercise worker setup against the pinned engine's query-free context contract."""

import re
import subprocess
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
import pytest

from scopelens.adapters import zap_active_worker as worker
from scopelens.adapters.zap_active import ActiveRulePin, ActiveRuleTask


@pytest.mark.parametrize(
    "url",
    [
        "http://172.28.0.11/active/xss?q=scopelens",
        "https://owned.example/active/xss?q=scopelens",
        "https://owned.example:8443/active/xss?q=scopelens&unchanged=one",
    ],
)
@pytest.mark.parametrize("history_delay", [0, 2])
def test_worker_context_accepts_query_free_engine_url_and_no_neighbor(
    url, history_delay, monkeypatch, tmp_path
):
    pin = ActiveRulePin(
        rule_id="40012",
        control_id="SL-C03-XSS-01",
        engine_version="2.17.0",
        engine_sha256="2" * 64,
        addon_filename="ascanrules-release-78.zap",
        addon_sha256="3" * 64,
        rule_config_sha256=worker.CONFIG_SHA256,
        allowed_values=("scopelens", "0W45pz4p"),
        max_requests=8,
        deadline_seconds=60,
    )
    task = ActiveRuleTask(
        scan_id="scan",
        task_id="task",
        input_id="input",
        rule_id=pin.rule_id,
        url=url,
        input_name="q",
        rule_config_sha256=worker.CONFIG_SHA256,
        max_requests=8,
        deadline_seconds=60,
    )
    monkeypatch.setattr(worker, "verify_binaries", lambda selected: None)
    monkeypatch.setattr(worker, "IPC", tmp_path)
    monkeypatch.setattr(
        worker,
        "HTTPServer",
        lambda *args: SimpleNamespace(serve_forever=lambda: None, shutdown=lambda: None),
    )
    monkeypatch.setattr(
        worker,
        "threading",
        SimpleNamespace(Thread=lambda **kwargs: SimpleNamespace(start=lambda: None)),
    )
    process = SimpleNamespace(terminate=lambda: None, wait=lambda **kwargs: 0)
    monkeypatch.setattr(
        worker,
        "subprocess",
        SimpleNamespace(
            Popen=lambda *a, **kw: process,
            DEVNULL=subprocess.DEVNULL,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    configured = {}
    seeded = []
    rejected = []
    original_api = worker.local_api

    def api(client, deadline, component, operation, name, **params):
        if name == "version":
            return {"version": pin.engine_version}
        if name == "newContext":
            return {"contextId": "1"}
        if name == "includeInContext":
            configured["regex"] = params["regex"]
        if name == "accessUrl":
            seeded.append(params["url"])
        if component == "ascan" and name == "scan":
            # ZAP 2.17 Context.isInContext removes the query before full matching.
            actual = urlsplit(params["url"])._replace(query="", fragment="").geturl()
            if not re.fullmatch(configured["regex"], actual):
                raise ValueError("URL_NOT_IN_CONTEXT")
            assert seeded == [worker.native_url(task)]
            assert params["url"] == worker.native_url(task)
            for outside in (
                actual + "/neighbor",
                actual.replace("/active/xss", "/active/other"),
                actual.replace(urlsplit(actual).hostname, "other.example"),
            ):
                assert not re.fullmatch(configured["regex"], outside)
            if len(rejected) < history_delay:
                rejected.append(params)
                with httpx.Client(
                    transport=httpx.MockTransport(
                        lambda request: httpx.Response(
                            400, json={"code": "url_not_found", "message": "URL Not Found"}
                        )
                    )
                ) as real_client:
                    return original_api(real_client, deadline, component, operation, name, **params)
            return {"scan": "1"}
        if name == "status":
            return {"status": "100"}
        if name == "alerts":
            alert = {
                "pluginId": "40012",
                "risk": "High",
                "url": worker.native_url(task).replace("q=scopelens", "q=0W45pz4p"),
            }
            # Core API baseurl is a prefix filter. A changed query no longer
            # starts with the original seed value, though it is still task-bound.
            return {"alerts": [alert] if alert["url"].startswith(params["baseurl"]) else []}
        return {}

    monkeypatch.setattr(worker, "local_api", api)
    assert worker.run(task, pin) == {
        "site": [
            {
                "alerts": [
                    {
                        "pluginid": "40012",
                        "riskcode": "High",
                        "instances": [{"uri": url.replace("q=scopelens", "q=0W45pz4p")}],
                    }
                ]
            }
        ]
    }
    assert len(rejected) == history_delay
