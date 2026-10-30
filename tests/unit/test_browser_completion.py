import json

import pytest

from scopelens.browser.integration import run_browser
from scopelens.config import Settings
from scopelens.execution.supervisor import (
    ARTIFACT_MARKER,
    RESULT_MARKER,
    RecordingSupervisor,
    SupervisorError,
    WorkerResult,
    WorkerSpec,
)


@pytest.mark.parametrize("startup_error", [False, True])
def test_browser_failure_preserves_crawl_and_reports_missing_completion(startup_error):
    crawl = WorkerResult(
        "run",
        0,
        ARTIFACT_MARKER
        + json.dumps({"kind": "surface", "data": {}})
        + "\n"
        + RESULT_MARKER
        + '{"ok":true,"body_bytes":12}',
        "",
        1,
    )
    browser = WorkerResult(
        "browser",
        None,
        ARTIFACT_MARKER + '{"kind":"browser_state","data":{}}',
        "",
        300,
        timed_out=True,
    )
    supervisor = RecordingSupervisor(browser)
    if startup_error:

        def fail(*args, **kwargs):
            raise SupervisorError("unavailable")

        supervisor.run = fail
    result = run_browser(
        Settings(_env_file=None),
        supervisor,
        WorkerSpec("image", [], {}, "worker"),
        crawl,
        run_id="run",
    )
    assert any(a["kind"] == "surface" for a in result.artifacts())
    summary = next(a["data"] for a in result.artifacts() if a["kind"] == "browser_summary")
    assert summary["status"] == "incomplete"
    assert summary["states"] == (0 if startup_error else 1)
    assert summary["gaps"][0]["reason"] == (
        "browser_interrupted" if startup_error else "browser_timeout"
    )
    assert not result.succeeded


def test_browser_waits_for_parsed_document_before_capturing_with_busy_network():
    from scopelens.browser.policy import BrowserAction
    from scopelens.browser.worker import Controller, PlaywrightTimeout

    calls = []

    class Page:
        url = "https://fixture.invalid/"

        def wait_for_load_state(self, state, *, timeout):
            calls.append((state, timeout))
            if state == "networkidle":
                raise PlaywrightTimeout("background polling")

    controller = Controller.__new__(Controller)
    controller.sequence = 0
    controller.gaps = []
    controller.command = lambda operation, **fields: calls.append(operation)

    def capture(page):
        assert calls.index(("domcontentloaded", 30000)) < calls.index(("networkidle", 1500))
        calls.append("capture")
        return "captured-state"

    controller.state = capture
    result = controller.act(
        Page(), BrowserAction(kind="navigate", url=Page.url), lambda: calls.append("navigate")
    )
    assert result == "captured-state"
    assert calls[-1] == "complete"
    assert controller.gaps[0]["reason"] == "background_requests_pending"


def test_browser_navigation_failure_preserves_specific_error_and_crawl_result():
    crawl = WorkerResult("run", 0, RESULT_MARKER + '{"ok":true,"body_bytes":12}', "", 1)
    browser = WorkerResult(
        "browser",
        1,
        ARTIFACT_MARKER
        + json.dumps(
            {
                "kind": "browser_summary",
                "data": {
                    "states": 0,
                    "actions": 1,
                    "gaps": [{"reason": "Error", "detail": "net::ERR_TUNNEL_CONNECTION_FAILED"}],
                },
            }
        )
        + "\n"
        + RESULT_MARKER
        + '{"ok":false}',
        "",
        1,
    )
    result = run_browser(
        Settings(_env_file=None),
        RecordingSupervisor(browser),
        WorkerSpec("image", [], {}, "worker"),
        crawl,
        run_id="run",
    )
    declaration = result.declared_result()
    assert declaration["crawl_ok"] is True
    assert declaration["browser_ok"] is False
    assert declaration["error"] == "net::ERR_TUNNEL_CONNECTION_FAILED"
    assert not result.succeeded
