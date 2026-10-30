"""Upload response completion must precede page close and cleanup still runs on timeout."""

import time
from contextlib import suppress
from http.server import ThreadingHTTPServer
from threading import Thread

import pytest
from labs.expansion_browser.app import handler
from playwright.sync_api import Page
from test_browser_workflows import workflow_app as workflow_app
from test_expansion_browser_worker import setup

from scopelens.expansion.browser_worker import collect_browser_assessments


@pytest.mark.parametrize("timeout", [False, True])
def test_upload_page_close_waits_for_complete_response_or_reports_timeout(
    workflow_app, tmp_path, monkeypatch, timeout
):
    records = {"bad": "", "fixed": ""}
    app = handler(records)

    class DelayedBody(app):
        def end_headers(self):
            super().end_headers()
            if self.path.endswith("/upload"):
                time.sleep(0.25)

        def do_POST(self):
            with suppress(BrokenPipeError, ConnectionResetError):
                super().do_POST()

    server = ThreadingHTTPServer(("127.0.0.1", 0), DelayedBody)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    local_app = (origin, origin + "/foreign", workflow_app[2], records)
    config, catalogue, plan, crawl, browser, control = setup(
        local_app, tmp_path, "bad", "upload_serving"
    )
    original_wait = Page.expect_request_finished
    original_close = Page.close
    completed_pages, closed_pages = set(), []

    def completion_wait(page, predicate=None, *, timeout=None):
        page.on(
            "requestfinished",
            lambda request: completed_pages.add(page) if request.url.endswith("/upload") else None,
        )
        return original_wait(page, predicate, timeout=50 if force_timeout else timeout)

    def close(page, *args, **kwargs):
        if not force_timeout:
            assert page in completed_pages, "upload page closed before response body completion"
        closed_pages.append(page)
        return original_close(page, *args, **kwargs)

    force_timeout = timeout
    monkeypatch.setattr(Page, "expect_request_finished", completion_wait)
    monkeypatch.setattr(Page, "close", close)
    artifacts = []
    try:
        summary = collect_browser_assessments(
            config,
            catalogue,
            plan,
            browser,
            control,
            crawl,
            lambda kind, data: artifacts.append({"kind": kind, "data": data}),
            owner="completion-test",
            token="fixture-token",
            cancelled=lambda: False,
        )
        result = next(a["data"] for a in artifacts if a["kind"] == "workflow_capture")
        assert result["state"] == ("error" if timeout else "confirmed")
        assert result["cleanup_state"] == "clean"
        assert records["bad"] == ""
        assert bool(summary["complete"]) is not timeout
        assert len(closed_pages) == (1 if timeout else 2)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
