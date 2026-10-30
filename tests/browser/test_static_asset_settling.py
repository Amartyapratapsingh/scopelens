"""A slow local image must finish before a browser state is credited as settled."""

import base64
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from playwright.sync_api import sync_playwright

from scopelens.browser.policy import BrowserAction
from scopelens.browser.worker import Controller
from scopelens.checks.crawl import CrawlConfig


def test_slow_image_finishes_without_a_stale_pending_gap(monkeypatch):
    image = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aD1sAAAAASUVORK5CYII="
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            slow = self.path == "/slow.png"
            if slow:
                time.sleep(2.3)
            body = (
                image
                if slow
                else b'<html><body><h1>Fixture</h1><img src="/slow.png"></body></html>'
            )
            self.send_response(200)
            self.send_header("Content-Type", "image/png" if slow else "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    config = CrawlConfig(
        origin=origin,
        scheme="http",
        host="127.0.0.1",
        port=server.server_port,
        max_pages=2,
        max_depth=1,
        timeout=10,
        max_body_bytes=65536,
        user_agent="local-settling-fixture",
    )
    monkeypatch.setenv("SCOPELENS_EGRESS_TOKEN", "synthetic-settling-token")
    controller = Controller(config, "http://127.0.0.1:9", "synthetic-owner-long")
    controller.command = lambda *args, **kwargs: {"allowed": True}
    controller.context_id = "synthetic-context"
    capture = controller.state

    def state(page):
        assert controller.pending_request_count == 0, "capture preceded the known image completion"
        return capture(page)

    controller.state = state
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.on("request", controller.request_started)
                page.on("requestfinished", controller.request_finished)
                page.on("requestfailed", controller.request_failed)
                result = controller.act(
                    page,
                    BrowserAction(kind="navigate", url=origin),
                    lambda: page.goto(origin, wait_until="commit"),
                )
                assert result and controller.states
                assert any(row["url"].endswith("/slow.png") for row in controller.responses)
                assert not any(
                    gap["reason"] == "background_requests_pending" for gap in controller.gaps
                )
            finally:
                browser.close()
    finally:
        controller.http.close()
        server.shutdown()
        server.server_close()
