"""A completed body is retained before metadata calls can yield to navigation."""

import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from playwright.sync_api import sync_playwright

from scopelens.browser.worker import Controller
from scopelens.checks.crawl import CrawlConfig


def test_body_survives_navigation_during_header_collection(monkeypatch):
    image = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aD1sAAAAASUVORK5CYII="
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (
                image
                if self.path == "/asset.png"
                else b'<html><body><img src="/asset.png"></body></html>'
            )
            self.send_response(200)
            self.send_header(
                "Content-Type", "image/png" if self.path == "/asset.png" else "text/html"
            )
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
        timeout=5,
        max_body_bytes=65536,
        user_agent="local-body-retention-fixture",
    )
    monkeypatch.setenv("SCOPELENS_EGRESS_TOKEN", "synthetic-capture-token")
    controller = Controller(config, "http://127.0.0.1:9", "synthetic-owner-long")
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                with page.expect_response(origin + "/asset.png") as seen:
                    page.goto(origin, wait_until="load")
                response = seen.value
                original = response.headers_array

                def headers():
                    values = original()
                    page.goto(origin + "/next", wait_until="load")
                    return values

                response.headers_array = headers
                assert controller.capture_response(response) is True, controller.gaps
                assert not controller.gaps
                assert controller.responses[0]["body_bytes"] == len(image)
            finally:
                browser.close()
    finally:
        controller.http.close()
        server.shutdown()
        server.server_close()
