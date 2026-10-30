"""Concurrent local parser assets must terminate and release broker admissions."""

import concurrent.futures
import http.client
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from proxy_bypass import PolicyStub, Proxy


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(1)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    policy = PolicyStub()
    with tempfile.TemporaryDirectory() as directory:
        proxy = Proxy(policy.url, Path(directory))
        try:
            assert proxy.wait_ready()

            def fetch(index):
                connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=15)
                started = time.monotonic()
                try:
                    connection.request(
                        "GET",
                        f"http://127.0.0.1:{server.server_port}/asset-{index}",
                        headers={"x-scopelens-egress": "local-test"},
                    )
                    response = connection.getresponse()
                    body = response.read()
                    return response.status, body, round(time.monotonic() - started, 2)
                except (OSError, http.client.HTTPException) as exc:
                    return type(exc).__name__, str(exc), round(time.monotonic() - started, 2)
                finally:
                    connection.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
                results = list(pool.map(fetch, range(24)))
            print(results, flush=True)
            assert not any(row[0] == "TimeoutError" for row in results), (
                "canceled queued request left HTTP hook unresolved"
            )
            assert fetch("after")[0] == 200, "queue leaked its admission slots"
        finally:
            proxy.stop()
            policy.close()
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
