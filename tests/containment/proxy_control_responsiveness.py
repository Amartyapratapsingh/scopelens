"""Slow admission must not starve browser control on the real proxy event loop."""

import concurrent.futures
import http.client
import json
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from proxy_bypass import Proxy


def main():
    admission_started = threading.Event()

    class Policy(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            if self.path.endswith("/authorize"):
                assert payload["host"] == "127.0.0.1"
                admission_started.set()
                time.sleep(2)
            body = json.dumps(
                {
                    "allowed": True,
                    "addresses": ["127.0.0.1"],
                    "limits": {"max_in_flight": "6"},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    policy = ThreadingHTTPServer(("127.0.0.1", 0), Policy)
    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    for server in (policy, target):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            proxy = Proxy(f"http://127.0.0.1:{policy.server_port}", Path(directory))
            try:
                assert proxy.wait_ready()

                def asset(index):
                    connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=30)
                    try:
                        connection.request(
                            "GET",
                            f"http://127.0.0.1:{target.server_port}/asset-{index}",
                            headers={"x-scopelens-egress": "synthetic-test"},
                        )
                        response = connection.getresponse()
                        assert response.read() == b"ok"
                        return response.status
                    except (OSError, http.client.HTTPException) as error:
                        return type(error).__name__
                    finally:
                        connection.close()

                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                    pending = [pool.submit(asset, index) for index in range(6)]
                    assert admission_started.wait(timeout=10)
                    # The asset burst has already arrived while one policy call is slow.
                    time.sleep(0.2)
                    connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
                    started = time.monotonic()
                    control = {}
                    try:
                        connection.request(
                            "POST",
                            "http://scopelens-broker.invalid/browser",
                            body=json.dumps({"owner": "synthetic-owner-long", "operation": "open"}),
                            headers={
                                "x-scopelens-egress": "synthetic-test",
                                "Content-Type": "application/json",
                            },
                        )
                        response = connection.getresponse()
                        control = {
                            "status": response.status,
                            "allowed": json.loads(response.read())["allowed"],
                        }
                    except TimeoutError:
                        control = {"error": "ReadTimeout"}
                    finally:
                        connection.close()
                    control["seconds"] = round(time.monotonic() - started, 3)
                    print(json.dumps({"browser_control": control}), flush=True)
                    assets = [job.result(timeout=30) for job in pending]
                    print(json.dumps({"asset_results": assets}), flush=True)
                    assert control.get("allowed") and control["seconds"] < 2, (
                        "slow policy admissions starved the browser control channel"
                    )
                    assert assets == [200] * 6
            finally:
                proxy.stop()
    finally:
        for server in (policy, target):
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
