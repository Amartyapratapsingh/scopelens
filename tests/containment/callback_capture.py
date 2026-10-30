"""Real proxy request commitments; isolated loopback canaries, no target scans.

Run inside the proxy image with the current addon mounted at /addons/scope_enforcer.py.
"""

import hashlib
import http.client
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from proxy_bypass import Proxy


def main():
    captures = []
    requests = []
    mode = ["allow"]

    class Target(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length", 0)))
            requests.append((self.path, body, dict(self.headers)))
            self.send_response(201)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    class Policy(BaseHTTPRequestHandler):
        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers["content-length"])))
            result = {"allowed": True}
            if self.path.endswith("callback-dispatch"):
                captures.append(data)
                if mode[0] == "deny-" + data["operation"]:
                    result = {"allowed": False}
                elif data["operation"] == "begin":
                    result["dispatch_id"] = "trusted-dispatch"
            elif self.path.endswith("authorize"):
                result.update(addresses=["127.0.0.1"], limits={"callback_capture": "1"})
            body = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    policy = ThreadingHTTPServer(("127.0.0.1", 0), Policy)
    for server in (target, policy):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            proxy = Proxy(
                f"http://127.0.0.1:{policy.server_port}/internal/broker/authorize", Path(directory)
            )
            try:
                assert proxy.wait_ready(), proxy.log()
                url = f"http://fixture.invalid:{target.server_port}/capture?q=%2F"
                body = b"synthetic-callback-request"

                def send(destination=url):
                    client = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
                    try:
                        client.request(
                            "POST",
                            destination,
                            body,
                            {"x-scopelens-egress": "test-egress", "Content-Type": "text/plain"},
                        )
                        response = client.getresponse()
                        response.read()
                        return response.status
                    except http.client.RemoteDisconnected:
                        return None
                    finally:
                        client.close()

                assert send() == 201
                assert len(requests) == 1
                assert captures == [
                    {
                        "operation": "begin",
                        "egress_token": "test-egress",
                        "method": "POST",
                        "url": url,
                        "body_sha256": hashlib.sha256(body).hexdigest(),
                    },
                    {
                        "operation": "complete",
                        "egress_token": "test-egress",
                        "dispatch_id": "trusted-dispatch",
                        "response_status": 201,
                    },
                ], captures
                assert requests[0][0] == "/capture?q=%2F" and requests[0][1] == body
                assert not any(k.lower() == "x-scopelens-egress" for k in requests[0][2])
                print(
                    "PASS exact original URL/body committed, actual status captured, token stripped"
                )
                captures.clear()
                mode[0] = "deny-begin"
                assert send() == 403
                assert len(requests) == 1 and len(captures) == 1
                print("PASS unavailable capture prevents upstream request")
                captures.clear()
                mode[0] = "deny-complete"
                assert send() != 201
                assert len(requests) == 2 and len(captures) == 2
                print("PASS failed response capture cannot report successful delivery")
                captures.clear()
                assert send("http://scopelens-broker.invalid/callback-dispatch") == 403
                assert len(requests) == 2 and not captures
                print(
                    "PASS worker cannot call private capture endpoint through local control route"
                )
            finally:
                proxy.stop()
    finally:
        for server in (target, policy):
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
