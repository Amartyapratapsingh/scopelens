"""Run only in pinned Kali image with --network none: loopback policy canary."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
from urllib.parse import urlsplit

from scopelens.adapters.expansion_runner import run_expansion_tools


class PolicyCanary(BaseHTTPRequestHandler):
    vulnerable = True
    requests: ClassVar[list[str]] = []

    def do_GET(self):
        token = self.headers.get("x-scopelens-egress")
        assert token == "local-fixture-capability", "inner scan token missing"
        assert self.headers.get("Proxy-Authorization"), "bridge proxy token missing"
        target = urlsplit(self.path)
        assert target.hostname == "127.0.0.1" and target.port == 1
        path = target.path + ("?" + target.query if target.query else "")
        self.requests.append(path)
        bodies = {
            "/.env": "APP_NAME=lab\nDB_PASSWORD=synthetic-only-not-live\n",
            "/phpinfo.php": "<title>phpinfo()</title>PHP Version DOCUMENT_ROOT SERVER_SOFTWARE",
            "/server-status?auto": "Total Accesses: 1\nBusyWorkers: 1\nIdleWorkers: 2\n",
            "/actuator/env": '{"propertySources":[{"properties":{"private":"synthetic"}}]}',
            "/server.key": "-----BEGIN PRIVATE KEY-----synthetic-invalid-key-----END PRIVATE KEY-----",
        }
        assert path in bodies, "unreviewed request"
        body = bodies[path] if self.vulnerable else "not found"
        self.send_response(200 if self.vulnerable else 404)
        self.send_header("Content-Length", str(len(body.encode())))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), PolicyCanary)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
os.environ["HTTP_PROXY"] = f"http://127.0.0.1:{server.server_port}"
os.environ["SCOPELENS_EGRESS_TOKEN"] = "local-fixture-capability"
try:
    for vulnerable in (True, False):
        PolicyCanary.vulnerable = vulnerable
        PolicyCanary.requests.clear()
        results = list(
            run_expansion_tools(
                SimpleNamespace(origin="http://127.0.0.1:1"),
                technologies=("php", "apache", "spring"),
                bundle=Path("/templates"),
            )
        )
        assert len(results) == 5 and all(row.state == "completed" for row in results), [
            row.model_dump() for row in results
        ]
        observations = [item for row in results for item in row.observations]
        assert len(observations) == (5 if vulnerable else 0), [row.model_dump() for row in results]
        assert len(PolicyCanary.requests) == 5
        assert all(item.status == "potential" and item.mapped_control for item in observations)
        assert all(row.assessed_rule_ids == [] for row in results)
        print(
            json.dumps(
                {
                    "variant": "vulnerable" if vulnerable else "fixed",
                    "candidates": len(observations),
                    "proxy_requests": len(PolicyCanary.requests),
                    "all_mapped": all(item.mapped_control for item in observations),
                }
            )
        )
finally:
    server.shutdown()
    server.server_close()
    thread.join()
