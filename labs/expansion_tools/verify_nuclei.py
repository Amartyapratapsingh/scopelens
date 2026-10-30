"""Run in pinned Kali image with --network none; only loopback synthetic lab traffic."""

import json
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FOLDER = Path("/templates")
manifest = json.loads((FOLDER / "manifest.json").read_text())
expected = {r["id"] for r in manifest["templates"]}


class Handler(BaseHTTPRequestHandler):
    vulnerable = True

    def do_GET(self):
        bodies = {
            "/.env": "APP_NAME=lab\nDB_PASSWORD=synthetic-only-not-live\n",
            "/phpinfo.php": "<title>phpinfo()</title>PHP Version DOCUMENT_ROOT SERVER_SOFTWARE",
            "/server-status?auto": "Total Accesses: 1\nBusyWorkers: 1\nIdleWorkers: 2\n",
            "/actuator/env": '{"propertySources":[{"properties":{"private":"synthetic"}}]}',
            "/server.key": "-----BEGIN PRIVATE KEY-----synthetic-invalid-key-----END PRIVATE KEY-----",
        }
        body = bodies.get(self.path) if self.vulnerable else None
        self.send_response(200 if body else 404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write((body or "not found").encode())

    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory() as temp:
        for vulnerable in (True, False):
            Handler.vulnerable = vulnerable
            output = Path(temp) / ("bad.jsonl" if vulnerable else "good.jsonl")
            command = [
                "nuclei",
                "-u",
                f"http://127.0.0.1:{server.server_port}",
                "-jsonl",
                "-o",
                str(output),
                "-duc",
                "-ni",
                "-nc",
                "-silent",
                "-rl",
                "5",
                "-c",
                "1",
                "-timeout",
                "3",
                "-retries",
                "0",
            ]
            for row in manifest["templates"]:
                command += ["-t", str(FOLDER / row["file"])]
            subprocess.run(command, check=True, timeout=30, stdout=subprocess.DEVNULL)
            rows = (
                [json.loads(line) for line in output.read_text().splitlines()]
                if output.exists()
                else []
            )
            ids = {row["template-id"] for row in rows}
            assert ids == (expected if vulnerable else set()), ids
            print(
                json.dumps(
                    {
                        "variant": "vulnerable" if vulnerable else "fixed",
                        "candidate_ids": sorted(ids),
                        "expected_count": len(expected) if vulnerable else 0,
                    }
                )
            )
finally:
    server.shutdown()
    server.server_close()
    thread.join()
