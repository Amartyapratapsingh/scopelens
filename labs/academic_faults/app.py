"""Academic fault fixture. Fault controls exist only in the container's tmpfs."""

import argparse
import json
import threading
import time
from contextlib import suppress
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from labs.academic_workflows.app import handler as academic_handler

CONTROL_DIR = Path("/tmp/academic-faults")
FLAGS = {"hold-mutation", "release-mutation", "allow-reset"}


def handler(control_dir=CONTROL_DIR):
    """Reuse the academic record and auth contract; add bounded synthetic faults."""
    control_dir = Path(control_dir)
    control_dir.mkdir(parents=True, exist_ok=True)
    parent = academic_handler(vulnerable=True)
    ledger_lock = threading.Lock()

    class Handler(parent):
        def reply(self, status, body, cookie=None):
            path = urlsplit(self.path).path
            with ledger_lock, (control_dir / "requests.jsonl").open("a") as stream:
                # No request body, secret, cookie or session identifier is recorded.
                stream.write(
                    json.dumps({"method": self.command, "path": path, "status": status}) + "\n"
                )
            if (
                self.command == "POST"
                and path == "/records/student_a/marks"
                and status == 200
                and (control_dir / "hold-mutation").exists()
            ):
                (control_dir / "mutation-applied").write_text("marks mutation applied\n")
                while not (control_dir / "release-mutation").exists():
                    time.sleep(0.02)
            # A cancelled worker may close the held response connection.
            with suppress(BrokenPipeError, ConnectionResetError):
                super().reply(status, body, cookie)

        def do_POST(self):
            if (
                urlsplit(self.path).path == "/records/student_a/reset"
                and self.identity() == "staff"
                and not (control_dir / "allow-reset").exists()
            ):
                return self.reply(503, {"error": "reset_failed"})
            return super().do_POST()

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=["127.0.0.1", "0.0.0.0"], default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), handler()).serve_forever()


if __name__ == "__main__":
    main()
