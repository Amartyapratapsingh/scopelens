"""Disposable synthetic B5 workflow application. No external services or user data."""

from __future__ import annotations

import json
import secrets
import tempfile
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from jinja2.sandbox import SandboxedEnvironment

MARKER = "workflow-owned-a-marker-251973"
CANARY = "workflow-nonsensitive-traversal-canary-4907"


def handler(*, vulnerable=False, cleanup_fails=False):
    sessions = {}
    record = {"marker": MARKER, "privileged": False, "status": "draft"}
    cache = {}
    scratch = tempfile.TemporaryDirectory(prefix="scopelens-canary-")
    root = Path(scratch.name).resolve()
    (root / "public").mkdir()
    (root / "canary.txt").write_text(CANARY)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def identity(self):
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            return sessions.get(cookies["sid"].value) if "sid" in cookies else None

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path == "/login":
                if (
                    data.get("username") not in {"a", "b", "admin"}
                    or data.get("password") != "synthetic-password"
                ):
                    self.reply(401, {"error": "bad_credentials"})
                    return
                sid = secrets.token_hex(16)
                sessions[sid] = data["username"]
                self.send_response(200)
                self.send_header("Set-Cookie", f"sid={sid}; Path=/; HttpOnly")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
                return
            identity = self.identity()
            if not identity:
                self.reply(401, {"error": "unauthenticated"})
                return
            if self.path == "/reset":
                if cleanup_fails:
                    self.reply(503, {"error": "reset_failed"})
                    return
                record.update(privileged=False, status="draft")
                self.reply(200, {"ok": True})
            elif self.path == "/update":
                if vulnerable or identity == "admin":
                    record["privileged"] = data.get("privileged", False)
                self.reply(200, {"ok": True})
            elif self.path == "/approve":
                if vulnerable or identity == "admin":
                    record["status"] = "approved"
                self.reply(200, {"ok": True})
            elif self.path == "/graphql":
                if data.get("operationName") == "PrivateObject" and (identity == "a" or vulnerable):
                    self.reply(200, {"data": {"object": {"marker": MARKER}}})
                else:
                    self.reply(200, {"error": "forbidden"})
            else:
                self.reply(404, {"error": "missing"})

        def do_GET(self):
            identity = self.identity()
            parsed = urlsplit(self.path)
            args = parse_qs(parsed.query)
            if parsed.path == "/me":
                self.reply(200, {"identity": identity}) if identity else self.reply(
                    401, {"error": "unauthenticated"}
                )
            elif not identity:
                self.reply(401, {"error": "unauthenticated"})
            elif parsed.path == "/record":
                self.reply(200, dict(record))
            elif parsed.path == "/cache":
                if identity == "a":
                    cache["private"] = MARKER
                    self.reply(200, {"marker": MARKER})
                elif vulnerable and cache.get("private") and args.get("variant") != ["fresh"]:
                    self.reply(200, {"marker": cache["private"]})
                else:
                    self.reply(403, {"error": "forbidden"})
            elif parsed.path == "/canary-baseline":
                self.reply(200, {"body": CANARY})
            elif parsed.path == "/file":
                candidate = (root / "public" / args.get("path", [""])[0]).resolve()
                allowed_root = root if vulnerable else root / "public"
                if candidate.is_relative_to(allowed_root) and candidate.is_file():
                    self.reply(200, {"body": candidate.read_text()})
                else:
                    self.reply(403, {"error": "forbidden"})
            elif parsed.path == "/render":
                value = args.get("value", [""])[0]
                # Only the vulnerable fixture interprets the benign arithmetic template.
                rendered = (
                    SandboxedEnvironment().from_string(value).render() if vulnerable else value
                )
                self.reply(200, {"result": rendered})
            else:
                self.reply(404, {"error": "missing"})

    Handler.scratch = scratch
    return Handler
