"""Synthetic identity lab, importable by tests or runnable on loopback only."""

from __future__ import annotations

import argparse
import json
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

MARKER = "scopelens-owned-a-private-marker-84721"


def handler(*, vulnerable=False, expire_on_object=False, waf=False, shared=False):
    sessions = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body, cookie=None):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            if vulnerable and self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Credentials", "true")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(raw)

        def session(self):
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            sid = cookies.get("sid")
            return sid.value if sid else None

        def do_POST(self):
            if self.path == "/login":
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                data = (
                    {key: values[0] for key, values in parse_qs(raw.decode()).items()}
                    if self.headers.get("Content-Type", "").startswith(
                        "application/x-www-form-urlencoded"
                    )
                    else json.loads(raw or b"{}")
                )
                if data.get("password") != "synthetic-password" or data.get("username") not in {
                    "a",
                    "b",
                    "admin",
                }:
                    self.reply(401, {"error": "bad_credentials"})
                    return
                previous = self.session()
                if not vulnerable:
                    sessions.pop(previous, None)
                sid = previous if vulnerable and previous else secrets.token_hex(16)
                sessions[sid] = data["username"]
                self.reply(200, {"ok": True}, f"sid={sid}; HttpOnly; Path=/; SameSite=Lax")
            elif self.path == "/logout":
                if not vulnerable:
                    sessions.pop(self.session(), None)
                self.reply(200, {"ok": True}, "sid=; Max-Age=0; Path=/")
            else:
                self.reply(404, {"error": "missing"})

        def do_GET(self):
            if self.path == "/foreign":
                self.reply(200, {"controlled_foreign_page": True})
                return
            identity = sessions.get(self.session())
            if self.path == "/me":
                self.reply(200, {"identity": identity}) if identity else self.reply(
                    401, {"error": "unauthenticated"}
                )
                return
            if not identity:
                self.reply(302, {"login": True})
                return
            if self.path in {"/objects/a", "/admin/export", "/tenant/a", "/property/a"}:
                if expire_on_object and identity == "b":
                    sessions.pop(self.session(), None)
                    self.reply(403, {"error": "forbidden"})
                elif identity in {"a", "admin"} or vulnerable:
                    self.reply(200, {"private": MARKER, "public": "shared"})
                elif waf:
                    self.reply(403, {"waf": "challenge"})
                elif shared:
                    self.reply(200, {"private": None, "public": "shared"})
                else:
                    self.reply(403, {"error": "forbidden"})
            else:
                self.reply(404, {"error": "missing"})

    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8777)
    parser.add_argument("--vulnerable", action="store_true")
    args = parser.parse_args()
    ThreadingHTTPServer(
        ("127.0.0.1", args.port), handler(vulnerable=args.vulnerable)
    ).serve_forever()
