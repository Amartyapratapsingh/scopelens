"""Loopback fixture with actual server-side elapsed session expiry."""

import argparse
import hashlib
import json
import secrets
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PASSWORD = "synthetic-expiry-password"


def handler(
    *,
    vulnerable=False,
    denial_status=401,
    denial_value="unauthenticated",
    fail_replay=False,
    browser_max_age=None,
):
    sessions = {}
    replay_count = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body, cookie=None):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(raw)

        def cookie(self):
            cookie = SimpleCookie(self.headers.get("Cookie", "")).get("sid")
            return cookie.value if cookie else None

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            data = json.loads(raw or b"{}")
            if self.path != "/login" or data != {"username": "student", "password": PASSWORD}:
                self.reply(401, {"error": "bad_credentials"})
                return
            sid = secrets.token_hex(16)
            sessions[sid] = time.monotonic()
            cookie = f"sid={sid}; HttpOnly; Path=/; SameSite=Lax"
            if browser_max_age is not None:
                cookie += f"; Max-Age={browser_max_age}"
            self.reply(200, {"ok": True}, cookie)

        def do_GET(self):
            if self.path == "/healthz":
                self.reply(200, {"ok": True})
                return
            if self.path == "/fixture-proof":
                self.reply(
                    200,
                    {
                        "server_ttl_seconds": 1,
                        "sessions": [
                            {
                                "cookie_hash": hashlib.sha256(sid.encode()).hexdigest(),
                                "expired_probe_count": replay_count.get(sid, 0),
                                "server_age_seconds": time.monotonic() - created,
                            }
                            for sid, created in sessions.items()
                        ],
                    },
                )
                return
            sid = self.cookie()
            created = sessions.get(sid)
            if self.path != "/me":
                self.reply(404, {"error": "missing"})
                return
            expired = created is not None and time.monotonic() - created >= 1
            if expired:
                replay_count[sid] = replay_count.get(sid, 0) + 1
                if fail_replay and replay_count[sid] == 2:
                    self.close_connection = True
                    return
            if created is not None and (vulnerable or not expired):
                self.reply(200, {"identity": "student"})
            else:
                # Delete the client cookie to test that both replay requests reset the jar.
                self.reply(denial_status, {"error": denial_value}, "sid=; Max-Age=0; Path=/")

    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--host", choices=("127.0.0.1", "0.0.0.0"), default="127.0.0.1")
    parser.add_argument("--vulnerable", action="store_true")
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), handler(vulnerable=args.vulnerable)).serve_forever()
