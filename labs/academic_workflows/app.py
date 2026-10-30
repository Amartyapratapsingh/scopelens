"""Owned synthetic academic fixture. Contains no real users or academic records."""

import argparse
import html
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

PASSWORD = "synthetic-only"
MARKERS = {name: f"synthetic-academic-{name}-record-2026" for name in ("student_a", "student_b")}
FUNCTION_MARKER = "synthetic-academic-staff-function-2026"
BASELINE = {
    "marks": 61,
    "attendance": 72,
    "academic_status": "enrolled",
    "display_name": "Synthetic student",
    "approval_state": "draft",
}
PROTECTED_FIELDS = {"marks", "attendance", "academic_status", "approval_state"}


def handler(*, vulnerable=False, cleanup_fails=False, session_ttl=3600, fix_flag=None):
    sessions = {}
    records = {name: {"marker": marker, **BASELINE} for name, marker in MARKERS.items()}
    lock = threading.RLock()
    if fix_flag not in {None, "/tmp/academic-fixed"}:
        raise ValueError("fixture lifecycle flag must use its designated tmpfs path")

    def is_vulnerable():
        return vulnerable and not (fix_flag and Path(fix_flag).exists())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body, cookie=None):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(raw)

        def session_id(self):
            try:
                cookies = SimpleCookie(self.headers.get("Cookie", ""))
                return cookies["sid"].value if "sid" in cookies else None
            except ValueError:
                return None

        def identity(self):
            item = sessions.get(self.session_id())
            return item[0] if item and item[1] > time.monotonic() else None

        def do_GET(self):
            with lock:
                self.get()

        def get(self):
            path = urlsplit(self.path).path
            if path in {"/", "/healthz"}:
                return self.reply(200, {"synthetic": True, "service": "academic-development-lab"})
            identity = self.identity()
            if path == "/identity-home":
                # Mirrors a legacy HTML account header without real personal data.
                body = (
                    '<div class="user-menu"><a class="dropdown-toggle"><span '
                    f'class="hidden-xs">{html.escape(identity)}</span></a></div>'
                    if identity
                    else '<form><input type="password" name="password"></form>'
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            if not identity:
                return self.reply(401, {"error": "unauthenticated"})
            if path == "/me":
                return self.reply(200, {"identity": identity})
            if path == "/staff/approval-function":
                if is_vulnerable() or identity == "staff":
                    return self.reply(200, {"marker": FUNCTION_MARKER})
                return self.reply(403, {"error": "forbidden"})
            name = path.removeprefix("/records/")
            if path.startswith("/records/") and name in records:
                if is_vulnerable() or identity in {name, "staff"}:
                    return self.reply(200, dict(records[name]))
                return self.reply(403, {"error": "forbidden"})
            self.reply(404, {"error": "missing"})

        def do_POST(self):
            with lock:
                self.post()

        def post(self):
            try:
                size = int(self.headers.get("Content-Length", 0))
                if size < 0 or size > 4096:
                    return self.reply(413, {"error": "too_large"})
                data = json.loads(self.rfile.read(size) or b"{}")
                if not isinstance(data, dict):
                    raise ValueError
            except ValueError:
                return self.reply(400, {"error": "invalid_json"})
            path = urlsplit(self.path).path
            if path == "/login":
                name = data.get("username")
                if name not in {*records, "staff"} or data.get("password") != PASSWORD:
                    return self.reply(401, {"error": "bad_credentials"})
                sid = secrets.token_hex(16)
                sessions[sid] = (name, time.monotonic() + session_ttl)
                return self.reply(200, {}, f"sid={sid}; Path=/; HttpOnly; SameSite=Strict")
            identity = self.identity()
            if not identity:
                return self.reply(401, {"error": "unauthenticated"})
            if path in {"/logout", "/expire"}:
                # Logout vulnerability is separate from real server-side expiry.
                if path == "/expire" or not is_vulnerable():
                    sessions.pop(self.session_id(), None)
                return self.reply(
                    200, {"ok": True}, "sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
                )
            parts = path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "records" or parts[1] not in records:
                return self.reply(404, {"error": "missing"})
            name, operation = parts[1:]
            record = records[name]
            if operation == "reset":
                if identity != "staff":
                    return self.reply(403, {"error": "forbidden"})
                if cleanup_fails:
                    return self.reply(503, {"error": "reset_failed"})
                record.update(BASELINE)
            elif operation in {"marks", "attendance"}:
                if not is_vulnerable() and identity != "staff":
                    return self.reply(403, {"error": "forbidden"})
                value = data.get("value")
                if type(value) is not int or not 0 <= value <= 100:
                    return self.reply(422, {"error": "invalid_value"})
                record[operation] = value
            elif operation == "profile":
                if identity not in {name, "staff"}:
                    return self.reply(403, {"error": "forbidden"})
                if not data or set(data) - (PROTECTED_FIELDS | {"display_name"}):
                    return self.reply(422, {"error": "unknown_field"})
                if not is_vulnerable() and identity != "staff" and set(data) & PROTECTED_FIELDS:
                    return self.reply(403, {"error": "protected_field"})
                if any(
                    not isinstance(value, (str, int)) or isinstance(value, bool)
                    for value in data.values()
                ):
                    return self.reply(422, {"error": "invalid_value"})
                record.update(data)
            elif operation in {"submit", "review", "approve"}:
                allowed = {
                    "submit": (identity in {name, "staff"}, "draft", "submitted"),
                    "review": (identity == "staff", "submitted", "reviewed"),
                    "approve": (identity == "staff", "reviewed", "approved"),
                }
                permitted, before, after = allowed[operation]
                if not is_vulnerable() or operation != "approve":
                    if not permitted:
                        return self.reply(403, {"error": "forbidden"})
                    if record["approval_state"] != before:
                        return self.reply(409, {"error": "invalid_transition"})
                record["approval_state"] = after
            else:
                return self.reply(404, {"error": "missing"})
            self.reply(200, {"ok": True})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=["bad", "fixed"], required=True)
    parser.add_argument("--host", choices=["127.0.0.1", "0.0.0.0"], default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--fix-flag", choices=["/tmp/academic-fixed"])
    args = parser.parse_args()
    ThreadingHTTPServer(
        (args.host, args.port), handler(vulnerable=args.variant == "bad", fix_flag=args.fix_flag)
    ).serve_forever()


if __name__ == "__main__":
    main()
