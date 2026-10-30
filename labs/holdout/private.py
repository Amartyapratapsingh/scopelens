"""Small private implementations; no benchmark labels or answer-key API."""

import html
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = urlsplit(self.path)
        value = parse_qs(parts.query, keep_blank_values=True).get("value", [""])[0]
        status, headers, body = 200, {}, ""
        if parts.path == "/render-raw":
            body = "<html><body><article>" + value + "</article></body></html>"
        elif parts.path == "/render-text":
            body = "<html><body><article>" + html.escape(value) + "</article></body></html>"
        elif parts.path in {"/find-sql", "/find-param"}:
            # Fresh read-only synthetic state on each request. No persistent rows.
            with sqlite3.connect(":memory:") as db:
                db.execute("CREATE TABLE catalogue (term TEXT)")
                db.execute("INSERT INTO catalogue VALUES ('pear')")
                try:
                    if parts.path == "/find-param":
                        row = db.execute("SELECT term FROM catalogue WHERE term=?", (value,))
                    else:
                        row = db.execute("SELECT term FROM catalogue WHERE term='" + value + "'")
                    body = "available" if row.fetchone() else "absent"
                except sqlite3.Error:
                    status, body = 400, "invalid query"
        elif parts.path == "/next-free":
            status, headers = 302, {"Location": value or "/"}
        elif parts.path == "/next-local":
            status, headers = 302, {"Location": "/"}
        elif parts.path == "/cors-echo":
            headers = {
                "Access-Control-Allow-Origin": self.headers.get("Origin", "null"),
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
            body = "synthetic public resource"
        elif parts.path == "/cors-constant":
            headers = {"Access-Control-Allow-Origin": "https://local-client.invalid"}
            body = "synthetic public resource"
        else:
            status, body = 404, "missing"
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for key, val in headers.items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
