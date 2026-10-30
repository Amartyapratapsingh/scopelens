"""Stateless synthetic validation app. Labels and scanner code are not imported here."""

import html
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        parts = parsed.path.strip("/").split("/")
        query = parse_qs(parsed.query)
        value = query.get("q", [""])[0][:1000]
        status, body, headers = 200, "Validation application", {}
        mime = "text/html; charset=utf-8"
        if len(parts) != 2:
            status = 200 if parsed.path in {"/", "/healthz"} else 404
        else:
            family, variant = parts
            if family in {"xss", "html"}:
                if variant == "markup":
                    body = "<main>Preview: " + value + "</main>"
                elif variant == "template":
                    body = "<table><tr><td>" + value + "</td></tr></table>"
                elif variant == "escaped":
                    body = "<main>Preview: " + html.escape(value) + "</main>"
                elif variant == "plaintext":
                    body, mime = value, "text/plain; charset=utf-8"
                    headers["X-Content-Type-Options"] = "nosniff"
                else:
                    status = 404
            elif family == "sql":
                with sqlite3.connect(":memory:") as db:
                    db.execute("CREATE TABLE products (name TEXT, id INTEGER)")
                    db.executemany(
                        "INSERT INTO products VALUES (?, ?)", [("apple", 1), ("pear", 2)]
                    )
                    try:
                        if variant == "single":
                            rows = db.execute(
                                "SELECT name FROM products WHERE name='" + value + "'"
                            ).fetchall()
                        elif variant == "double":
                            rows = db.execute(
                                'SELECT name FROM products WHERE name="' + value + '"'
                            ).fetchall()
                        elif variant == "numeric":
                            rows = db.execute(
                                "SELECT name FROM products WHERE id=" + (value or "0")
                            ).fetchall()
                        elif variant == "bound":
                            rows = db.execute(
                                "SELECT name FROM products WHERE name=?", (value,)
                            ).fetchall()
                        elif variant == "integer":
                            rows = db.execute(
                                "SELECT name FROM products WHERE id=?", (int(value),)
                            ).fetchall()
                        elif variant == "empty":
                            rows = db.execute(
                                "SELECT name FROM products WHERE name=? AND id=999", (value,)
                            ).fetchall()
                        else:
                            rows, status = [], 404
                        body = json.dumps(rows)
                    except (sqlite3.Error, ValueError):
                        body = "Invalid search"
                    mime = "application/json"
            elif family == "redirect":
                target = query.get("next", ["/"])[0]
                if variant in {"301", "303", "307", "308"}:
                    status, headers["Location"] = int(variant), target
                elif variant == "local":
                    status, headers["Location"] = 302, "/account"
                elif variant == "echo":
                    body = html.escape(target)
                else:
                    status = 404
            elif family == "cors":
                origin = self.headers.get("Origin", "https://allowed.invalid")
                body, mime = '{"value":"synthetic"}', "application/json"
                if variant in {"reflect", "empty"}:
                    headers.update(
                        {
                            "Access-Control-Allow-Origin": origin,
                            "Access-Control-Allow-Credentials": "true",
                        }
                    )
                    if variant == "empty":
                        status, body = 204, ""
                elif variant == "wildcard":
                    headers.update(
                        {
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Credentials": "true",
                        }
                    )
                elif variant == "allowlist":
                    headers.update(
                        {
                            "Access-Control-Allow-Origin": "https://allowed.invalid",
                            "Access-Control-Allow-Credentials": "true",
                        }
                    )
                elif variant == "no-credentials":
                    headers["Access-Control-Allow-Origin"] = origin
                elif variant == "invalid-credentials":
                    headers.update(
                        {
                            "Access-Control-Allow-Origin": origin,
                            "Access-Control-Allow-Credentials": "TRUE",
                        }
                    )
                else:
                    status = 404
            else:
                status = 404
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        for name, content in headers.items():
            self.send_header(name, content)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
