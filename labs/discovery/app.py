"""Owned, memory-only discovery fixture. Never deploy on a public interface.

The two variants expose the same discoverable routes. The evaluator owns their
labels; this application provides no ground-truth or answer-key endpoint.
"""

import argparse
import hashlib
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import uuid4


def routes():
    return {
        name: "/" + hashlib.sha256(("discovery-development-v1:" + name).encode()).hexdigest()[:16]
        for name in ("query", "form", "json", "path", "dom")
    }


def search(value, *, parameterized):
    """Only a synthetic in-memory table; each request gets a fresh database."""
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("invalid search value")
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE products (name TEXT)")
        db.execute("INSERT INTO products VALUES ('apple')")
        try:
            rows = (
                db.execute("SELECT name FROM products WHERE name = ?", (value,)).fetchall()
                if parameterized
                else db.execute("SELECT name FROM products WHERE name = '" + value + "'").fetchall()
            )
            return {"count": len(rows), "request_id": str(uuid4())}
        except sqlite3.Error:
            return {"error": "invalid search expression", "request_id": str(uuid4())}


def make_server(host="127.0.0.1", port=0, *, variant="fixed"):
    if variant not in {"bad", "fixed"}:
        raise ValueError("unknown fixture variant")
    paths = routes()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, value, *, content_type="application/json", status=200):
            body = (json.dumps(value) if content_type == "application/json" else value).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if len(self.path) > 8192:
                return self.respond({"error": "request too long"}, status=414)
            url = urlsplit(self.path)
            if url.path == "/healthz":
                return self.respond({"ready": True})
            if url.path == "/":
                # Construct the JSON route at runtime; a literal-link crawler cannot find it.
                html = f'''<!doctype html><html><body>
<a href="{paths["query"]}?q=apple">Search catalogue</a>
<form action="{paths["form"]}" method="post"><input name="q" value="apple"></form>
<a href="{paths["dom"]}?q=ordinary">Preview text</a>
<a href="/openapi.json">API schema</a>
<script>
const endpoint = ["", "{paths["json"][1:]}"] .join("/");
fetch(endpoint, {{method:"POST", headers:{{"Content-Type":"application/json"}},
body:JSON.stringify({{search:{{text:"apple"}}}})}}).catch(() => {{}});
</script></body></html>'''
                return self.respond(html, content_type="text/html")
            if url.path == "/openapi.json":
                return self.respond(
                    {
                        "openapi": "3.0.3",
                        "info": {"title": "Catalogue", "version": "1"},
                        "paths": {
                            paths["path"] + "/{item}": {
                                "get": {
                                    "parameters": [
                                        {
                                            "name": "item",
                                            "in": "path",
                                            "required": True,
                                            "schema": {"type": "string"},
                                            "example": "apple",
                                        }
                                    ],
                                    "responses": {"200": {"description": "Search results"}},
                                }
                            }
                        },
                    }
                )
            if url.path == paths["dom"]:
                sink = "innerHTML" if variant == "bad" else "textContent"
                return self.respond(
                    '<!doctype html><html><body><div id="preview"></div><script>'
                    f'document.querySelector("#preview").{sink}='
                    'new URLSearchParams(location.search).get("q") || "";'
                    "</script></body></html>",
                    content_type="text/html",
                )
            if url.path == paths["query"]:
                return self.search_response(
                    parse_qs(url.query, keep_blank_values=True).get("q", [""])[0]
                )
            if url.path.startswith(paths["path"] + "/"):
                return self.search_response(unquote(url.path[len(paths["path"]) + 1 :]))
            return self.respond({"error": "not found"}, status=404)

        def search_response(self, value):
            try:
                return self.respond(search(value, parameterized=variant == "fixed"))
            except ValueError:
                return self.respond({"error": "invalid input"}, status=400)

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 65536:
                    raise ValueError
                raw = self.rfile.read(size)
                path = urlsplit(self.path).path
                if path == paths["form"]:
                    value = parse_qs(raw.decode(), keep_blank_values=True).get("q", [""])[0]
                elif path == paths["json"]:
                    value = json.loads(raw)["search"]["text"]
                else:
                    return self.respond({"error": "not found"}, status=404)
            except (ValueError, KeyError, TypeError, UnicodeError):
                return self.respond({"error": "invalid request"}, status=400)
            return self.search_response(value)

    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("bad", "fixed"), required=True)
    args = parser.parse_args()
    make_server("0.0.0.0", 8080, variant=args.variant).serve_forever()
