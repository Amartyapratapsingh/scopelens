"""Synthetic canary fixture, dev-only, with one fixed permitted callback destination.

The XML route recognizes the existing reviewed marker shape; it does not run an XML
entity parser. It cannot read files or fetch arbitrary URLs. Neither route returns
collector content, and fixed variants never initiate callbacks.
"""

from __future__ import annotations

import http.client
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

COLLECTOR_HOST = "172.28.0.17"
COLLECTOR_PORT = 8091
COLLECTOR_ORIGIN = f"http://{COLLECTOR_HOST}:{COLLECTOR_PORT}"
TOKEN_PATH = re.compile(r"/callback/[A-Za-z0-9_-]{20,128}\Z")
XML_MARKER = re.compile(
    r"""\A<\?xml version="1\.0"\?><!DOCTYPE (?P<root>[A-Za-z_][A-Za-z0-9_]{0,63}) \[<!ENTITY scopelens SYSTEM (?P<quote>["'])(?P<url>[^"'<>\s]+)(?P=quote)>\]><(?P=root)>&scopelens;</(?P=root)>\Z"""
)
MAX_BODY = 4096


def allowed_callback(url: str) -> str | None:
    parsed = urlsplit(url)
    if (
        f"{parsed.scheme}://{parsed.netloc}" != COLLECTOR_ORIGIN
        or parsed.query
        or parsed.fragment
        or not TOKEN_PATH.fullmatch(parsed.path)
    ):
        return None
    return parsed.path


def fetch_collector(url: str) -> bool:
    path = allowed_callback(url)
    if path is None:
        return False
    # A numeric fixed peer avoids DNS/rebinding. No proxy environment, redirects or
    # destination supplied by the request can change this connection.
    connection = http.client.HTTPConnection(COLLECTOR_HOST, COLLECTOR_PORT, timeout=2)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        response.read(1024)
        return response.status == 204
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def handler(fetch=fetch_collector):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, status=200):
            body = json.dumps({"status": "processed"}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/healthz":
                return self.reply()
            if parsed.path not in {"/bad/ssrf", "/fixed/ssrf"}:
                return self.reply(404)
            values = parse_qs(parsed.query, keep_blank_values=True).get("url", [])
            if len(values) != 1:
                return self.reply(400)
            if parsed.path == "/bad/ssrf" and allowed_callback(values[0]):
                fetch(values[0])
            self.reply()

        def do_POST(self):
            if urlsplit(self.path).path not in {"/bad/xxe", "/fixed/xxe"}:
                return self.reply(404)
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self.reply(400)
            if not 0 < length <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                return self.reply(413)
            self.connection.settimeout(3)
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            match = XML_MARKER.fullmatch(body)
            if urlsplit(self.path).path == "/bad/xxe" and match and allowed_callback(match["url"]):
                fetch(match["url"])
            self.reply()

    return Handler


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), handler()).serve_forever()
