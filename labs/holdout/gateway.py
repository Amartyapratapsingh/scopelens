"""Exact-route ingress. Upstream administration and benchmark APIs are unreachable."""

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


ROUTES = json.loads(Path(os.environ["ROUTES_FILE"]).read_text())
UPSTREAM = os.environ["UPSTREAM"]
CLIENT = build_opener(NoRedirect)


class Handler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        # The target interface exposes no upstream or gateway technology banner.
        self.send_response_only(code, message)

    def do_GET(self):
        path = urlsplit(self.path)
        if path.path == "/healthz" and not path.query:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ready")
            return
        if path.path == "/" and not path.query:
            body = "<html><body>"
            for route, spec in ROUTES.items():
                query = urlencode({spec["parameter"]: spec.get("baseline", "hello")})
                body += f'<a href="{route}?{query}">{route}</a><br>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write((body + "</body></html>").encode())
            return
        spec = ROUTES.get(path.path)
        params = parse_qsl(path.query, keep_blank_values=True)
        if spec is None or any(k != spec["parameter"] for k, _ in params) or len(params) > 1:
            self.send_error(404)
            return
        upstream_params = dict(spec.get("fixed_parameters", {}))
        upstream_params.update(
            (spec.get("upstream_parameter", key), value) for key, value in params
        )
        url = UPSTREAM + spec["upstream_path"] + "?" + urlencode(upstream_params)
        request = Request(url, headers={"Cache-Control": "no-cache"})
        if self.headers.get("Origin"):
            request.add_header("Origin", self.headers["Origin"])
        try:
            response = CLIENT.open(request, timeout=15)
        except HTTPError as exc:
            response = exc
        except OSError:
            self.send_error(502)
            return
        with response:
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                self.send_error(502)
                return
            content_type = response.headers.get("Content-Type", "text/plain")
            filename = spec["upstream_path"].rsplit("/", 1)[-1].encode()
            if response.code >= 400:
                # Error pages contain native servlet names and source stack traces.
                body = b"fixture request failed"
            elif "html" in content_type:
                # Benchmark titles identify expected results. Remove titles and rewrite
                # form actions, without modifying the input sink or response status.
                body = re.sub(rb"<title\b[^>]*>.*?</title>", b"", body, flags=re.I | re.S)
                body = body.replace(spec["upstream_path"].encode(), path.path.encode())
                if spec.get("upstream_parameter"):
                    body = re.sub(
                        rb"(action=[\"'])" + re.escape(filename) + rb"([\"'])",
                        lambda match: match[1] + path.path.encode() + match[2],
                        body,
                    )
                    body = body.replace(
                        spec["upstream_parameter"].encode(), spec["parameter"].encode()
                    )
                body = body.replace(filename, path.path.encode())
            self.send_response(response.code)
            for key, value in response.headers.items():
                if key.lower() not in {
                    "content-length",
                    "transfer-encoding",
                    "connection",
                    "keep-alive",
                    "proxy-authenticate",
                    "proxy-authorization",
                    "te",
                    "trailer",
                    "upgrade",
                    "server",
                    "x-powered-by",
                    "content-location",
                    "refresh",
                    "set-cookie",
                }:
                    if key.lower() == "location":
                        resolved = urlsplit(urljoin(UPSTREAM + spec["upstream_path"], value))
                        upstream = urlsplit(UPSTREAM)
                        if resolved.netloc == upstream.netloc:
                            value = next(
                                (
                                    route
                                    for route, entry in ROUTES.items()
                                    if entry["upstream_path"] == resolved.path
                                ),
                                "/",
                            )
                        elif (
                            "BenchmarkTest" in value
                            or spec["upstream_path"] in value
                            or filename.decode() in value
                        ):
                            continue
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
