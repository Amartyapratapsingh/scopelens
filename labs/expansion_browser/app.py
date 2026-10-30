"""Synthetic disposable browser workflow fixture; deploy only on the isolated lab network."""

import html
import json
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

# Public fixture-only password; never a deployed operator credential.
FIXTURE_PASSWORD = "scopelens-synthetic-role-A-password"


def handler(records):
    class App(BaseHTTPRequestHandler):
        def respond(self):
            parsed = urlsplit(self.path)
            parts = parsed.path.split("/")
            query = parse_qs(parsed.query, keep_blank_values=True)
            variant, operation = (parts[1], parts[2]) if len(parts) > 2 else ("fixed", "foreign")
            identity = (
                "A"
                if "sid=A" in self.headers.get("Cookie", "")
                else "B"
                if "sid=B" in self.headers.get("Cookie", "")
                else None
            )
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            ctype = self.headers.get("Content-Type", "")
            data = (
                json.loads(body)
                if body and "application/json" in ctype
                else {k: v[0] for k, v in parse_qs(body.decode(errors="replace")).items()}
                if body
                else {}
            )
            status, headers = 200, {"Content-Type": "application/json"}
            result = {}
            if operation == "credential-login":
                if self.command != "POST":
                    status, result = 405, {"error": "POST required"}
                elif data.get("role") == "A" and data.get("password") == FIXTURE_PASSWORD:
                    headers["Set-Cookie"] = "sid=A; HttpOnly; SameSite=Lax; Path=/"
                    result = {"identity": "A"}
                else:
                    status, result = 401, {"error": "fixture credentials required"}
            elif operation == "protected-html":
                if identity != "A":
                    status, result = 403, {"error": "role A required"}
                elif self.command != "GET":
                    status, result = 405, {"error": "GET required"}
                else:
                    # Disposable read-only marker rendering; no record is changed.
                    value = query.get("q", [""])[0]
                    headers["Content-Type"] = "text/html"
                    result = (
                        "<html><body>"
                        + (value if variant == "bad" else html.escape(value))
                        + "</body></html>"
                    )
            elif operation == "cors-record":
                # Static synthetic seed: CORS comparisons never mutate a target record.
                if self.command != "GET":
                    status, result = 405, {"error": "GET required"}
                elif identity != "A":
                    status, result = 403, {"error": "role A required"}
                else:
                    result = {"private": "scopelens-owned-cors-marker-84721"}
                if variant == "bad" and self.headers.get("Origin"):
                    headers["Access-Control-Allow-Origin"] = self.headers["Origin"]
                    headers["Access-Control-Allow-Credentials"] = "true"
                headers["Cache-Control"] = "no-store"
                headers["Vary"] = "Origin"
            elif operation == "protected-redirect":
                if identity != "A":
                    status, result = 403, {"error": "role A required"}
                else:
                    destination = query.get("next", ["/safe"])[0]
                    target = urlsplit(destination)
                    if variant == "bad" and target.scheme in {"http", "https"} and target.hostname:
                        status, headers["Location"] = 302, destination
                        result = {"redirect": "fixture destination"}
                    else:
                        # Fixed behavior returns an explicit ordinary response with no
                        # redirect. Probe verdicts must distinguish this from a WAF block.
                        result = {"redirect": "external destination refused", "identity": "A"}
            elif operation == "login":
                headers["Set-Cookie"] = f"sid={data['role']}; HttpOnly; SameSite=Lax; Path=/"
                result = {"identity": data["role"]}
            elif operation == "identity":
                status = 200 if identity else 401
                result = {"identity": identity}
            elif operation == "record":
                status = 200 if identity == "A" else 403
                result = (
                    {"seed": "scopelens-disposable-record", "content": records[variant]}
                    if status == 200
                    else {}
                )
            elif operation == "mutate":
                foreign = self.headers.get("Origin") not in {None, f"http://{self.headers['Host']}"}
                if identity != "A" or (variant == "fixed" and foreign):
                    status = 403
                else:
                    records[variant] = data.get("content", "")
            elif operation == "cleanup":
                if identity != "A":
                    status = 403
                else:
                    records[variant] = ""
            elif operation == "viewer":
                status = 200 if identity else 401
                headers["Content-Type"] = "text/html"
                result = (
                    "<html><body>"
                    + (records[variant] if variant == "bad" else html.escape(records[variant]))
                    + "</body></html>"
                )
            elif operation == "form":
                headers["Content-Type"] = "text/html"
                result = f'<html><body><form method="POST" enctype="multipart/form-data" action="/{variant}/upload"><input type="file" name="file"><button type="submit">Upload</button></form></body></html>'
            elif operation == "upload":
                if identity != "A":
                    status = 403
                else:
                    message = BytesParser(policy=default).parsebytes(
                        f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
                    )
                    records[variant] = next(
                        part.get_payload(decode=True).decode()
                        for part in message.iter_parts()
                        if part.get_filename()
                    )
            elif operation == "file":
                status = 403 if variant == "fixed" and identity != "A" else 200
                headers["Content-Type"] = "text/plain"
                result = records[variant] if status == 200 else "denied"
            else:
                headers["Content-Type"] = "text/html"
                result = "<html><body>controlled foreign test page</body></html>"
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(
                json.dumps(result).encode() if isinstance(result, dict) else result.encode()
            )

        do_GET = respond
        do_POST = respond

        def log_message(self, *args):
            pass

    return App


if __name__ == "__main__":
    records = {"bad": "", "fixed": ""}
    secondary = ThreadingHTTPServer(("0.0.0.0", 8081), handler(records))
    Thread(target=secondary.serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), handler(records)).serve_forever()
