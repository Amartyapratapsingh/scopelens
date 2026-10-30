"""Actual HTTP/XXE parser fixture, run in a Linux container with --network none.

Scanner sockets originate 127.0.0.1; the target's callback client explicitly binds
127.0.0.2. Both vulnerable and fixed cases use the same target application/parser.
"""

import io
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from xml.sax import InputSource, handler, make_parser

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scopelens.callbacks.probes import CallbackProbeRecipe, run_callback_probe
from scopelens.callbacks.service import CallbackBase, CallbackService


class CollectorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        token = self.path.rsplit("/", 1)[-1]
        receipt = service.capture(token, peer=self.client_address[0], method="GET")
        self.send_response(200 if receipt else 404)
        self.end_headers()
        self.wfile.write(b"synthetic-canary")

    def log_message(self, *_):
        pass


collector = ThreadingHTTPServer(("127.0.0.1", 0), CollectorHandler)
callback_origin = f"http://127.0.0.1:{collector.server_port}"


def target_fetch(url):
    if not url.startswith(callback_origin + "/callback/"):
        raise ValueError("fixture only permits its synthetic callback origin")
    with httpx.Client(
        transport=httpx.HTTPTransport(local_address="127.0.0.2"), timeout=2, trust_env=False
    ) as client:
        response = client.get(url, follow_redirects=False)
        return response.content


class Resolver(handler.EntityResolver):
    def resolveEntity(self, publicId, systemId):
        source = InputSource()
        source.setByteStream(io.BytesIO(target_fetch(systemId)))
        return source


class TargetHandler(BaseHTTPRequestHandler):
    vulnerable = True

    def do_GET(self):
        value = parse_qs(urlsplit(self.path).query)["url"][0]
        if self.vulnerable and value.startswith("http:"):
            target_fetch(value)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"processed synthetic request")

    def do_POST(self):
        size = min(int(self.headers["Content-Length"]), 65536)
        parser = make_parser()
        parser.setFeature(handler.feature_external_ges, self.vulnerable)
        parser.setEntityResolver(Resolver())
        parser.setContentHandler(handler.ContentHandler())
        parser.parse(io.BytesIO(self.rfile.read(size)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"parsed synthetic XML")

    def log_message(self, *_):
        pass


target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (collector, target)]
with tempfile.TemporaryDirectory() as folder:
    engine = create_engine("sqlite:///" + str(Path(folder) / "callbacks.sqlite"))
    CallbackBase.metadata.create_all(engine)
    service = CallbackService(
        sessionmaker(engine), b"synthetic-lab-signing-key-32bytes!!", {callback_origin}
    )
    for thread in threads:
        thread.start()
    try:
        for vulnerable in (True, False):
            TargetHandler.vulnerable = vulnerable
            for family in ("ssrf", "xxe"):
                recipe = CallbackProbeRecipe(
                    family=family,
                    target_url=f"http://127.0.0.1:{target.server_port}/"
                    + ("fetch?url=normal" if family == "ssrf" else "xml"),
                    method="GET" if family == "ssrf" else "POST",
                    parameter="url" if family == "ssrf" else None,
                    callback_origin=callback_origin,
                    expected_target_peers=frozenset({"127.0.0.2"}),
                    scanner_peers=frozenset({"127.0.0.1"}),
                    approved_staging=True,
                    unexpected_external_fetch=True,
                    max_wait_seconds=0.2,
                )
                with httpx.Client(timeout=2, trust_env=False) as client:
                    result = run_callback_probe(
                        client,
                        service,
                        recipe,
                        owner_id="lab-owner",
                        scan_id="lab-scan",
                        task_id=family + str(vulnerable),
                    )
                assert result.state == ("confirmed" if vulnerable else "inconclusive"), result
                assert len(result.receipts) == (2 if vulnerable else 0)
                print(
                    json.dumps(
                        {
                            "variant": "vulnerable" if vulnerable else "fixed",
                            "family": family,
                            "state": result.state,
                            "requests": result.requests,
                            "http_target_receipts": len(result.receipts),
                            "distinct_nonces": len(set(result.nonce_ids)),
                            "receipt_signatures_valid": all(
                                service.verify(r) for r in result.receipts
                            ),
                        }
                    )
                )
    finally:
        for server in (target, collector):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join()
        engine.dispose()
