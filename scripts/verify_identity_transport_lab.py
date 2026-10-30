"""Owned HTTPS /auerp compression failure, exact baseline vs current collector.

No external target or customer credentials. The generated certificate is trusted
explicitly, and only a temporary loopback listener receives synthetic cookies.
"""

import argparse
import ipaddress
import json
import ssl
import subprocess
import tempfile
import threading
import types
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import SecretStr

from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import IdentityProfile, IdentityRequest, SessionProbe
from scopelens.identities import sessions
from scopelens.identities.readiness import collect_identity_readiness, evaluate_identity_readiness


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        assert self.path in {"/auerp/home", "/auerp/always-broken", "/auerp/redirect"}
        valid = self.headers.get("Cookie") == "sid=synthetic-owned-session"
        body = b'{"identity":"owned-student"}' if valid else b'{"identity":null}'
        encoding = self.headers.get("Accept-Encoding", "")
        broken = self.path == "/auerp/always-broken" or "gzip" in encoding
        self.server.receipts.append(
            {
                "path": self.path,
                "encoding": encoding,
                "valid_cookie": valid,
                "broken_compression": broken,
            }
        )
        self.send_response(302 if self.path == "/auerp/redirect" else 200 if valid else 401)
        self.send_header("Content-Type", "application/json")
        if broken:
            # Legacy compression filter labels uncompressed bytes as gzip.
            self.send_header("Content-Encoding", "gzip")
        if self.path == "/auerp/redirect":
            self.send_header("Location", "/outside-scope")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def run(output):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned-loopback-lab")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        (root / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "cert.pem", root / "key.pem")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.receipts = []
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        source = subprocess.check_output(
            ["git", "show", "d8b259a:backend/scopelens/identities/sessions.py"], text=True
        )
        legacy = types.ModuleType("owned_baseline_sessions")
        exec(compile(source, "baseline-identity-sessions.py", "exec"), legacy.__dict__)
        current = sessions.IdentitySessions.request
        results = []
        try:
            for variant, method, path, cookie in [
                ("before", legacy.IdentitySessions.request, "/auerp/home", True),
                ("after", current, "/auerp/home", True),
                ("invalid-session", current, "/auerp/home", False),
                ("unconditional-broken-body", current, "/auerp/always-broken", True),
                ("redirect", current, "/auerp/redirect", True),
            ]:
                sessions.IdentitySessions.request = method
                configuration = AssessmentConfiguration(
                    scope_version_id=uuid4(),
                    identities=(
                        IdentityProfile(
                            id="student",
                            role="student",
                            supplied_headers={"Cookie": "owned-cookie-ref"},
                            probe=SessionProbe(
                                request=IdentityRequest(
                                    url=f"https://127.0.0.1:{server.server_port}{path}"
                                ),
                                identity_pointer="/identity",
                                expected_identity="owned-student",
                            ),
                        ),
                    ),
                )
                records = []
                collect_identity_readiness(
                    configuration,
                    lambda _, cookie=cookie: SecretStr(
                        "sid=synthetic-owned-session" if cookie else "sid=invalid-owned-session"
                    ),
                    lambda _: httpx.Client(
                        verify=ssl.create_default_context(cafile=str(root / "cert.pem")),
                        trust_env=False,
                        timeout=3,
                        follow_redirects=False,
                    ),
                    lambda kind, record, records=records: records.append(record),
                    cancelled=lambda: False,
                )
                record = records[0]
                assert len(records) == 1
                verified = evaluate_identity_readiness(
                    configuration.identities[0],
                    record,
                    configuration_binding=record["configuration_binding"],
                )
                if variant == "after":
                    assert record["state"] == "verified" and verified
                else:
                    assert record["state"] == "blocked" and not verified
                if variant == "before":
                    assert (
                        record["reason"] == "identity_probe_transport_unavailable"
                        and record["status"] is None
                        and record["transport_phase"] == "response_body_decode"
                    )
                if variant == "unconditional-broken-body":
                    assert (
                        record["transport_phase"] == "response_body_decode"
                        and record["response_status"] == 200
                        and record["transport_error"] == "decoding"
                    )
                if variant == "redirect":
                    assert record["reason"] == "identity_probe_redirect_not_followed"
                results.append({"variant": variant, "verified": verified, "record": record})
            assert len(server.receipts) == 5
            assert all(r["path"].startswith("/auerp/") for r in server.receipts)
        finally:
            sessions.IdentitySessions.request = current
            server.shutdown()
            server.server_close()
        output.mkdir(parents=True, exist_ok=True)
        receipt = {
            "baseline_commit": "d8b259a",
            "fixture": "owned-loopback-https-compression",
            "customer_root_cause_established": False,
            "results": results,
            "server_receipts": server.receipts,
        }
        (output / "compression-receipt.json").write_text(json.dumps(receipt, indent=2))
        print(
            json.dumps(
                {
                    "cases": len(results),
                    "baseline_transport_failure": True,
                    "fixed_readiness_verified": True,
                    "customer_root_cause_established": False,
                }
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("runs/discovery-auth/owned-https"))
    run(parser.parse_args().output)
