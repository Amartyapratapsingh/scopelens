"""Real token-only CONNECT and signed HTTPS inner GET with broker CA verification."""

import base64
import http.client
import ipaddress
import json
import ssl
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from proxy_bypass import PolicyStub, Proxy


def main():
    observed = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append(dict(self.headers))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.invalid")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("fixture.invalid"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        (root / "target.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / "target.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "target.crt", root / "target.key")
        target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
        target.socket = context.wrap_socket(target.socket, server_side=True)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        policy = PolicyStub()
        proxy = Proxy(policy.url, root)
        connection = None
        try:
            assert proxy.wait_ready()
            # Trust the proxy CA and require the tunnel destination's hostname.
            trusted = ssl.create_default_context(cafile=str(root / "mitmproxy-ca-cert.pem"))
            connection = http.client.HTTPSConnection(
                "127.0.0.1", proxy.port, timeout=5, context=trusted
            )
            connection.set_tunnel(
                "fixture.invalid",
                target.server_port,
                headers={"x-scopelens-egress": "synthetic-token"},
            )
            signed = base64.b64encode(
                json.dumps({"signature": "synthetic-fixture"}).encode()
            ).decode()
            connection.request(
                "GET",
                "/xss?q=scopelens",
                headers={"x-scopelens-egress": "synthetic-token", "x-scopelens-zap-task": signed},
            )
            response = connection.getresponse()
            assert response.status == 200 and response.read() == b"ok"
            assert response.getheader("x-scopelens-zap-decision") == "allow"
            requests = [row for row in policy.seen if "signed" in row]
            assert len(requests) == 1
            assert (
                requests[0]["url"]
                == f"https://fixture.invalid:{target.server_port}/xss?q=scopelens"
            )
            assert not any(name.lower().startswith("x-scopelens") for name in observed[0])
            assert not any(name.lower() == "proxy-authorization" for name in observed[0])
            assert len(observed) == 1
            print(
                "PASS: verified broker CA/hostname, token-only CONNECT, task-authorized HTTPS GET, stripped headers"
            )
        finally:
            if connection:
                connection.close()
            proxy.stop()
            policy.close()
            target.shutdown()
            target.server_close()


if __name__ == "__main__":
    main()
