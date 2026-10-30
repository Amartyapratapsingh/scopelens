"""Real HTTPS connection-reuse regression. Entire test is local to the proxy container."""

import http.client
import ipaddress
import ssl
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from proxy_bypass import PolicyStub, Proxy


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.host_headers.append(self.headers.get("Host"))
        if self.path == "/stall":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"partial")
            self.wfile.flush()
            time.sleep(30)
            return
        body = b"" if self.path == "/missing" else b"fixture body"
        self.send_response(404 if self.path == "/missing" else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
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
        server_names = []
        context.set_servername_callback(lambda socket, name, context: server_names.append(name))
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.host_headers = []
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        policy = PolicyStub()
        proxy = Proxy(policy.url, root)
        connection = None
        try:
            assert proxy.wait_ready()
            # Both clients abandon an upstream that accepted a request but never replies.
            held = []
            for _ in range(2):
                stalled = http.client.HTTPSConnection(
                    "127.0.0.1", proxy.port, timeout=2, context=ssl._create_unverified_context()
                )
                stalled.set_tunnel(
                    "fixture.invalid",
                    server.server_port,
                    headers={"x-scopelens-egress": "local-test"},
                )
                stalled.request("GET", "/stall", headers={"x-scopelens-egress": "local-test"})
                time.sleep(0.2)
                held.append(stalled)
            time.sleep(11)
            # The certificate is a disposable local fixture; this never accesses the internet.
            connection = http.client.HTTPSConnection(
                "127.0.0.1", proxy.port, timeout=3, context=ssl._create_unverified_context()
            )
            connection.set_tunnel(
                "fixture.invalid", server.server_port, headers={"x-scopelens-egress": "local-test"}
            )
            for path in ["/", "/missing", "/style.css", "/missing", "/"] * 3:
                started = time.monotonic()
                connection.request("GET", path, headers={"x-scopelens-egress": "local-test"})
                response = connection.getresponse()
                body = response.read()
                assert response.status == (404 if path == "/missing" else 200)
                assert body == (b"" if path == "/missing" else b"fixture body")
                print(
                    "HTTP/1.1",
                    path,
                    response.status,
                    round(time.monotonic() - started, 3),
                    flush=True,
                )
            assert set(server_names) == {"fixture.invalid"}, server_names
            assert set(server.host_headers) == {f"fixture.invalid:{server.server_port}"}
            assert len(server_names) <= 3, "healthy requests must reuse their pinned connection"
            print("Pinned destination retained HTTP Host/SNI and reused one healthy connection")
        finally:
            if connection:
                connection.close()
            for stalled in held:
                stalled.close()
            proxy.stop()
            policy.close()
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
