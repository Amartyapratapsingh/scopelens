import socket
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scopelens.broker.tls_lane import measure_tls


@contextmanager
def tls_server(tmp_path, *, hostname="localhost", expired=False, future=False):
    now = datetime.now(UTC)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ScopeLens test root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=1) if future else now - timedelta(days=3))
        .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    ca, cert, key_file = [tmp_path / n for n in ("ca.pem", "cert.pem", "key.pem")]
    ca.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key_file)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.1)
    stopped = threading.Event()

    def serve():
        while not stopped.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                with conn, context.wrap_socket(conn, server_side=True):
                    pass
            except ssl.SSLError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], ca
    finally:
        stopped.set()
        listener.close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    "options,valid",
    [
        ({}, True),
        ({"hostname": "wrong.test"}, False),
        ({"expired": True}, False),
        ({"future": True}, False),
    ],
)
def test_real_handshakes_validate_certificate_and_authorize_each_connection(
    tmp_path, options, valid
):
    calls = []

    def admit():
        calls.append(True)
        return "127.0.0.1"

    with tls_server(tmp_path, **options) as (port, ca):
        facts = measure_tls("localhost", port, ca_file=str(ca), authorize_handshake=admit)
    assert facts.certificate_verified is valid
    assert facts.not_after and facts.measured_at
    assert facts.legacy_protocols == {"TLSv1": "rejected", "TLSv1.1": "rejected"}
    assert len(calls) == (3 if valid else 4)


def test_denied_handshake_never_connects():
    def denied():
        raise OSError("denied")

    facts = measure_tls("localhost", 9, authorize_handshake=denied)
    assert not facts.reachable
    assert "denied" in facts.error
