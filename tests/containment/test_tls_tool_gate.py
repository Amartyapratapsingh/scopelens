import socket
from contextlib import closing

import pytest

from scopelens.broker.tls_tool import TLSConnectGate


@pytest.mark.parametrize(
    "header", [b"CONNECT wrong.test:443 HTTP/1.0\n\n", b"GET / HTTP/1.1\r\n\r\n"]
)
def test_wrong_destination_and_non_connect_never_open_canary(header):
    with closing(socket.socket()) as canary:
        canary.bind(("127.0.0.1", 0))
        canary.listen()
        canary.settimeout(0.15)
        with TLSConnectGate(
            "allowed.test", canary.getsockname()[1], lambda: "127.0.0.1", lambda: True
        ) as gate:
            with socket.create_connection(("127.0.0.1", gate.server.server_address[1])) as client:
                client.sendall(header)
                assert client.recv(100) == b""
            with pytest.raises(TimeoutError):
                canary.accept()


def test_denied_admission_never_connects():
    def deny():
        raise RuntimeError("denied")

    with closing(socket.socket()) as canary:
        canary.bind(("127.0.0.1", 0))
        canary.listen()
        canary.settimeout(0.15)
        port = canary.getsockname()[1]
        with TLSConnectGate("allowed.test", port, deny, lambda: True) as gate:
            with socket.create_connection(("127.0.0.1", gate.server.server_address[1])) as client:
                client.sendall(f"CONNECT allowed.test:{port} HTTP/1.0\n\n".encode())
                assert client.recv(100) == b""
            with pytest.raises(TimeoutError):
                canary.accept()


def test_approved_lf_connect_reaches_only_pinned_address_and_revocation_closes():
    live = [True]
    with closing(socket.socket()) as canary:
        canary.bind(("127.0.0.1", 0))
        canary.listen()
        canary.settimeout(2)
        port = canary.getsockname()[1]
        with (
            TLSConnectGate("unresolvable.test", port, lambda: "127.0.0.1", lambda: live[0]) as gate,
            socket.create_connection(("127.0.0.1", gate.server.server_address[1])) as client,
        ):
            client.settimeout(2)
            client.sendall(f"CONNECT unresolvable.test:{port} HTTP/1.0\n\n".encode())
            upstream, _ = canary.accept()
            with upstream:
                assert b"200" in client.recv(200)
                live[0] = False
                assert client.recv(200) == b""
