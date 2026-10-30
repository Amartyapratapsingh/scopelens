"""Loopback proxy bridge: attach CONNECT credentials before forwarding to the broker.

Chromium's proxy authentication challenge behavior differs from httpx. This bridge adds
credentials on the first CONNECT; the upstream broker still authorizes every destination.
It has exactly one upstream, supplied by the trusted supervisor, and no direct target path.
"""

import base64
import select
import socket
import socketserver
import threading
from urllib.parse import urlsplit


class Bridge:
    def __init__(self, upstream: str, token: str):
        target = urlsplit(upstream)
        self.upstream = (target.hostname, target.port or 8080)
        self.auth = base64.b64encode((token + ":").encode()).decode()
        bridge = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(15)
                data = b""
                while b"\r\n\r\n" not in data:
                    part = self.request.recv(4096)
                    if not part or len(data) > 65536:
                        return
                    data += part
                header, body = data.split(b"\r\n\r\n", 1)
                lines = header.split(b"\r\n")
                lines = [
                    line for line in lines if not line.lower().startswith(b"proxy-authorization:")
                ]
                lines.append(f"Proxy-Authorization: Basic {bridge.auth}".encode())
                with socket.create_connection(bridge.upstream, timeout=15) as remote:
                    remote.sendall(b"\r\n".join(lines) + b"\r\n\r\n" + body)
                    while True:
                        ready, _, _ = select.select([self.request, remote], [], [], 30)
                        if not ready:
                            return
                        for source in ready:
                            part = source.recv(65536)
                            if not part:
                                return
                            (remote if source is self.request else self.request).sendall(part)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
