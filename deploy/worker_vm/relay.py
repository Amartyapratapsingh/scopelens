"""Fixed TCP transport to the host's enforcing proxy; no configurable destination."""

import select
import socket
import socketserver


class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.create_connection(("192.168.5.2", 8098), timeout=10) as upstream:
            peers = {self.request: upstream, upstream: self.request}
            while True:
                ready, _, _ = select.select(list(peers), [], [], 30)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    peers[source].sendall(data)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32


if __name__ == "__main__":
    with Server(("0.0.0.0", 8080), Relay) as server:
        server.serve_forever()
