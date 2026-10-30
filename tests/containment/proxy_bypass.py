#!/usr/bin/env python3
"""CONNECT-bypass containment test (Build Plan §5.3, §8 "Containment/scope").

Runs **inside the proxy image**, which is the only environment with mitmproxy available
(`docs/OPEN_QUESTIONS.md` Q-9), and needs nothing else — no database, no lab stack.

WHAT THIS REPRODUCES
====================

An earlier version of the addon hooked only `request`. mitmproxy connects upstream
*eagerly* on CONNECT, and a tunnel carrying bytes that are neither TLS nor HTTP is passed
through as raw TCP. The `request` hook never fires for such a tunnel, so the broker was
never consulted and a worker could reach anything the proxy could reach — including
unauthenticated Redis and PostgreSQL on the control network.

This test is the reproduction. It stands up:

* a **raw TCP canary** that records every connection and every byte it receives
* an **HTTP canary** for the legitimate inner-request path
* a **stub policy service** whose answer the test controls (allow / deny / unreachable)
* a real `mitmdump` running the real addon with `connection_strategy=lazy`

and then asserts that the canaries never see a connection the policy did not allow.

The stub exists so the test can be deterministic and offline. The *decisions* it returns
are trivial; what is under test is whether the proxy consults it at all, and whether a
denied or unroutable connection can still reach the target. Those are proxy-level facts,
so a stub is the right instrument — the policy rules themselves are covered by
`tests/integration/test_broker.py`.

Exit code 0 means every case passed.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ADDON = Path("/addons/scope_enforcer.py")
STARTUP_TIMEOUT = 45.0

_failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}{f' — {detail}' if detail else ''}")
        _failures.append(label)


# --- Canaries ------------------------------------------------------------------------


class Canary:
    """A TCP listener that records connections and bytes. Never replies."""

    def __init__(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(8)
        self.port = self._server.getsockname()[1]
        self.connections = 0
        self.payloads: list[bytes] = []
        self._stop = threading.Event()
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        self._server.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._drain, args=(conn,), daemon=True).start()

    def _drain(self, conn: socket.socket) -> None:
        conn.settimeout(2.0)
        try:
            data = conn.recv(4096)
            if data:
                self.payloads.append(data)
        except (TimeoutError, OSError):
            pass
        finally:
            conn.close()

    def reset(self) -> None:
        self.connections = 0
        self.payloads.clear()

    def close(self) -> None:
        self._stop.set()
        self._server.close()


_http_canary_requests = 0
_http_canary_body = b"inner-request-reached-canary"


class HttpCanaryHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        global _http_canary_requests
        _http_canary_requests += 1
        body = _http_canary_body
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        """Silence the default stderr logging."""


class HttpCanary:
    def __init__(self) -> None:
        global _http_canary_requests
        _http_canary_requests = 0
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), HttpCanaryHandler)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def requests(self) -> int:
        return _http_canary_requests

    @requests.setter
    def requests(self, value: int) -> None:
        global _http_canary_requests
        _http_canary_requests = value

    def _serve(self) -> None:
        self._server.serve_forever(poll_interval=0.2)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


# --- Stub policy service -------------------------------------------------------------


class PolicyStub:
    """Returns a decision the test controls. Records what it was asked about."""

    def __init__(self) -> None:
        self.mode = "allow"  # allow | deny | deny_host
        self.wait_seconds = 0
        self.allowed_host = "127.0.0.1"
        self.seen: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("content-length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                stub.seen.append(payload)

                if stub.mode == "deny":
                    decision = {"allowed": False, "reason": "stub_denied", "detail": "deny-all"}
                elif stub.mode == "deny_host" and payload.get("host") != stub.allowed_host:
                    decision = {"allowed": False, "reason": "host_not_in_scope", "detail": "stub"}
                else:
                    decision = {
                        "allowed": True,
                        "reason": "allowed",
                        "addresses": ["127.0.0.1"],
                        "detail": "stub",
                        "limits": {"wait_seconds": stub.wait_seconds},
                    }
                    if self.path.endswith("/zap-task/authorize"):
                        decision["limits"]["task_remaining_seconds"] = "10"

                body = json.dumps(decision).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                """Silence the default stderr logging."""

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True
        ).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


# --- The proxy under test ------------------------------------------------------------


class Proxy:
    """A real mitmdump running the real addon."""

    def __init__(self, policy_url: str, confdir: Path) -> None:
        self.port = _free_port()
        self._log = confdir / "proxy.log"
        self._log_handle = self._log.open("w")
        self._process = subprocess.Popen(
            [
                "mitmdump",
                "-q",
                "-s",
                str(ADDON),
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                str(self.port),
                "--ssl-insecure",
                # The fix. Without this, mitmproxy opens the upstream connection on
                # CONNECT, so the decision at that point is already too late.
                "--set",
                "connection_strategy=lazy",
                # Raw TCP passthrough off, as in deploy/docker-compose.dev.yml. This is
                # the option that stops a non-TLS tunnel from being relayed.
                "--set",
                "rawtcp=false",
                "--set",
                f"confdir={confdir}",
            ],
            env={**os.environ, "SCOPELENS_POLICY_URL": policy_url},
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )

    def wait_ready(self) -> bool:
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                return False
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
                return True
            except OSError:
                time.sleep(0.25)
        return False

    def log(self) -> str:
        self._log_handle.flush()
        return self._log.read_text(errors="replace")

    def stop(self) -> None:
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
        self._log_handle.close()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- Probes --------------------------------------------------------------------------


def connect_through(
    proxy_port: int, target_port: int, *, token: str = "", proxy_auth: bool = False
):
    """Send a CONNECT. Returns (status_line, socket_or_None)."""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    lines = [f"CONNECT 127.0.0.1:{target_port} HTTP/1.1", f"Host: 127.0.0.1:{target_port}"]
    if token:
        if proxy_auth:
            credential = base64.b64encode(f"{token}:".encode()).decode()
            lines.append(f"Proxy-Authorization: Basic {credential}")
        else:
            lines.append(f"x-scopelens-egress: {token}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    sock.settimeout(8)

    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(1)
            if not chunk:
                break
            buf += chunk
    except (TimeoutError, OSError):
        pass

    status = buf.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200 " in status:
        return status, sock
    sock.close()
    return status, None


def raw_http_through(
    proxy_port: int,
    canary_port: int,
    *,
    token: str,
    host: str = "127.0.0.1",
    host_header: str | None = None,
) -> str:
    """A plain HTTP request through the proxy (no CONNECT), returning the response."""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    request = (
        f"GET http://{host}:{canary_port}/ HTTP/1.1\r\n"
        f"Host: {host_header or f'{host}:{canary_port}'}\r\n"
        f"x-scopelens-egress: {token}\r\n"
        "Connection: close\r\n\r\n"
    )
    sock.sendall(request.encode())
    sock.settimeout(10)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (TimeoutError, OSError):
        pass
    finally:
        sock.close()
    return buf.decode(errors="replace")


# --- Cases ---------------------------------------------------------------------------


def run() -> int:
    global _http_canary_body
    if not ADDON.exists():
        print(f"FAIL: addon not mounted at {ADDON}")
        return 1

    confdir = Path(tempfile.mkdtemp(prefix="scopelens-proxy-test-"))
    raw_canary = Canary()
    http_canary = HttpCanary()
    stub = PolicyStub()

    try:
        print("case 1: deny-all policy — no tunnel may open, no bytes may arrive")
        stub.mode = "deny"
        proxy = Proxy(stub.url, confdir)
        if not proxy.wait_ready():
            print(f"FAIL: proxy did not start\n{proxy.log()}")
            return 1
        try:
            raw_canary.reset()

            status, _ = connect_through(proxy.port, raw_canary.port)
            check("CONNECT with no token is refused", "403" in status, status)

            status, sock = connect_through(
                proxy.port, raw_canary.port, token="a-real-looking-token"
            )
            check("CONNECT with a token the policy denies is refused", "403" in status, status)
            if sock:
                sock.close()

            # The original reproduction: CONNECT then non-HTTP bytes. With the policy
            # set to deny, none of this may reach the canary.
            status, _ = connect_through(proxy.port, raw_canary.port, token="denied-token")
            check(
                "denied CONNECT never reaches the canary",
                raw_canary.connections == 0,
                f"{raw_canary.connections} connection(s)",
            )
            check(
                "no raw bytes reached the canary",
                not raw_canary.payloads,
                f"{raw_canary.payloads!r}",
            )
        finally:
            proxy.stop()

        print("case 2: unreachable policy — the original bypass, must stay closed")
        # Port 9 (discard) is never listening, so every decision call fails.
        proxy = Proxy("http://127.0.0.1:9", confdir)
        if not proxy.wait_ready():
            print(f"FAIL: proxy did not start\n{proxy.log()}")
            return 1
        try:
            raw_canary.reset()
            http_canary.requests = 0

            status, _ = connect_through(proxy.port, raw_canary.port, token="tok", proxy_auth=True)
            check(
                "CONNECT is refused when the policy service is unreachable", "403" in status, status
            )

            # Send the payload anyway, exactly as the original probe did.
            sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            sock.sendall(
                f"CONNECT 127.0.0.1:{raw_canary.port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{raw_canary.port}\r\n"
                f"x-scopelens-egress: tok\r\n\r\n".encode()
            )
            sock.settimeout(5)
            with contextlib.suppress(OSError):
                sock.recv(4096)
            with contextlib.suppress(OSError):
                sock.sendall(b"RAW-TCP-PAYLOAD-NOT-HTTP\r\n\r\n")
            sock.close()
            time.sleep(1.0)

            check(
                "zero connections reached the canary",
                raw_canary.connections == 0,
                f"{raw_canary.connections}",
            )
            check(
                "zero payloads reached the canary",
                not raw_canary.payloads,
                f"{raw_canary.payloads!r}",
            )

            response = raw_http_through(proxy.port, http_canary.port, token="tok")
            check(
                "an inner HTTP request is refused too",
                "403" in response.split("\r\n", 1)[0],
                response.split("\r\n", 1)[0],
            )
            check("the HTTP canary saw no request", http_canary.requests == 0)
        finally:
            proxy.stop()

        print("case 3: allowed policy — the legitimate path still works")
        stub.mode = "allow"
        proxy = Proxy(stub.url, confdir)
        if not proxy.wait_ready():
            print(f"FAIL: proxy did not start\n{proxy.log()}")
            return 1
        try:
            raw_canary.reset()
            http_canary.requests = 0

            status, sock = connect_through(proxy.port, raw_canary.port, token="tok")
            check("an allowed CONNECT succeeds", "200" in status, status)

            if sock:
                # A tunnel that carries non-HTTP bytes is killed, not relayed.
                with contextlib.suppress(OSError):
                    sock.sendall(b"RAW-TCP-PAYLOAD-NOT-HTTP\r\n\r\n")
                time.sleep(1.5)
                sock.close()

                check(
                    "raw TCP through an allowed tunnel never reaches the canary",
                    not raw_canary.payloads,
                    f"{raw_canary.payloads!r}",
                )

            response = raw_http_through(proxy.port, http_canary.port, token="tok")
            check(
                "an allowed inner HTTP request is served",
                "200" in response.split("\r\n", 1)[0],
                response.split("\r\n", 1)[0],
            )
            check("the HTTP canary saw the request", http_canary.requests >= 1)
            before = http_canary.requests
            response = raw_http_through(
                proxy.port, http_canary.port, token="tok", host_header="other-tenant.invalid"
            )
            check(
                "conflicting Host cannot select another virtual host at an approved address",
                "403" in response.split("\r\n", 1)[0] and http_canary.requests == before,
            )
            response = raw_http_through(
                proxy.port, http_canary.port, token="tok", host="does-not-resolve.invalid"
            )
            check(
                "upstream uses approved address without another DNS resolution",
                "inner-request-reached-canary" in response,
            )
            _http_canary_body = b"X" * (2 * 1024 * 1024)
            response = raw_http_through(proxy.port, http_canary.port, token="tok")
            check("body transfer stops at the broker cap", response.count("X") <= 1048576)
            _http_canary_body = b"inner-request-reached-canary"
            response = raw_http_through(proxy.port, http_canary.port, token="tok")
            check(
                "body-cap termination releases its concurrency slot",
                "inner-request-reached-canary" in response,
            )

            response = raw_http_through(proxy.port, http_canary.port, token="")
            check(
                "an inner request with no token is refused",
                "403" in response.split("\r\n", 1)[0],
                response.split("\r\n", 1)[0],
            )

            # With rawtcp disabled the raw-TCP layer is never selected, so no kill is
            # expected. What matters is that the payload did not arrive, asserted above.
            check(
                "the proxy did not select a raw TCP layer",
                "killing raw TCP flow" not in proxy.log(),
                "a raw TCP flow appeared despite rawtcp=false",
            )
        finally:
            proxy.stop()

        print("case 4: the policy sees host and port, and its denial is honoured")
        stub.mode = "deny_host"
        stub.allowed_host = "not-what-we-connect-to"
        stub.seen.clear()
        proxy = Proxy(stub.url, confdir)
        if not proxy.wait_ready():
            print(f"FAIL: proxy did not start\n{proxy.log()}")
            return 1
        try:
            status, _ = connect_through(proxy.port, raw_canary.port, token="tok")
            check("CONNECT to a host the policy denies is refused", "403" in status, status)

            connects = [s for s in stub.seen if s.get("method") == "CONNECT"]
            check("the policy was asked about the CONNECT", bool(connects))
            if connects:
                check(
                    "the CONNECT carried the target host",
                    connects[0].get("host") == "127.0.0.1",
                    str(connects[0].get("host")),
                )
                check(
                    "the CONNECT carried the target port",
                    connects[0].get("port") == raw_canary.port,
                    str(connects[0].get("port")),
                )
                check(
                    "the CONNECT carried the egress token", connects[0].get("egress_token") == "tok"
                )
        finally:
            proxy.stop()

    finally:
        raw_canary.close()
        http_canary.close()
        stub.close()
        shutil.rmtree(confdir, ignore_errors=True)

    print()
    if _failures:
        print(f"FAIL — {len(_failures)} case(s) failed:")
        for name in _failures:
            print(f"  - {name}")
        return 1

    print("PASS — the CONNECT bypass is closed and raw TCP never reaches a target")
    return 0


if __name__ == "__main__":
    sys.exit(run())
