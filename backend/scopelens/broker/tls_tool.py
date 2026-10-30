"""Loopback-only testssl transport, separately admitted for each real connection.

Only the trusted TLS lane starts this reviewed command. Workers cannot access the listener.
The fixed protocol-only command and destination are not caller-provided shell text.
"""

import contextlib
import hashlib
import os
import re
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from scopelens.adapters.scanners import ScannerObservation, ScannerResult, parse_output


def measure_negotiation(host, port, gate, *, timeout):
    """OpenSSL supports extension offers through CONNECT where testssl refuses them.

    A completed handshake establishes the observed negotiation only. Failure, missing
    extension support and TLS-1.2-only offer rejection remain incomplete, never N/A.
    """
    observations, errors, assessed = [], [], []
    for rule, option in [("ALPN", "-alpn"), ("NPN", "-nextprotoneg")]:
        command = [
            "/usr/bin/openssl",
            "s_client",
            "-proxy",
            gate.proxy,
            "-connect",
            f"{host}:{port}",
            "-servername",
            host,
            option,
            "h2,http/1.1",
        ]
        if rule == "NPN":
            command.append("-tls1_2")
        try:
            process = subprocess.run(
                command,
                input=b"",
                capture_output=True,
                timeout=timeout,
                start_new_session=True,
            )
        except (OSError, subprocess.TimeoutExpired):
            errors.append(f"{rule} native measurement unavailable or timed out")
            continue
        raw = (process.stdout + process.stderr).decode("utf-8", "replace")
        handshake = re.search(r"(?:New|Reused), TLSv\S+, Cipher is (?!\(NONE\))\S+", raw)
        if process.returncode != 0 or not handshake or not gate.live():
            errors.append(f"{rule} native handshake incomplete")
            continue
        lines = [
            line.strip()
            for line in raw.splitlines()
            if (
                "ALPN protocol:" in line
                or "No ALPN negotiated" in line
                or "Next protocol:" in line
                or "Protocols advertised by server:" in line
            )
        ]
        assessed.append(rule)
        observations.append(
            ScannerObservation(
                tool="testssl",
                tool_version="3.2.4",
                rule_id=rule,
                title=f"{rule} native negotiation inventory",
                reported_severity="informational",
                locations=[f"{host}:{port}"],
                evidence="; ".join([handshake.group(0), *lines])
                + "; offered h2,http/1.1 through per-connection admitted TLS gate",
                output_hash=hashlib.sha256(raw.encode()).hexdigest(),
            )
        )
    return observations, errors, assessed


class TLSConnectGate:
    def __init__(self, host, port, admit, live, max_connections=40):
        self.host, self.port, self.admit, self.live = host, port, admit, live
        self.count = 0
        self.permit = threading.Semaphore(1)
        self.lock = threading.Lock()
        self.sockets = set()
        gate = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with gate.permit:
                    self.relay()

            def relay(self):
                self.request.settimeout(5)
                data = b""
                try:
                    while b"\r\n\r\n" not in data and b"\n\n" not in data:
                        part = self.request.recv(4096)
                        if not part or len(data) > 8192:
                            return
                        data += part
                    target = data.splitlines()[0].decode().split()
                    if len(target) != 3 or target[0] != "CONNECT":
                        return
                    with gate.lock:
                        if gate.count >= max_connections:
                            return
                        gate.count += 1
                    address = gate.admit()
                    if target[1] not in {f"{host}:{port}", f"{address}:{port}"}:
                        return
                    if not gate.live():
                        return
                    with socket.create_connection((address, port), timeout=5) as upstream:
                        with gate.lock:
                            gate.sockets.update([upstream, self.request])
                        self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        started = time.monotonic()
                        received = 0
                        last_check = 0
                        while time.monotonic() - started < 10:
                            now = time.monotonic()
                            if now - last_check >= 0.5:
                                if not gate.live():
                                    return
                                last_check = now
                            ready, _, _ = select.select([upstream, self.request], [], [], 0.2)
                            for source in ready:
                                chunk = source.recv(16384)
                                if not chunk:
                                    return
                                received += len(chunk)
                                if received > 1024 * 1024:
                                    return
                                (upstream if source is self.request else self.request).sendall(
                                    chunk
                                )
                except (OSError, ValueError, RuntimeError):
                    return
                finally:
                    with gate.lock:
                        gate.sockets.discard(self.request)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    @property
    def proxy(self):
        return f"127.0.0.1:{self.server.server_address[1]}"

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        with self.lock:
            for sock in self.sockets:
                with contextlib.suppress(OSError):
                    sock.close()
        self.thread.join(2)


def run_testssl(host, port, admit, live, *, binary="/opt/testssl/testssl.sh", timeout=90):
    if not Path(binary).is_file():
        return ScannerResult(
            tool="testssl",
            version="3.2.4",
            state="not_tested",
            errors=["testssl binary unavailable"],
        )
    with tempfile.TemporaryDirectory(prefix="scopelens-tls-") as folder:
        output = Path(folder) / "testssl.json"
        with TLSConnectGate(host, port, admit, live) as gate:
            command = [
                binary,
                "--quiet",
                "--warnings",
                "batch",
                "--color",
                "0",
                "--openssl",
                "/usr/bin/openssl",
                "--proxy",
                gate.proxy,
                "--ip",
                "proxy",
                "--nodns",
                "none",
                "--protocols",
                "--jsonfile",
                str(output),
                f"{host}:{port}",
            ]
            environment = {
                **os.environ,
                "OPENSSL_TIMEOUT": "5",
                "CONNECT_TIMEOUT": "5",
                "TESTSSL_NO_DNS": "true",
                "TMPDIR": folder,
            }
            timed_out = False
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                start_new_session=True,
            )
            started = time.monotonic()
            while process.poll() is None:
                if not live() or time.monotonic() - started > timeout:
                    timed_out = live()
                    import signal

                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.2)
            code = process.wait()
            raw = output.read_text() if output.exists() else ""
            result = parse_output(
                "testssl",
                "3.2.4",
                raw[: 1024 * 1024],
                exit_code=code,
                truncated=len(raw) > 1024 * 1024,
                timed_out=timed_out,
                cancelled=not live(),
            )
            if not timed_out and live():
                remaining = timeout - (time.monotonic() - started)
                if remaining > 1:
                    observations, errors, assessed = measure_negotiation(
                        host, port, gate, timeout=min(5, remaining / 2)
                    )
                    result.observations.extend(observations)
                    result.errors = [
                        error
                        for error in result.errors
                        if not (
                            error == "not tested as proxies do not support proxying it"
                            and len(assessed) == 2
                        )
                    ]
                    result.errors.extend(errors)
                    # Warning IDs are not assessed checks. Only native successful
                    # handshake observations establish extension inventory completion.
                    result.assessed_rule_ids = [
                        rule for rule in result.assessed_rule_ids if rule not in {"ALPN", "NPN"}
                    ] + assessed
                    if code == 0 and not result.errors:
                        result.state = "completed"
            return result
