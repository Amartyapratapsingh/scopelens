"""Host-side dedicated VM gateway. Generated stdout is always untrusted."""

import hashlib
import hmac
import json
import os
import selectors
import ssl
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Literal
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from scopelens.api.deps import AppSettings
from scopelens.security.redaction import redact_text

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
VM = "scopelens-sandbox"


class ScriptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: uuid.UUID
    language: Literal["python", "bash"]
    source: str = Field(min_length=1, max_length=32000)
    artifacts: dict
    network: Literal["none", "lab-proxy"] = "none"
    authority: Literal["lab", "production"] = "lab"
    egress_token: str | None = Field(default=None, repr=False)
    proxy_ca_pem: str | None = Field(default=None, max_length=10000, repr=False)

    @model_validator(mode="after")
    def bounded(self):
        if len(json.dumps(self.artifacts).encode()) > 1_000_000:
            raise ValueError("artifact cap exceeded")
        if self.network == "lab-proxy" and (
            self.authority != "lab" or not self.egress_token or not self.proxy_ca_pem
        ):
            raise ValueError("networked scripts require an explicit lab capability")
        return self


def vm_command(unit):
    return [
        "limactl",
        "shell",
        VM,
        "--",
        "sudo",
        "systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--unit=" + unit,
        "-p",
        "DynamicUser=yes",
        "-p",
        "PrivateNetwork=yes",
        "-p",
        "PrivateTmp=yes",
        "-p",
        "ProtectSystem=strict",
        "-p",
        "ProtectHome=yes",
        "-p",
        "ProtectProc=invisible",
        "-p",
        "NoNewPrivileges=yes",
        "-p",
        "PrivateDevices=yes",
        "-p",
        "ProtectKernelTunables=yes",
        "-p",
        "ProtectKernelModules=yes",
        "-p",
        "ProtectControlGroups=yes",
        "-p",
        "RestrictSUIDSGID=yes",
        "-p",
        "LockPersonality=yes",
        "-p",
        "CapabilityBoundingSet=",
        "-p",
        "RestrictAddressFamilies=AF_UNIX",
        "-p",
        "MemoryMax=256M",
        "-p",
        "TasksMax=32",
        "-p",
        "RuntimeMaxSec=15s",
        "-p",
        "KillMode=control-group",
        "-p",
        "TimeoutStopSec=1s",
        "/usr/bin/python3",
        "-I",
        "/opt/scopelens/guest_runner.py",
    ]


def execute(request):
    unit = "scopelens-" + request.scan_id.hex + "-" + uuid.uuid4().hex[:8]
    started = time.monotonic()
    process = subprocess.Popen(
        vm_command(unit), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    initial = {"language": request.language, "source": request.source}
    pending_input = bytearray(
        json.dumps(initial).encode() + b"\n" + json.dumps(request.artifacts).encode() + b"\n"
    )
    os.set_blocking(process.stdin.fileno(), False)
    rpc_pending = bytearray()
    rpc_count = 0
    rpc_results = []
    output = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
    stopped = False
    try:
        while selector.get_map():
            if time.monotonic() - started > 20 or sum(map(len, output.values())) >= 1_048_576:
                stopped = True
                break
            for key, _ in selector.select(0.1):
                if key.data == "stdin":
                    try:
                        count = os.write(process.stdin.fileno(), pending_input[:8192])
                        del pending_input[:count]
                    except BrokenPipeError:
                        pending_input.clear()
                    except BlockingIOError:
                        continue
                    if not pending_input:
                        selector.unregister(process.stdin)
                        if request.network == "none" or process.poll() is not None:
                            process.stdin.close()
                    continue
                chunk = key.fileobj.read1(8192)
                if chunk:
                    output[key.data].extend(chunk)
                    if key.data == "stdout" and request.network == "lab-proxy":
                        rpc_pending.extend(chunk)
                        while b"\n" in rpc_pending:
                            line, _, remainder = rpc_pending.partition(b"\n")
                            rpc_pending = bytearray(remainder)
                            if line.startswith(b"SCOPELENS_HTTP "):
                                rpc_count += 1
                                reply = proxy_request(request, line[15:], rpc_count)
                                rpc_results.append(
                                    {"state": reply.get("state"), "status": reply.get("status")}
                                )
                                pending_input.extend(json.dumps(reply).encode() + b"\n")
                                try:
                                    selector.get_key(process.stdin)
                                except KeyError:
                                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    selector.unregister(key.fileobj)
    finally:
        if stopped:
            subprocess.run(
                ["limactl", "shell", VM, "--", "sudo", "systemctl", "stop", unit],
                capture_output=True,
                timeout=5,
            )
            process.kill()
        process.wait(timeout=5)
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    return {
        "state": "limited" if stopped else "completed" if process.returncode == 0 else "error",
        "exit_code": process.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "source_hash": hashlib.sha256(request.source.encode()).hexdigest(),
        "stdout": redact_text(output["stdout"].decode("utf-8", "replace"))[:65536],
        "stderr": redact_text(output["stderr"].decode("utf-8", "replace"))[:4096],
        "trusted": False,
        "origin": "untrusted_observation",
        "boundary": "dedicated-lima-vz-systemd-v1",
        "network": request.network,
        "proxy_requests": rpc_results,
    }


@app.post("/execute")
def run(request: ScriptRequest, settings: AppSettings, authorization: str = Header(default="")):
    secret = settings.session_secret.get_secret_value() if settings.session_secret else ""
    if not secret or not hmac.compare_digest(authorization, "Bearer " + secret):
        raise HTTPException(403, "sandbox gateway denied")
    try:
        return execute(request)
    except (OSError, subprocess.SubprocessError):
        raise HTTPException(503, "dedicated sandbox unavailable") from None


def proxy_request(request, raw, count):
    if count > 3:
        return {"state": "denied", "reason": "script request budget"}
    try:
        operation = json.loads(raw)
        if set(operation) != {"url", "method"} or operation["method"] not in {"GET", "HEAD"}:
            return {"state": "denied", "reason": "reviewed RPC accepts GET/HEAD only"}
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / "ca.pem"
            ca.write_text(request.proxy_ca_pem)
            context = ssl.create_default_context(cafile=str(ca))
            proxy = "http://" + quote(request.egress_token, safe="") + ":@127.0.0.1:8098"
            with (
                httpx.Client(
                    proxy=proxy, verify=context, trust_env=False, timeout=5, follow_redirects=False
                ) as client,
                client.stream(
                    operation["method"],
                    operation["url"],
                    headers={"x-scopelens-egress": request.egress_token},
                ) as response,
            ):
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk[: max(0, 65536 - len(content))])
                    if len(content) >= 65536:
                        break
                return {
                    "state": "observed",
                    "status": response.status_code,
                    "body": redact_text(content.decode("utf-8", "replace")),
                    "headers": {
                        k: v
                        for k, v in response.headers.items()
                        if k
                        in {"content-type", "content-security-policy", "x-content-type-options"}
                    },
                }
    except httpx.ProxyError:
        return {"state": "denied", "reason": "tunnel refused by proxy"}
    except (ValueError, KeyError, httpx.HTTPError, OSError):
        return {"state": "error", "reason": "proxy RPC unavailable"}
