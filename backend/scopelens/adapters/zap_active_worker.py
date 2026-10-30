"""Native ZAP in a network-none container; all target I/O uses file IPC.

Only loopback sockets exist here. The trusted supervisor supplies responses after
broker authorization. The scanner never receives a broker token or signing key.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from scopelens.adapters.zap_active import ActiveRulePin, ActiveRuleTask
from scopelens.domain.capabilities import canonical_sha256

IPC = Path("/tmp/zap-active-ipc")
NATIVE_CONFIG = {
    "version": "zap-active-query-v1",
    "strength": "LOW",
    "threshold": "MEDIUM",
    "injectable": 1,
    "rpc": 0,
    "threads": 1,
    "recurse": False,
    "method": "GET",
    "redirects": False,
}
CONFIG_SHA256 = canonical_sha256(NATIVE_CONFIG)


def publish_request(identity: str, request: dict):
    """Only a flushed, complete JSON request becomes visible to the IPC reader."""
    if not re.fullmatch(r"[0-9a-f]{32}", identity):
        raise ValueError("native request identity refused")
    serialized = json.dumps(request)
    if len(serialized.encode("utf-8")) > 16384:
        raise ValueError("native request size limit")
    root = IPC / "requests"
    temporary, destination = root / (identity + ".tmp"), root / (identity + ".json")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def native_url(task: ActiveRuleTask) -> str:
    """HTTP loopback representation; real HTTPS is performed only by the supervisor.

    Preserve the logical host and explicit HTTPS port. This is not TLS analysis:
    rule 40012 operates on the query and response body, through the existing IPC.
    """
    part = urlsplit(task.url)
    if part.scheme == "http":
        return task.url
    host = f"[{part.hostname}]" if ":" in part.hostname else part.hostname
    return part._replace(scheme="http", netloc=f"{host}:{part.port or 443}").geturl()


def logical_url(task: ActiveRuleTask, pin: ActiveRulePin, offered: str) -> str | None:
    """Map only the exact loopback representation; reject alternate origins/inputs."""
    projected = task.model_copy(update={"url": native_url(task)})
    if not projected.accepts("GET", offered, b"", pin):
        return None
    return urlsplit(task.url)._replace(query=urlsplit(offered).query).geturl()


def verify_binaries(pin: ActiveRulePin, root=Path("/opt/zap")):
    """Check the actual executable JAR and addon, not a version string."""
    if (
        pin.engine_version != "2.17.0"
        or not pin.addon_filename
        or not pin.addon_sha256
        or pin.rule_config_sha256 != CONFIG_SHA256
    ):
        raise ValueError("native engine/addon/config pin incomplete")
    for path, expected in (
        (root / "zap-2.17.0.jar", pin.engine_sha256),
        (root / "plugin" / pin.addon_filename, pin.addon_sha256),
    ):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("native engine/addon hash mismatch")


class Bridge(BaseHTTPRequestHandler):
    deadline = 0.0
    task: ActiveRuleTask
    pin: ActiveRulePin

    def log_message(self, *args):
        pass

    def do_GET(self):
        """Do not forward any scanner headers or accept relative/credentialed URLs."""
        part = urlsplit(self.path)
        if (
            part.scheme != "http"
            or not part.hostname
            or part.username
            or part.password
            or self.headers.get("Content-Length", "0") != "0"
            or self.headers.get("Transfer-Encoding")
            or self.headers.get("Authorization")
            or self.headers.get("Cookie")
            or len(self.path) > 4096
        ):
            self.send_error(403)
            return
        destination_url = logical_url(self.task, self.pin, self.path)
        if destination_url is None:
            self.send_error(403)
            return
        identity = secrets.token_hex(16)
        publish_request(identity, {"method": "GET", "url": destination_url})
        destination = IPC / "responses" / (identity + ".json")
        while time.monotonic() < self.deadline:
            if destination.exists():
                try:
                    response = json.loads(destination.read_bytes())
                    destination.unlink()
                    body = base64.b64decode(response["body"], validate=True)
                    self.send_response(response["status"])
                    for name, value in response["headers"].items():
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (OSError, ValueError, KeyError):
                    self.send_error(502)
                return
            time.sleep(0.02)
        self.send_error(504)

    def do_CONNECT(self):
        self.send_error(403)

    do_POST = do_CONNECT
    do_PUT = do_CONNECT
    do_DELETE = do_CONNECT
    do_PATCH = do_CONNECT
    do_HEAD = do_CONNECT
    do_OPTIONS = do_CONNECT


class NativeApiRefusal(ValueError):
    def __init__(self, operation, status, code=None):
        super().__init__(f"native API refused configuration: {operation} HTTP {status}")
        self.status = status
        self.code = code


def local_api(client, deadline, component, operation, name, **params):
    """Each synchronous local API operation shares the task's absolute deadline."""
    diagnostic = {
        "phase": "local_api",
        "operation": f"{component}/{operation}/{name}",
        "http_status": None,
        "exception_class": None,
        "deadline_expired": False,
    }
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("native task deadline")
        with client.stream(
            "GET",
            f"http://127.0.0.1:8778/JSON/{component}/{operation}/{name}/",
            params=params,
            timeout=remaining,
        ) as response:
            diagnostic["http_status"] = response.status_code
            response.read()
            if time.monotonic() >= deadline:
                raise TimeoutError("native task deadline")
            if not response.is_success:
                try:
                    failure = response.json()
                except ValueError:
                    failure = None
                code = (
                    "url_not_found"
                    if isinstance(failure, dict) and failure.get("code") == "url_not_found"
                    else None
                )
                raise NativeApiRefusal(
                    f"{component}/{operation}/{name}", response.status_code, code
                )
            result = response.json()
        if "code" in result:
            raise ValueError(f"native API refused configuration: {component}/{operation}/{name}")
        return result
    except Exception as error:
        diagnostic["exception_class"] = type(error).__name__
        diagnostic["deadline_expired"] = time.monotonic() >= deadline
        if diagnostic["deadline_expired"] and isinstance(error, httpx.TransportError):
            raise TimeoutError("native task deadline") from None
        raise
    finally:
        # Publish fixed diagnostic fields atomically, without URLs, params or API key.
        temporary = IPC / "local-api.tmp"
        temporary.write_text(json.dumps(diagnostic))
        temporary.chmod(0o600)
        os.replace(temporary, IPC / "local-api.json")


def start_native_scan(api, deadline, **params):
    """Seed history reaches ZAP's site tree asynchronously after accessUrl returns."""
    visible_by = min(deadline, time.monotonic() + 2)
    while True:
        try:
            return api("ascan", "action", "scan", **params)["scan"]
        except NativeApiRefusal as error:
            # This exact refusal happens before ZAP creates any scan. Ambiguous
            # network errors and all other API refusals must never be retried.
            if error.status != 400 or error.code != "url_not_found":
                raise
            remaining = visible_by - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(0.05, remaining))


def run(task: ActiveRuleTask, pin: ActiveRulePin):
    verify_binaries(pin)
    if task.rule_config_sha256 != CONFIG_SHA256:
        raise ValueError("native task config/transport unsupported")
    for directory in (IPC / "requests", IPC / "responses"):
        directory.mkdir(parents=True, exist_ok=True)
    Bridge.deadline = time.monotonic() + task.deadline_seconds
    Bridge.task, Bridge.pin = task, pin
    seed = native_url(task)
    bridge = HTTPServer(("127.0.0.1", 8777), Bridge)
    threading.Thread(target=bridge.serve_forever, daemon=True).start()
    api_key = secrets.token_hex(32)
    process = subprocess.Popen(
        [
            "/opt/zap/zap.sh",
            "-Xmx512m",
            "-daemon",
            "-host",
            "127.0.0.1",
            "-port",
            "8778",
            "-dir",
            "/tmp/zap-home",
            "-config",
            f"api.key={api_key}",
            "-config",
            "autoupdate.checkOnStart=false",
            "-config",
            "autoupdate.downloadNewRelease=false",
            "-config",
            "autoupdate.installAddonUpdates=false",
        ],
        stdin=subprocess.DEVNULL,
        # The supervisor retains only a bounded, redacted Docker stderr tail.
        # Preserve daemon startup errors until that capture precedes removal.
        stdout=sys.stderr,
        stderr=sys.stderr,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LC_ALL": "C"},
    )
    try:
        with httpx.Client(trust_env=False) as client:

            def api(component, operation, name, **params):
                return local_api(
                    client, Bridge.deadline, component, operation, name, apikey=api_key, **params
                )

            while time.monotonic() < Bridge.deadline:
                try:
                    if api("core", "view", "version")["version"] != pin.engine_version:
                        raise ValueError("native version mismatch")
                    break
                except httpx.TransportError:
                    time.sleep(0.05)
            api("core", "action", "setMode", mode="protect")
            api("network", "action", "setHttpProxy", host="127.0.0.1", port="8777")
            api("network", "action", "setHttpProxyEnabled", enabled="true")
            api("pscan", "action", "disableAllScanners")
            context = api("context", "action", "newContext", contextName="ScopeLensBound")[
                "contextId"
            ]
            part = urlsplit(seed)
            api(
                "context",
                "action",
                "includeInContext",
                contextName="ScopeLensBound",
                # ZAP strips query parameters before its full context match.
                # Query names/values remain constrained by the trusted task grant.
                regex=r"^" + re.escape(f"{part.scheme}://{part.netloc}{part.path}") + r"$",
            )
            api(
                "context",
                "action",
                "setContextInScope",
                contextName="ScopeLensBound",
                booleanInScope="true",
            )
            api(
                "ascan",
                "action",
                "addScanPolicy",
                scanPolicyName="ScopeLensBound",
                alertThreshold="MEDIUM",
                attackStrength="LOW",
            )
            api("ascan", "action", "disableAllScanners", scanPolicyName="ScopeLensBound")
            api(
                "ascan",
                "action",
                "enableScanners",
                ids=pin.rule_id,
                scanPolicyName="ScopeLensBound",
            )
            # ZAP 2.17.0's option API uses case-sensitive "Integer". Lowercase
            # "integer" is a missing parameter, before any seed request is made.
            api("ascan", "action", "setOptionTargetParamsInjectable", Integer="1")
            api("ascan", "action", "setOptionTargetParamsEnabledRPC", Integer="0")
            api("ascan", "action", "setOptionThreadPerHost", Integer="1")
            # An explicit exact seed; no spider, authentication, replay or redirects.
            api("core", "action", "accessUrl", url=seed, followRedirects="false")
            scan = start_native_scan(
                api,
                Bridge.deadline,
                url=seed,
                recurse="false",
                inScopeOnly="true",
                scanPolicyName="ScopeLensBound",
                contextId=context,
                method="GET",
            )
            while api("ascan", "view", "status", scanId=scan)["status"] != "100":
                time.sleep(0.05)
            # Mutated query values are part of bound native alerts. The original
            # seed query would exclude them from ZAP's prefix-filtered view.
            alert_base = part._replace(query="", fragment="").geturl()
            alerts = api("core", "view", "alerts", baseurl=alert_base)["alerts"]
            rows = [
                {
                    "pluginid": item["pluginId"],
                    "riskcode": item.get("risk", "unknown"),
                    "instances": [{"uri": logical_url(task, pin, item["url"])}],
                }
                for item in alerts
            ]
            return {"site": [{"alerts": rows}]}
    finally:
        bridge.shutdown()
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


def publish_result(result, deadline):
    """The supervisor must collect tmpfs output before the container exits."""
    serialized = json.dumps(result).encode()
    if len(serialized) > 1_048_576:
        raise ValueError("native output size limit")
    temporary = IPC / "result.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, IPC / "result.json")
    finally:
        temporary.unlink(missing_ok=True)
    wait_until = min(deadline, time.monotonic() + 5)
    while time.monotonic() < wait_until:
        if (IPC / "result.ack").is_file():
            return
        time.sleep(0.01)
    raise TimeoutError("native result acknowledgement deadline")


def main():
    payload = json.loads(sys.argv[1])
    task = ActiveRuleTask.model_validate(payload["task"])
    pin = ActiveRulePin.model_validate(payload["pin"])
    result = run(task, pin)
    publish_result(result, Bridge.deadline)


if __name__ == "__main__":
    main()
