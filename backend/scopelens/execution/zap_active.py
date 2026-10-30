"""Trusted file-channel launcher for reviewed origin-scoped native ZAP tasks.

The scanner has no network, mounts or secrets. Docker container.id establishes
worker identity. Target requests use the mandatory proxy with supervisor signatures.
An empty reviewed manifest returns before touching Docker or constructing a client.
"""

import base64
import hashlib
import json
import re
import ssl
import time
from contextlib import suppress
from dataclasses import replace
from urllib.parse import urlencode, urlsplit

import httpx
from pydantic import PrivateAttr

from scopelens.adapters.scanners import ScannerResult
from scopelens.adapters.zap_active import (
    ActiveRulePin,
    ActiveRuleTask,
    normalize_active_report,
    reviewed_rule,
    rule_authorized_for_scope,
)
from scopelens.adapters.zap_active_worker import CONFIG_SHA256
from scopelens.broker.zap_task import (
    ZAP_TASK_HEADER,
    close_grant,
    grant_live,
    issue_grant,
    sign_request,
)
from scopelens.domain.enums import AuthorityDomain
from scopelens.execution.supervisor import ARTIFACT_MARKER
from scopelens.persistence.session import session_scope
from scopelens.security.redaction import redact_text

ZAP_DECISION_HEADER = "x-scopelens-zap-decision"

LOG_READ_LIMIT = 16384
LOG_TAIL_LIMIT = 4096


class NativeScannerResult(ScannerResult):
    # Stored on the evidence envelope, not the public ScannerResult field schema.
    _launcher_diagnostics: dict = PrivateAttr(default_factory=dict)


def _observed_exit(container):
    """Created/running containers have a default ExitCode, not an observed exit."""
    if container.status != "exited":
        return None
    code = container.attrs.get("State", {}).get("ExitCode")
    return code if type(code) is int else None


def _stderr_tail(container, secrets_to_remove):
    """Non-following, bounded Docker stderr; redact before retaining the tail."""
    chunks = None
    try:
        chunks = container.logs(stdout=False, stderr=True, stream=True, follow=False, tail=40)
        data = bytearray()
        truncated = False
        for index, block in enumerate(chunks):
            if index == 64:
                truncated = True
                break
            if not isinstance(block, bytes):
                raise ValueError("native stderr stream shape")
            room = LOG_READ_LIMIT - len(data)
            data.extend(block[:room])
            if len(block) >= room:
                truncated = True
                break
        if truncated:
            # Do not retain a credential fragment split at the read boundary.
            boundary = data.rfind(b"\n")
            data = data[: boundary + 1] if boundary >= 0 else bytearray()
        text = data.decode("utf-8", errors="replace")
        for value in secrets_to_remove:
            if value:
                text = text.replace(value, "[redacted]")
        text = redact_text(text)
        retained = text.encode("utf-8")[-LOG_TAIL_LIMIT:].decode("utf-8", errors="ignore")
        return {
            "worker_stderr_tail": retained,
            "worker_stderr_capture": "captured",
            "worker_stderr_truncated": truncated or len(text.encode("utf-8")) > LOG_TAIL_LIMIT,
        }
    except Exception as exc:  # noqa: BLE001 - diagnostics must not prevent containment cleanup.
        return {
            "worker_stderr_tail": "",
            "worker_stderr_capture": "unavailable",
            "worker_stderr_capture_exception_class": type(exc).__name__,
        }
    finally:
        if chunks is not None:
            with suppress(Exception):
                chunks.close()


# Fixed scripts, executed with isolated Python. No scanner text becomes executable
# code or a Docker identifier. Read limits precede deserialization; symlinks refused.
READ_REQUEST = r"""
import json, os, re
result='/tmp/zap-active-ipc/result.json'
if os.path.lexists(result):
    if os.path.islink(result) or not os.path.isfile(result): raise SystemExit(2)
    print('{"result_ready":true}'); raise SystemExit()
root='/tmp/zap-active-ipc/requests'
if not os.path.isdir(root): print('{}'); raise SystemExit()
names=sorted(os.listdir(root))
if len(names)>32: raise SystemExit(2)
for name in names:
    if re.fullmatch(r'[0-9a-f]{32}\.tmp', name): continue
    if not re.fullmatch(r'[0-9a-f]{32}\.json', name): raise SystemExit(2)
    fd=os.open(root+'/'+name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try: data=os.read(fd,16385)
    finally: os.close(fd)
    os.unlink(root+'/'+name)
    if len(data)>16384: raise SystemExit(2)
    print(json.dumps({'id':name[:-5],'request':json.loads(data)})); break
else: print('{}')
"""
ACK_RESULT = r"""
import os
fd=os.open('/tmp/zap-active-ipc/result.ack',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
os.close(fd)
"""
READ_FILE = r"""
import os, stat, sys
limits={'result.json':1048576,'local-api.json':1024}
if len(sys.argv)!=2 or sys.argv[1] not in limits: raise SystemExit(2)
name=sys.argv[1]; limit=limits[name]
root=os.open('/tmp/zap-active-ipc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try: fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root)
finally: os.close(root)
try:
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size>limit: raise SystemExit(2)
    data=bytearray()
    for _ in range(limit//16384+2):
        block=os.read(fd,min(16384,limit+1-len(data)))
        if not block: break
        data.extend(block)
        if len(data)>limit: raise SystemExit(2)
    sys.stdout.buffer.write(data)
finally: os.close(fd)
"""
WRITE_RESPONSE = r"""
import json, os, re, sys
ident=sys.argv[1]
if not re.fullmatch(r'[0-9a-f]{32}',ident) or len(sys.argv[2])>100000: raise SystemExit(2)
root='/tmp/zap-active-ipc/responses'
fd=os.open(root+'/'+ident+'.tmp',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try: os.write(fd,sys.argv[2].encode())
finally: os.close(fd)
os.rename(root+'/'+ident+'.tmp',root+'/'+ident+'.json')
"""


def container_kwargs(image_id, task, pin):
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise ValueError("native ZAP requires an immutable measured image ID")
    return {
        "image": image_id,
        "command": [
            "python",
            "-m",
            "scopelens.adapters.zap_active_worker",
            json.dumps(
                {
                    "task": task.model_dump(),
                    "pin": pin.model_dump(include=set(ActiveRulePin.model_fields)),
                }
            ),
        ],
        "network_mode": "none",
        "environment": {"PATH": "/app/.venv/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp"},
        "labels": {
            "scopelens.managed": "worker",
            "scopelens.scan_id": task.scan_id,
            "scopelens.run_id": task.task_id,
        },
        "read_only": True,
        "tmpfs": {"/tmp": "rw,noexec,nosuid,size=256m"},
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "privileged": False,
        "mem_limit": "2048m",
        "nano_cpus": 1_000_000_000,
        "pids_limit": 512,
        "auto_remove": False,
        "working_dir": "/tmp",
    }


def _exec(container, script, *args):
    code, output = container.exec_run(["python", "-I", "-c", script, *args])
    if code != 0:
        raise ValueError("native worker channel failed")
    return output


def _forward(client, settings, grant, task, worker_id, offered, token, *, diagnostic=None):
    """Worker URL is data only. Proxy authenticates it before any target connection."""
    record = diagnostic if diagnostic is not None else {}
    record.update(phase="transport", http_status=None, broker_decision="unknown")
    if not isinstance(offered, dict) or set(offered) != {"method", "url"}:
        raise ValueError("native worker request shape refused")
    if offered["method"] != "GET" or not isinstance(offered["url"], str):
        raise ValueError("native worker request method refused")
    pin = reviewed_rule(task.rule_id, settings)
    if pin is None or not task.accepts("GET", offered["url"], b"", pin):
        record.update(http_status=403, broker_decision="not_requested", local_catalog_denied=True)
        return {"status": 403, "headers": {}, "body": "", "diagnostics": record}, False
    wire_url = str(httpx.URL(offered["url"]))
    signed = sign_request(
        settings, grant, scan_id=task.scan_id, worker_id=worker_id, method="GET", url=wire_url
    )
    header = base64.b64encode(signed.model_dump_json().encode()).decode()
    # Reviewed native tasks are anonymous, including after a target sets cookies.
    cookies = getattr(client, "cookies", None)
    if cookies is not None:
        cookies.clear()
    started = time.monotonic()
    with client.stream(
        "GET",
        wire_url,
        headers={
            "x-scopelens-egress": token,
            ZAP_TASK_HEADER: header,
            "Accept-Encoding": "identity",
            "User-Agent": "ScopeLens-reviewed-ZAP",
        },
    ) as response:
        verdict = response.headers.get(ZAP_DECISION_HEADER, "unknown")
        if verdict not in {"allow", "deny"}:
            verdict = "unknown"
        record.update(http_status=response.status_code, broker_decision=verdict)
        kept = {
            name: value
            for name, value in response.headers.items()
            if name.lower() in {"content-type", "cache-control"} and len(value) <= 1024
        }
        body = bytearray()
        for block in response.iter_bytes():
            body.extend(block)
            if len(body) > 65536:
                raise ValueError("native target response exceeds retained limit")
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        return {
            "diagnostics": record,
            "status": response.status_code,
            "headers": kept,
            "body": base64.b64encode(body).decode(),
        }, verdict == "allow" and response.status_code < 400


def _read_result(container):
    data = _exec(container, READ_FILE, "result.json")
    if len(data) > 1_048_576:
        raise ValueError("native output size limit")
    return data


def _read_worker_api(container):
    """Read bounded worker telemetry, without accepting authority or arbitrary fields."""
    data = _exec(container, READ_FILE, "local-api.json")
    if len(data) > 1024:
        raise ValueError("native API diagnostic size limit")
    value = json.loads(data)
    if (
        set(value) != {"phase", "operation", "http_status", "exception_class", "deadline_expired"}
        or value["phase"] != "local_api"
        or not re.fullmatch(
            r"(?:core|network|pscan|context|ascan)/(?:action|view)/[A-Za-z]{1,48}",
            value["operation"],
        )
        or (
            value["http_status"] is not None
            and (type(value["http_status"]) is not int or not 100 <= value["http_status"] <= 599)
        )
        or type(value["deadline_expired"]) is not bool
        or (
            value["exception_class"] is not None
            and (
                not isinstance(value["exception_class"], str)
                or not re.fullmatch(r"[A-Za-z]{1,64}", value["exception_class"])
            )
        )
    ):
        raise ValueError("native API diagnostic fields refused")
    return value


def transport_kwargs(settings, task, token):
    """Scan credential on CONNECT only; each inner GET has its separate task signature.

    Trust only the existing broker CA for intercepted HTTPS. No signed task header,
    grant token or scanner identity is placed on CONNECT. Missing CA fails closed.
    """
    verify = (
        ssl.create_default_context(cafile=str(settings.proxy_ca_path))
        if urlsplit(task.url).scheme == "https"
        else True
    )
    return {
        "proxy": httpx.Proxy(
            f"http://{settings.proxy_host}:{settings.proxy_http_port}",
            headers={"x-scopelens-egress": token},
        ),
        "verify": verify,
        "trust_env": False,
        "follow_redirects": False,
        "timeout": min(5, task.deadline_seconds),
    }


def run_task(settings, supervisor, task, pin, token):
    """At most one bounded, scope-bound grant; tombstones prohibit reissue."""
    started = time.monotonic()
    container = None
    grant = None
    timed_out = cancelled = False
    errors = []
    raw = b'{"site":[]}'
    result_collected = False
    code = None
    phase = "launch"
    diagnostics = {"exception_class": None, "requests": []}
    try:
        container = supervisor.client.containers.create(
            **container_kwargs(settings.kali_worker_image, task, pin)
        )
        phase = "grant"
        with session_scope(settings) as session:
            grant = issue_grant(
                session, settings=settings, scan_id=task.scan_id, task=task, worker_id=container.id
            )
        live_probe = sign_request(
            settings,
            grant,
            scan_id=task.scan_id,
            worker_id=container.id,
            method="GET",
            url=task.url,
        )
        phase = "launch"
        container.start()
        phase = "transport"
        with httpx.Client(**transport_kwargs(settings, task, token)) as client:
            while time.monotonic() - started < task.deadline_seconds:
                phase = "grant"
                with session_scope(settings) as session:
                    if not grant_live(
                        session, settings=settings, signed=live_probe, require_admitted=False
                    ):
                        cancelled = True
                        break
                phase = "read"
                container.reload()
                if container.status != "running":
                    code = _observed_exit(container)
                    break
                envelope = json.loads(_exec(container, READ_REQUEST))
                if envelope == {"result_ready": True} and type(envelope["result_ready"]) is bool:
                    if not result_collected:
                        raw = _read_result(container)
                        result_collected = True
                        try:
                            diagnostics["worker_local_api"] = _read_worker_api(container)
                        except Exception as exc:  # noqa: BLE001 - telemetry is not authority.
                            diagnostics["worker_local_api_capture_exception_class"] = type(
                                exc
                            ).__name__
                        _exec(container, ACK_RESULT)
                        diagnostics["result_acknowledged"] = True
                    time.sleep(0.02)
                elif envelope:
                    if set(envelope) != {"id", "request"}:
                        raise ValueError("native worker channel envelope refused")
                    # Actual container.id comes from Docker, never the envelope.
                    phase = "transport"
                    request_diagnostic = {}
                    if len(diagnostics["requests"]) < task.max_requests + 1:
                        diagnostics["requests"].append(request_diagnostic)
                    else:
                        diagnostics["request_diagnostics_truncated"] = True
                    response, allowed = _forward(
                        client,
                        settings,
                        grant,
                        task,
                        container.id,
                        envelope["request"],
                        token,
                        diagnostic=request_diagnostic,
                    )
                    response.pop("diagnostics")
                    if not allowed:
                        verdict = request_diagnostic.get("broker_decision", "unknown")
                        status = request_diagnostic.get("http_status")
                        if verdict == "deny":
                            errors.append(f"native broker denied request: HTTP {status}")
                        elif verdict == "allow":
                            errors.append(f"native upstream HTTP {status}; broker allowed request")
                        elif verdict == "not_requested":
                            errors.append("native local task catalog refused request")
                        else:
                            errors.append(f"native broker decision unavailable: HTTP {status}")
                    phase = "read"
                    _exec(container, WRITE_RESPONSE, envelope["id"], json.dumps(response))
                else:
                    time.sleep(0.02)
            else:
                timed_out = True
        if code == 0 and not result_collected:
            phase = "read"
            raw = _read_result(container)
    except Exception as exc:  # noqa: BLE001 - failures never imply a clean assessment.
        diagnostics["exception_class"] = type(exc).__name__
        errors.append(f"native launcher failed in {phase}: {type(exc).__name__}")
    finally:
        diagnostics["phase"] = phase
        try:
            if container is not None:
                try:
                    container.reload()
                    observed = _observed_exit(container)
                    if observed is not None:
                        code = observed
                except Exception as exc:  # noqa: BLE001 - do not mask the original failure.
                    diagnostics["exit_probe_exception_class"] = type(exc).__name__
                secrets_to_remove = [token, (grant or {}).get("token", "")]
                key = settings.zap_active_signing_key
                if key is not None:
                    secrets_to_remove.append(key.get_secret_value())
                diagnostics.update(_stderr_tail(container, secrets_to_remove))
                if "worker_local_api" not in diagnostics:
                    try:
                        diagnostics["worker_local_api"] = _read_worker_api(container)
                    except Exception as exc:  # noqa: BLE001 - telemetry must not mask containment.
                        diagnostics["worker_local_api_capture_exception_class"] = type(exc).__name__
            else:
                diagnostics.update(worker_stderr_tail="", worker_stderr_capture="not_created")
            if grant is not None:
                try:
                    with session_scope(settings) as session:
                        close_grant(
                            session,
                            scan_id=task.scan_id,
                            grant_id=grant["grant_id"],
                            worker_id=container.id,
                        )
                except Exception as exc:  # noqa: BLE001 - worker removal still must run.
                    diagnostics["grant_close_exception_class"] = type(exc).__name__
                    errors.append(f"native grant cleanup failed: {type(exc).__name__}")
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception as exc:  # noqa: BLE001 - retain containment failure evidence.
                    diagnostics["worker_remove_exception_class"] = type(exc).__name__
                    errors.append(f"native worker removal failed: {type(exc).__name__}")
    diagnostics.update(
        exit_code=code, exit_status="observed" if code is not None else "no exit observed"
    )
    if code is None:
        errors.append("no exit observed")
    result = normalize_active_report(
        task, pin, raw, exit_code=code, timed_out=timed_out, cancelled=cancelled
    )
    scanner = NativeScannerResult(
        tool="zap-active",
        version=pin.engine_version,
        state=("partial" if result.observations else "error")
        if errors and result.state == "completed"
        else result.state,
        observations=result.observations,
        errors=[*result.errors, *errors],
        output_hash=result.output_sha256,
        template_hash=pin.rule_config_sha256,
    )
    scanner._launcher_diagnostics = diagnostics
    return scanner


def dispatch(settings, supervisor, *, scan_id, scope, probes, token):
    """Only frozen reviewed read-only inputs; at most two native tasks per scan."""
    if not settings.zap_active_lab_enabled:
        return []
    pin = reviewed_rule("40012", settings)
    if (
        not rule_authorized_for_scope(pin, scope)
        or pin.rule_config_sha256 != CONFIG_SHA256
        or not pin.addon_sha256
        or not pin.addon_filename
    ):
        return []
    results = []
    for probe in probes or []:
        if len(results) == 2:
            break
        if not isinstance(probe, dict) or probe.get("kind") != "xss":
            continue
        parameter = probe.get("parameter")
        if not isinstance(parameter, str) or not parameter or len(parameter) > 128:
            continue
        if scope.authority_domain == AuthorityDomain.LAB and (
            parameter != "q" or probe.get("path") != "/active/xss"
        ):
            continue
        baseline = probe.get("baseline_value", "scopelens")
        if baseline not in pin.allowed_values:
            continue
        path = probe.get("path", "")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or urlsplit(path).netloc
            or "?" in path
            or "#" in path
            or "%" in path
            or "\\" in path
        ):
            continue
        ident = hashlib.sha256(json.dumps(probe, sort_keys=True).encode()).hexdigest()
        task = ActiveRuleTask(
            scan_id=str(scan_id),
            task_id="zap-active:" + ident,
            input_id=ident,
            rule_id=pin.rule_id,
            url=scope.origin + path + "?" + urlencode({parameter: baseline}),
            input_name=parameter,
            rule_config_sha256=CONFIG_SHA256,
            max_requests=pin.max_requests,
            deadline_seconds=pin.deadline_seconds,
        )
        results.append(run_task(settings, supervisor, task, pin, token))
    return results


def append_results(crawl, results):
    if not results:
        return crawl
    lines = []
    for row in results:
        envelope = {
            "kind": "scanner_result",
            "source": "zap_task_supervisor",
            "data": row.model_dump(),
        }
        diagnostics = getattr(row, "_launcher_diagnostics", None)
        if diagnostics:
            envelope["launcher_diagnostics"] = diagnostics
        lines.append(ARTIFACT_MARKER + json.dumps(envelope))
    return replace(crawl, stdout=crawl.stdout + "\n" + "\n".join(lines) + "\n")
