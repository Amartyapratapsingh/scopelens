"""Reviewed tool invocations with fixed commands, bounded files and no shell interpolation."""

import contextlib
import hashlib
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import yaml

from scopelens.adapters.scanners import ScannerResult, parse_output
from scopelens.browser.bridge import Bridge


def invoke(tool, version, command, output, *, timeout=90, environment=None):
    output.parent.mkdir(parents=True, exist_ok=True)
    # Drain child output continuously but retain only a bounded diagnostic tail.
    # A noisy process must not fill the shared worker filesystem or block on a pipe.
    tail = bytearray()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
    except OSError:
        return ScannerResult(
            tool=tool,
            version=version,
            state="not_tested",
            errors=["reviewed executable unavailable"],
        )

    def drain():
        while chunk := process.stdout.read(8192):
            tail.extend(chunk)
            if len(tail) > 65536:
                del tail[:-65536]

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        code = process.wait()
    # Kill leftover descendants holding stdout after the main process exits.
    reader.join(timeout=2)
    if reader.is_alive():
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        reader.join(timeout=2)
    if not reader.is_alive():
        process.stdout.close()
    with output.open("rb") if output.exists() else tempfile.TemporaryFile() as source:
        raw = source.read(1024 * 1024 + 1)
    result = parse_output(
        tool,
        version,
        raw[: 1024 * 1024].decode("utf-8", "replace"),
        exit_code=code,
        timed_out=timed_out,
        truncated=len(raw) > 1024 * 1024,
    )
    if result.state in {"error", "timeout", "partial"}:
        from scopelens.security.redaction import redact_text

        result.errors.append(redact_text(bytes(tail[-3000:]).decode("utf-8", "replace")))
    if timed_out:
        result.errors.append(f"{tool} time allowance exhausted after {timeout:.1f}s")
    return result


def har(responses):
    entries = []
    for response in responses:
        body = response.body_excerpt
        entries.append(
            {
                "startedDateTime": datetime.now(UTC).isoformat(),
                "time": 0,
                "request": {
                    "method": "GET",
                    "url": response.url,
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [],
                    "queryString": [],
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "response": {
                    "status": response.status,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in response.headers.items()],
                    "cookies": [],
                    "content": {
                        "size": len(body.encode()),
                        "text": body,
                        "mimeType": response.content_type or "text/plain",
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": len(body.encode()),
                },
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
            }
        )
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "ScopeLens", "version": "M3"},
            "entries": entries,
        }
    }


def _run_zap(config, responses, *, timeout):
    """One offline batch owns its temporary files and releases them before the next."""
    with tempfile.TemporaryDirectory(prefix="scopelens-tools-") as folder:
        root = Path(folder)
        home = root / "home"
        home.mkdir()
        (home / ".ZAP").mkdir()
        (home / ".ZAP/.ZAP_JVM.properties").write_text("-Xmx384m\n")
        environment = {
            **os.environ,
            "HOME": str(home),
            "JAVA_OPTS": "-Xmx384m",
            "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD": "true",
            "DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD": "true",
        }
        capture = root / "capture.har"
        capture.write_text(json.dumps(har(responses)))
        plan = {
            "env": {
                "contexts": [{"name": "scan", "urls": [config.origin]}],
                "parameters": {"failOnError": True, "failOnWarning": False},
            },
            "jobs": [
                {
                    "type": "passiveScan-config",
                    "parameters": {"disableAllRules": True},
                    "rules": [
                        {"id": i, "threshold": "medium"} for i in [10038, 10020, 10035, 10021]
                    ],
                },
                {
                    "type": "import",
                    "parameters": {"type": "har", "fileName": str(capture)},
                },
                {"type": "passiveScan-wait", "parameters": {"maxDuration": 1}},
                {
                    "type": "report",
                    "parameters": {
                        "template": "traditional-json",
                        "reportDir": folder,
                        "reportFile": "zap.json",
                        "displayReport": False,
                    },
                },
            ],
        }
        plan_path = root / "plan.yaml"
        plan_path.write_text(yaml.safe_dump(plan))
        zap = invoke(
            "zap",
            "2.17.0",
            [
                "/opt/zap/zap.sh",
                "-cmd",
                "-silent",
                "-dir",
                str(home / "zap"),
                "-config",
                "autoupdate.checkOnStart=false",
                "-config",
                "autoupdate.downloadNewRelease=false",
                "-autorun",
                str(plan_path),
            ],
            root / "zap.json",
            timeout=timeout,
            environment={k: v for k, v in environment.items() if k in {"PATH", "HOME", "LANG"}},
        )
        zap.template_hash = hashlib.sha256(plan_path.read_bytes()).hexdigest()
        return zap


def _run_nuclei(config):
    # Nuclei never inherits ZAP's database, capture, logs or disk exhaustion.
    with tempfile.TemporaryDirectory(prefix="scopelens-nuclei-") as folder:
        root = Path(folder)
        home = root / "home"
        home.mkdir()
        environment = {
            **os.environ,
            "HOME": str(home),
            "TMPDIR": str(root),
            "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD": "true",
            "DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD": "true",
        }
        template = Path("/app/tooling/nuclei-csp.yaml")
        with Bridge(os.environ["HTTP_PROXY"], os.environ["SCOPELENS_EGRESS_TOKEN"]) as proxy:
            nuclei = invoke(
                "nuclei",
                "3.11.1",
                [
                    "nuclei",
                    "-u",
                    config.origin + "/",
                    "-t",
                    str(template),
                    "-proxy",
                    proxy,
                    "-H",
                    "x-scopelens-egress: " + os.environ["SCOPELENS_EGRESS_TOKEN"],
                    "-disable-update-check",
                    "-no-stdin",
                    "-no-httpx",
                    "-no-interactsh",
                    "-disable-redirects",
                    "-rate-limit",
                    "1",
                    "-concurrency",
                    "1",
                    "-bulk-size",
                    "1",
                    "-retries",
                    "0",
                    "-timeout",
                    "10",
                    "-jsonl",
                    "-output",
                    str(root / "nuclei.jsonl"),
                ],
                root / "nuclei.jsonl",
                environment=environment,
            )
        nuclei.template_hash = hashlib.sha256(template.read_bytes()).hexdigest()
        return nuclei


ZAP_BATCH_BYTES = 8 * 1024 * 1024
ZAP_TOTAL_SECONDS = 120


def capture_batches(responses):
    """Preserve full captured responses while bounding each import's serialized size."""
    batch = []
    size = 0
    for response in responses:
        response_size = len(json.dumps(har([response])).encode())
        if response_size > ZAP_BATCH_BYTES:
            raise ValueError("one captured response exceeds the ZAP import batch limit")
        if batch and size + response_size > ZAP_BATCH_BYTES:
            yield batch
            batch, size = [], 0
        batch.append(response)
        size += response_size
    if batch:
        yield batch


def run_tools(config, crawl):
    """Assess offline captures in bounded batches, then run the reviewed proxy-only check."""
    results = []
    hashes = []
    errors = []
    deadline = time.monotonic() + float(os.environ.get("SCOPELENS_ZAP_TIMEOUT", ZAP_TOTAL_SECONDS))
    try:
        for batch in capture_batches(crawl.responses):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                errors.append("ZAP total time budget reached; remaining capture batches unassessed")
                break
            result = _run_zap(config, batch, timeout=remaining)
            results.append(result)
            hashes.append(result.output_hash)
            errors.extend(result.errors)
            if result.state != "completed":
                errors.append("ZAP batch incomplete; remaining capture batches unassessed")
                break
    except (OSError, ValueError) as exc:
        errors.append("ZAP capture preparation failed: " + type(exc).__name__)
    if not results and not errors:
        errors.append("No captured responses available for ZAP")
    observations = [observation for result in results for observation in result.observations]
    yield ScannerResult(
        tool="zap",
        version="2.17.0",
        state=("partial" if any(r.state == "completed" for r in results) else "error")
        if errors
        else "completed",
        observations=observations,
        errors=errors,
        output_hash=hashlib.sha256(json.dumps(hashes).encode()).hexdigest(),
        template_hash=hashlib.sha256(
            json.dumps([r.template_hash for r in results]).encode()
        ).hexdigest(),
    )
    yield _run_nuclei(config)
