"""Five reviewed exposure templates, pinned engine, scan proxy, candidate-only output.

This adapter adds no templates or probing families. A clean tool exit establishes process
completion only: neither a match nor an empty output proves a control pass/confirmation.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlsplit

from scopelens.adapters.scanners import ScannerResult, parse_output
from scopelens.browser.bridge import Bridge
from scopelens.checks.packs.tooling import reviewed_templates

NUCLEI_VERSION = "3.11.1"
# Digests of `nuclei` inside the release archives pinned in tooling/releases.json.
# Both archives were independently SHA256 checked before deriving these binary pins.
ENGINE_SHA256 = frozenset(
    {
        "f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477",  # Linux arm64
        "c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251",  # Linux amd64
    }
)
BUNDLE_MANIFEST_SHA256 = "51c8a44bb9c6c7474e2ba85cc4fc430ff4cb910b2929765ee2f6e3625184ac02"
OUTPUT_CAP = 1_048_576
LOG_CAP = 65_536


def verify_engine(executable: Path) -> str:
    with executable.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if digest not in ENGINE_SHA256:
        raise ValueError("reviewed Nuclei engine integrity failure")
    return digest


def _stop(process):
    if process.poll() is None:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    return process.wait()


def _invoke(command, output, environment, *, timeout, cancelled):
    """Bound lifetime and retained files; keep partial output across cancellation/errors."""
    if cancelled():
        return parse_output("nuclei", NUCLEI_VERSION, "", cancelled=True)
    with tempfile.TemporaryFile() as log:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                env=environment,
                start_new_session=True,
            )
        except OSError:
            return ScannerResult(
                tool="nuclei",
                version=NUCLEI_VERSION,
                state="not_tested",
                errors=["reviewed executable unavailable"],
            )
        deadline = time.monotonic() + timeout
        timed_out = was_cancelled = oversized = False
        while process.poll() is None:
            was_cancelled = cancelled()
            timed_out = time.monotonic() >= deadline
            oversized = (output.exists() and output.stat().st_size > OUTPUT_CAP) or os.fstat(
                log.fileno()
            ).st_size > LOG_CAP
            if was_cancelled or timed_out or oversized:
                _stop(process)
                break
            try:
                process.wait(timeout=min(0.1, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                continue
        code = process.wait()
        raw = b""
        if output.exists():
            with output.open("rb") as source:
                raw = source.read(OUTPUT_CAP + 1)
        result = parse_output(
            "nuclei",
            NUCLEI_VERSION,
            raw[:OUTPUT_CAP].decode("utf-8", "replace"),
            exit_code=code,
            timed_out=timed_out,
            cancelled=was_cancelled,
            truncated=oversized or len(raw) > OUTPUT_CAP,
        )
        # Tool logs can contain target bodies, argv credentials and URLs. Export only
        # structured parser/process errors, never arbitrary stdout/stderr diagnostics.
        return result


def _environment(home: Path):
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD": "true",
        "DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD": "true",
    }


def _command(executable, target, template, proxy, token, output):
    return [
        str(executable),
        "-u",
        target,
        "-t",
        str(template),
        "-proxy",
        proxy,
        "-H",
        "x-scopelens-egress: " + token,
        "-disable-update-check",
        "-no-stdin",
        "-no-httpx",
        "-no-interactsh",
        "-disable-redirects",
        "-disable-clustering",
        "-omit-raw",
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
        "-response-size-read",
        "65536",
        "-response-size-save",
        "65536",
        "-jsonl",
        "-output",
        str(output),
    ]


def _bind_observations(result, pin, origin):
    expected = urlsplit(origin + pin.path)
    valid = []
    for observation in result.observations:
        location_matches = bool(observation.locations) and all(
            urlsplit(url) == expected for url in observation.locations
        )
        if observation.rule_id != pin.id or not location_matches:
            result.errors.append("tool observation outside selected template/request binding")
            continue
        observation.mapped_control = pin.control_id
        # Matches retain source/severity/hash, never returned private material or payloads.
        observation.evidence = (
            "Reviewed exposure template matched; independent trusted exposure proof required"
        )
        valid.append(observation)
    result.observations = valid
    result.assessed_rule_ids = []  # Candidate collection never earns coverage.
    if result.errors and result.state == "completed":
        result.state = "partial" if valid else "error"
    return result


def run_expansion_tools(
    config,
    *,
    technologies=(),
    bundle=Path("/app/tooling/expansion"),
    executable=Path("/usr/local/bin/nuclei"),
    cancelled=lambda: False,
    timeout=90,
):
    """Yield existing ScannerResult records; caller emits `scanner_result` artifacts.

    Caller supplies trusted worker configuration. All selected templates share the same
    proxy/token and thus existing atomic scope/request/byte/deadline budgets. The five
    fixed GET templates permit at most one target request each; no redirects/retries,
    DNS/OAST/headless/code templates or community-directory selection are enabled.
    """
    try:
        if not 0 < timeout <= 90:
            raise ValueError("invalid bounded tool deadline")
        target = urlsplit(config.origin)
        if (
            target.scheme not in {"http", "https"}
            or not target.hostname
            or target.username
            or target.password
            or target.query
            or target.fragment
            or target.path not in {"", "/"}
        ):
            raise ValueError("exact HTTP origin required")
        origin = config.origin.rstrip("/")
        engine_digest = verify_engine(executable)
        if (
            hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
            != BUNDLE_MANIFEST_SHA256
        ):
            raise ValueError("reviewed template manifest integrity failure")
        pins = reviewed_templates(bundle, technologies)
        if len(pins) > 5 or any(pin.method != "GET" or pin.max_requests != 1 for pin in pins):
            raise ValueError("unreviewed template request limit")
        proxy, token = os.environ["HTTP_PROXY"], os.environ["SCOPELENS_EGRESS_TOKEN"]
        if not token or urlsplit(proxy).scheme != "http" or not urlsplit(proxy).hostname:
            raise ValueError("mandatory scan proxy unavailable")
    except (OSError, ValueError, KeyError):
        yield ScannerResult(
            tool="nuclei",
            version=NUCLEI_VERSION,
            state="not_tested",
            errors=["reviewed engine/template/proxy prerequisites unavailable"],
        )
        return
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryDirectory(prefix="scopelens-expanded-tools-") as folder:
        root = Path(folder)
        home = root / "home"
        home.mkdir()
        with Bridge(proxy, token) as bridge:
            for index, pin in enumerate(pins):
                stopped = cancelled()
                if stopped or time.monotonic() >= deadline:
                    yield parse_output(
                        "nuclei",
                        NUCLEI_VERSION,
                        "",
                        cancelled=stopped,
                        timed_out=not stopped,
                    )
                    break
                template = root / pin.file
                content = (bundle / pin.file).read_bytes()
                if hashlib.sha256(content).hexdigest() != pin.sha256:
                    yield ScannerResult(
                        tool="nuclei",
                        version=NUCLEI_VERSION,
                        state="not_tested",
                        errors=["template changed after review"],
                    )
                    break
                template.write_bytes(content)
                output = root / f"result-{index}.jsonl"
                result = _invoke(
                    _command(executable, origin + "/", template, bridge, token, output),
                    output,
                    _environment(home),
                    timeout=min(25, max(0.001, deadline - time.monotonic())),
                    cancelled=cancelled,
                )
                result.template_hash = hashlib.sha256(
                    json.dumps(
                        {
                            "engine_sha256": engine_digest,
                            "template_id": pin.id,
                            "template_sha256": pin.sha256,
                        },
                        sort_keys=True,
                    ).encode()
                ).hexdigest()
                yield _bind_observations(result, pin, origin)
                if result.state in {"cancelled", "timeout"}:
                    break
