"""Supervisor call to the fixed TLS lane, always outside database transactions."""

import json
from dataclasses import replace

import httpx

from scopelens.adapters.scanners import ScannerResult
from scopelens.execution.supervisor import ARTIFACT_MARKER


def append_testssl(settings, scope, token, worker):
    result = ScannerResult(
        tool="testssl", version="3.2.4", state="not_tested", errors=["scope is not HTTPS"]
    )
    if scope.scheme == "https":
        try:
            response = httpx.post(
                settings.tls_lane_url.rstrip("/") + "/testssl",
                json={"egress_token": token, "host": scope.host, "port": scope.port},
                timeout=110,
                trust_env=False,
            )
            response.raise_for_status()
            result = ScannerResult.model_validate(response.json())
        except (httpx.HTTPError, ValueError):
            result = ScannerResult(
                tool="testssl",
                version="3.2.4",
                state="error",
                errors=["TLS tool lane unavailable or malformed response"],
            )
    return replace(
        worker,
        stdout=worker.stdout
        + "\n"
        + ARTIFACT_MARKER
        + json.dumps({"kind": "scanner_result", "source": "tls_lane", "data": result.model_dump()}),
    )
