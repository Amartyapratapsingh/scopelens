"""Bound a known scope-visibility race without retrying uncertain scan creation."""

import hashlib
import json
import re
import time
from datetime import UTC, datetime


def _redact(value):
    if isinstance(value, dict):
        return {
            key: "[redacted]"
            if any(
                word in key.lower()
                for word in ("password", "secret", "token", "cookie", "authorization")
            )
            else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(
            r"(?:postgresql(?:\+\w+)?|redis)://[^\s\"']+", "[redacted connection URL]", value
        )
        return re.sub(r"(https?://)[^/\s@]+:[^/\s@]+@", r"\1[redacted]@", value)
    return value


def save_http_error(response, directory):
    """Save redacted error bodies and safe request fields; never headers or login data."""
    if response.status_code < 400:
        return
    response.read()
    try:
        body = response.json()
    except ValueError:
        body = response.text
    request = response.request
    payload = None
    if request.method == "POST" and request.url.path == "/api/scans":
        submitted = json.loads(request.content)
        payload = {k: submitted[k] for k in ("scope_version_id", "adaptive") if k in submitted}
    record = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "method": request.method,
        "path": request.url.path,
        "request": payload,
        "status_code": response.status_code,
        "response_body_redacted": _redact(body),
        "response_body_sha256": hashlib.sha256(response.content).hexdigest(),
        "headers_recorded": False,
    }
    path = directory / f"api-error-{len(list(directory.glob('api-error-*.json'))) + 1:04d}.json"
    with path.open("x") as stream:
        path.chmod(0o600)
        json.dump(record, stream, indent=2)
        stream.write("\n")


def create_scan(client, scope_id, adaptive, *, clock=time.monotonic, sleep=time.sleep):
    """Retry once only after explicit scope-not-found and exact scope visibility."""
    payload = {"scope_version_id": scope_id, "adaptive": adaptive}
    response = client.post("/api/scans", json=payload)
    if response.status_code != 404:
        response.raise_for_status()
        return response
    try:
        detail = response.json().get("detail")
    except (ValueError, AttributeError):
        detail = None
    if detail != "scope not found":
        response.raise_for_status()
    deadline = clock() + 10
    while (remaining := deadline - clock()) > 0:
        visible = client.get(f"/api/scopes/{scope_id}", timeout=remaining)
        if visible.status_code == 200:
            if visible.json().get("id") != scope_id:
                raise RuntimeError("Visible scope ID differs; scan creation is not retried")
            retry = client.post("/api/scans", json=payload)
            retry.raise_for_status()
            return retry
        if visible.status_code != 404:
            visible.raise_for_status()
        sleep(min(0.25, max(0, deadline - clock())))
    response.raise_for_status()
    raise AssertionError("Unreachable after HTTP404")
