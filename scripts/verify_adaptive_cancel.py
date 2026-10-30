"""Cancel a real adaptive follow-up, then measure token denial and worker exit."""

import argparse
import json
import socket
import time
from pathlib import Path

import docker
import httpx

from scopelens.config import Settings

parser = argparse.ArgumentParser()
parser.add_argument("--scope-id", required=True)
args = parser.parse_args()
settings = Settings()
engine = docker.from_env()
with httpx.Client(base_url="http://127.0.0.1:8090", timeout=20) as client:
    client.post(
        "/api/auth/login",
        json={
            "username": settings.operator_username,
            "password": settings.operator_password.get_secret_value(),
        },
    ).raise_for_status()
    response = client.post("/api/scans", json={"scope_version_id": args.scope_id, "adaptive": True})
    response.raise_for_status()
    scan_id = response.json()["id"]
    deadline = time.monotonic() + 600
    token = None
    authority = None
    while time.monotonic() < deadline:
        workers = engine.containers.list(filters={"label": "scopelens.scan_id=" + scan_id})
        selected = next(
            (w for w in workers if "-adaptive-" in w.labels.get("scopelens.run_id", "")), None
        )
        if selected:
            selected.reload()
            env = dict(v.split("=", 1) for v in selected.attrs["Config"]["Env"] if "=" in v)
            token = env.get("SCOPELENS_EGRESS_TOKEN")
            from urllib.parse import urlsplit

            target = urlsplit(env["SCOPELENS_TARGET_URL"])
            authority = target.netloc
            break
        time.sleep(0.1)
    if not token:
        client.post(f"/api/scans/{scan_id}/cancel")
        raise AssertionError("No live adaptive worker captured before deadline")
    started = time.monotonic()
    client.post(f"/api/scans/{scan_id}/cancel").raise_for_status()
    with socket.create_connection(("127.0.0.1", 8098), timeout=4) as sock:
        sock.sendall(
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nx-scopelens-egress: {token}\r\n\r\n".encode()
        )
        status = sock.recv(4096).split(b"\r\n", 1)[0]
    denied = time.monotonic() - started
    assert b"403" in status and denied <= 5, (status, denied)
    while time.monotonic() - started < 30:
        if not engine.containers.list(filters={"label": "scopelens.scan_id=" + scan_id}):
            break
        time.sleep(0.1)
    stopped = time.monotonic() - started
    assert stopped < 30
    report = client.get(f"/api/scans/{scan_id}/export.json")
    report.raise_for_status()
    assert report.json()["score"]["score"] is None
    output = {
        "scan_id": scan_id,
        "phase": "adaptive",
        "admission_denied_seconds": denied,
        "workers_stopped_seconds": stopped,
        "proxy_status": status.decode(),
        "score": None,
    }
    Path("runs/m4-verification/adaptive-cancel.json").write_text(
        json.dumps(output, indent=2) + "\n"
    )
    print(json.dumps(output))
