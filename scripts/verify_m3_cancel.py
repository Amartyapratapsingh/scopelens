"""Cancel a real M3 browser worker, recording observed timings rather than simulated work."""

import argparse
import json
import time
from pathlib import Path

import docker
import httpx

from scopelens.config import Settings

parser = argparse.ArgumentParser()
parser.add_argument("--source-scan")
parser.add_argument("--worker-vm", action="store_true")
parser.add_argument("--output", type=Path, default=Path("runs/m3-verification/cancel.json"))
args = parser.parse_args()
s = Settings()
c = httpx.Client(base_url="http://127.0.0.1:8090", timeout=15)
r = c.post(
    "/api/auth/login",
    json={"username": s.operator_username, "password": s.operator_password.get_secret_value()},
)
r.raise_for_status()
source_id = (
    args.source_scan
    or json.loads(Path("runs/m3-verification/scan_ids.json").read_text())["labs-good"]
)
source = c.get("/api/scans/" + source_id).json()
r = c.post("/api/scans", json={"scope_version_id": source["scope_version_id"]})
r.raise_for_status()
scan_id = r.json()["id"]
if args.worker_vm:
    from scripts.verify_worker_vm import remote_client

    client = remote_client()
else:
    client = docker.from_env()
deadline = time.monotonic() + 600
print("Waiting for real browser worker", scan_id, flush=True)
while time.monotonic() < deadline:
    workers = client.containers.list(filters={"label": "scopelens.scan_id=" + scan_id})
    browser = next(
        (w for w in workers if w.labels.get("scopelens.run_id", "").endswith("-browser")), None
    )
    # Wait for one captured state to ensure cancellation preserves real browser evidence.
    if browser and b"SCOPELENS_ARTIFACT " in browser.logs(stdout=True, stderr=False):
        break
    time.sleep(0.2)
else:
    raise AssertionError("browser did not start")
started = time.monotonic()
r = c.post("/api/scans/" + scan_id + "/cancel")
r.raise_for_status()
admission_stop = time.monotonic() - started
while time.monotonic() - started < 30:
    workers = client.containers.list(filters={"label": "scopelens.scan_id=" + scan_id})
    if not workers:
        break
    time.sleep(0.1)
else:
    raise AssertionError("worker stop exceeded 30 seconds")
run_stop = time.monotonic() - started
for _ in range(50):
    evidence = c.get(f"/api/scans/{scan_id}/evidence").json()
    if any(e["producer"] == "reviewed_browser_capture" for e in evidence):
        break
    time.sleep(0.2)
else:
    raise AssertionError("partial browser evidence missing")
report = c.get(f"/api/scans/{scan_id}/export.json").json()
assert report["scan"]["status"] == "cancelled"
assert report["score"]["score"] is None
result = {
    "scan_id": scan_id,
    "cancel_commit_seconds": round(admission_stop, 3),
    "worker_stop_seconds": round(run_stop, 3),
    "partial_browser_evidence": True,
}
assert admission_stop < 5 and run_stop < 30
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2) + "\n")
print(result, flush=True)
