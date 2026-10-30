"""Freeze, independently health-check, scan and score the owned validation application."""

import argparse
import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import yaml

from evaluation.protocol import Protocol
from evaluation.run import assess, fetch_evidence, source_fingerprint
from scopelens.config import Settings


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest_path = Path("evaluation/protocols/active-validation.yaml")
    manifest = Protocol.model_validate(yaml.safe_load(manifest_path.read_text())).model_dump()
    freeze = {
        "source_fingerprint": source_fingerprint(),
        "manifest_hash": digest(manifest_path),
        "fixture_hash": digest("labs/fixtures/validation/server.py"),
        "oracle_hash": digest("evaluation/validation_health.py"),
    }
    image = subprocess.check_output(
        ["docker", "image", "inspect", "scopelens/browser-worker:dev", "--format", "{{.Id}}"],
        text=True,
    ).strip()
    freeze["evaluator_image"] = image
    (args.output / "freeze.json").write_text(json.dumps(freeze, indent=2))
    health = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "scopelens_labs_net",
            "--shm-size=256m",
            "--security-opt",
            "seccomp=" + str(Path("deploy/browser/seccomp.json").resolve()),
            "-v",
            str(Path("evaluation/validation_health.py").resolve()) + ":/oracle.py:ro",
            image,
            "python",
            "/oracle.py",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    (args.output / "health.log").write_text(health.stdout + health.stderr)
    health.check_returncode()
    record = json.loads(health.stdout)
    expected = {c["route"]: c["label"] == "vulnerable" for c in manifest["cases"]}
    assert {r["route"]: r["condition_present"] for r in record["cases"]} == expected
    settings = Settings()
    with httpx.Client(base_url="http://127.0.0.1:8090", timeout=20) as client:
        client.post(
            "/api/auth/login",
            json={
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        ).raise_for_status()
        response = client.post(
            "/api/scopes",
            json={
                "authority_domain": "lab",
                "scheme": "http",
                "lab_service": "labs-validation",
                "lab_port": 8080,
                "allowed_check_profile": "external-dast",
                "authorization_expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
            },
        )
        response.raise_for_status()
        response = client.post(
            "/api/scans", json={"scope_version_id": response.json()["id"], "adaptive": False}
        )
        response.raise_for_status()
        scan_id = response.json()["id"]
        (args.output / "scan-id.txt").write_text(scan_id)
        print("Validation scan", scan_id, "on isolated labs-validation", flush=True)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            response = client.get(f"/api/scans/{scan_id}")
            response.raise_for_status()
            if response.json()["status"] in {
                "completed",
                "completed_partial",
                "failed",
                "cancelled",
            }:
                break
            time.sleep(2)
        else:
            client.post(f"/api/scans/{scan_id}/cancel").raise_for_status()
            raise RuntimeError("validation timed out; cancelled")
        exports = {}
        for fmt in ["json", "html"]:
            response = client.get(f"/api/scans/{scan_id}/export.{fmt}")
            response.raise_for_status()
            (args.output / f"labs-validation-export.{fmt}").write_text(response.text)
            if fmt == "json":
                exports["labs-validation"] = response.json()
        result = assess(manifest, exports, {"labs-validation": fetch_evidence(client, scan_id)})
        if (
            freeze["source_fingerprint"] != source_fingerprint()
            or freeze["manifest_hash"] != digest(manifest_path)
            or freeze["fixture_hash"] != digest("labs/fixtures/validation/server.py")
        ):
            raise RuntimeError("Inputs changed during run; measurement disqualified")
        (args.output / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result["aggregate"], indent=2), flush=True)


if __name__ == "__main__":
    main()
