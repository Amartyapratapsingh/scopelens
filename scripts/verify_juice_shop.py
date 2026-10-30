"""Development assessment of the pinned local Juice Shop, with evaluator-only health."""

import argparse
import json
import shutil
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from scopelens.config import Budgets, Settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile("runs/release/freeze.json", args.output / "runtime-freeze.json")
    health = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "scopelens_labs_net",
            "-v",
            str(Path("evaluation/juice_health.py").resolve()) + ":/health.py:ro",
            "--entrypoint",
            "python",
            "scopelens/browser-worker:dev",
            "/health.py",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    (args.output / "health.log").write_text(health.stdout + health.stderr)
    health.check_returncode()
    settings = Settings()
    with httpx.Client(base_url="http://127.0.0.1:8090", timeout=25) as client:
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
                "lab_service": "juice-shop",
                "lab_port": 3000,
                "allowed_check_profile": "external-dast",
                "excluded_paths": [
                    "/api/Challenges",
                    "/rest/challenges",
                    "/rest/admin",
                    "/rest/score-board",
                    "/score-board",
                ],
                "authorization_expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
                "budgets_override": Budgets(
                    max_pages=100, max_total_requests=500, wall_clock_seconds=600
                ).model_dump(),
                "owner_note": "Pinned synthetic development lab; evaluator labels and challenge APIs excluded",
            },
        )
        response.raise_for_status()
        response = client.post(
            "/api/scans", json={"scope_version_id": response.json()["id"], "adaptive": False}
        )
        response.raise_for_status()
        scan_id = response.json()["id"]
        (args.output / "scan-id.txt").write_text(scan_id)
        print("Juice Shop development scan", scan_id, flush=True)
        terminal = False
        try:
            deadline = time.monotonic() + 660
            while time.monotonic() < deadline:
                response = client.get(f"/api/scans/{scan_id}")
                response.raise_for_status()
                if response.json()["status"] in {
                    "completed",
                    "completed_partial",
                    "failed",
                    "cancelled",
                }:
                    terminal = True
                    break
                time.sleep(2)
            if not terminal:
                raise RuntimeError("Juice Shop assessment deadline exceeded")
            for suffix in ["export.json", "export.html", "summary", "browser", "scanners"]:
                response = client.get(f"/api/scans/{scan_id}/{suffix}")
                response.raise_for_status()
                (args.output / suffix).write_text(response.text)
            report = json.loads((args.output / "export.json").read_text())
            sql = next(c for c in report["check_outcomes"] if c["check_id"] == "SL-C03-SQL-01")
            assert sql["status"] == "confirmed_issue", sql
            assert "/rest/products/search" in sql["completed_instances"]
            print(
                "Confirmed paired SQL behavior on the public search endpoint; report retained",
                flush=True,
            )
        finally:
            if not terminal:
                client.post(f"/api/scans/{scan_id}/cancel").raise_for_status()


if __name__ == "__main__":
    main()
