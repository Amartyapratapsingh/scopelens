"""Run user-authorized bounded origin assessments and save real API reports locally."""

import argparse
import json
import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from scopelens.config import Budgets, Settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("urls", nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    freeze = Path("runs/release/freeze.json")
    if freeze.exists():
        shutil.copyfile(freeze, args.output / "runtime-freeze.json")
    settings = Settings()
    results = []
    with httpx.Client(base_url="http://127.0.0.1:8090", timeout=25) as client:
        client.post(
            "/api/auth/login",
            json={
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        ).raise_for_status()
        for url in args.urls:
            parsed = urlsplit(url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.path not in {"", "/"}
            ):
                raise ValueError("Supply an exact http(s) origin without credentials")
            folder = args.output / parsed.hostname
            folder.mkdir()
            response = client.post(
                "/api/scopes",
                json={
                    "authority_domain": "production",
                    "scheme": parsed.scheme,
                    "host": parsed.hostname,
                    "port": parsed.port,
                    "transport_http_port": 80 if parsed.scheme == "https" else None,
                    "allowed_check_profile": "external-configuration",
                    "authorization_expires_at": (
                        datetime.now(UTC) + timedelta(hours=2)
                    ).isoformat(),
                    "owner_note": "Operator supplied this owned target in the ScopeLens build session on 2026-09-26.",
                    "budgets_override": Budgets(
                        max_pages=100,
                        max_total_requests=500,
                        max_crawl_depth=3,
                        wall_clock_seconds=600,
                    ).model_dump(),
                },
            )
            if response.status_code != 201:
                results.append(
                    {"url": url, "status": "registration_failed", "reason": response.text}
                )
                print(url, "registration failed", response.status_code, flush=True)
                continue
            response = client.post(
                "/api/scans", json={"scope_version_id": response.json()["id"], "adaptive": True}
            )
            response.raise_for_status()
            scan_id = response.json()["id"]
            (folder / "scan-id.txt").write_text(scan_id)
            print(url, "scan", scan_id, flush=True)
            deadline = time.monotonic() + 1260
            execution_deadline = None
            try:
                while time.monotonic() < deadline:
                    response = client.get(f"/api/scans/{scan_id}")
                    response.raise_for_status()
                    state = response.json()
                    if state["status"] != "queued" and execution_deadline is None:
                        execution_deadline = time.monotonic() + 660
                        deadline = min(deadline, execution_deadline)
                    if state["status"] in {"completed", "completed_partial", "failed", "cancelled"}:
                        break
                    time.sleep(2)
                else:
                    client.post(f"/api/scans/{scan_id}/cancel").raise_for_status()
                    raise RuntimeError("deadline exceeded; cancellation requested")
                report = None
                for suffix in ["export.json", "export.html", "summary", "scanners", "browser"]:
                    response = client.get(f"/api/scans/{scan_id}/{suffix}")
                    response.raise_for_status()
                    (folder / suffix).write_text(response.text)
                    if suffix == "export.json":
                        report = response.json()
                summary = {
                    "url": url,
                    "scan_id": scan_id,
                    "status": state["status"],
                    "budget_spent": state["budget_spent"],
                    "findings": [
                        {
                            k: f.get(k)
                            for k in [
                                "id",
                                "check_id",
                                "severity",
                                "evidence_status",
                                "title",
                                "locations",
                            ]
                        }
                        for f in report["findings"]
                    ],
                }
                results.append(summary)
                print(url, state["status"], len(report["findings"]), "findings", flush=True)
            except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
                results.append(
                    {"url": url, "scan_id": scan_id, "error": type(exc).__name__ + ": " + str(exc)}
                )
                print(url, "incomplete:", type(exc).__name__, flush=True)
            finally:
                (args.output / "summary.json").write_text(json.dumps(results, indent=2))
        (args.output / "summary.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
