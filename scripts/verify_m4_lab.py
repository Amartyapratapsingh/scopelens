"""Execute every active control and adaptive follow-up on the owned paired labs."""

import argparse
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from scopelens.config import Settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/m4-verification"))
    parser.add_argument(
        "--fixtures",
        nargs="+",
        choices=["labs-good", "labs-bad"],
        default=["labs-good", "labs-bad"],
    )
    parser.add_argument("--require-models", action="store_true")
    args = parser.parse_args()
    settings = Settings()
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    with httpx.Client(base_url="http://127.0.0.1:8090", timeout=20) as client:
        r = client.post(
            "/api/auth/login",
            json={
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        r.raise_for_status()
        for name in args.fixtures:
            r = client.post(
                "/api/scopes",
                json={
                    "authority_domain": "lab",
                    "scheme": "https",
                    "lab_service": name,
                    "lab_port": 8443,
                    "transport_http_port": 80,
                    "allowed_check_profile": "external-dast",
                    "authorization_expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
                },
            )
            r.raise_for_status()
            r = client.post("/api/scans", json={"scope_version_id": r.json()["id"]})
            r.raise_for_status()
            scan_id = r.json()["id"]
            print(name, scan_id, flush=True)
            (out / (name + "-scan-id.txt")).write_text(scan_id)
            deadline = time.monotonic() + 600
            statuses = []
            while time.monotonic() < deadline:
                status = client.get("/api/scans/" + scan_id).json()["status"]
                if not statuses or statuses[-1] != status:
                    statuses.append(status)
                if status in {"completed", "completed_partial", "failed", "cancelled"}:
                    break
                time.sleep(2)
            else:
                raise AssertionError("Scan did not finish")
            for suffix in [
                "export.json",
                "export.html",
                "summary",
                "evidence",
                "browser",
                "scanners",
            ]:
                r = client.get(f"/api/scans/{scan_id}/{suffix}")
                r.raise_for_status()
                (out / (name + "-" + suffix)).write_text(r.text)
            report = json.loads((out / (name + "-export.json")).read_text())
            (out / (name + "-statuses.json")).write_text(json.dumps(statuses))
            if args.require_models:
                calls = report["assessment_plan"].get("model_calls", [])
                assert calls and all(c["state"] != "outcome_unknown" for c in calls)
                completed = {c["role"] for c in calls if c["state"] == "completed"}
                required = {"script"}
                if name == "labs-bad":
                    required |= {"planner", "verification", "report_writer"}
                    assert "reporting" in statuses
                    assert report["assessment_plan"].get("report_prose")
                assert required <= completed, completed
                assert report["assessment_plan"]["generated_analysis"]["state"] == "completed"
            controls = {r["check_id"]: r for r in report["check_outcomes"]}
            active = {
                k: v["status"]
                for k, v in controls.items()
                if k
                in {
                    "SL-C03-XSS-01",
                    "SL-C03-HTML-01",
                    "SL-C03-SQL-01",
                    "SL-C04-REDIRECT-01",
                    "SL-C04-CORS-01",
                }
            }
            print(name, status, active, flush=True)
            assert len(active) == 5
            assert set(active.values()) == (
                {"pass"} if name == "labs-good" else {"confirmed_issue"}
            ), active
            if name == "labs-bad":
                hypotheses = report["assessment_plan"].get("hypotheses", [])
                assert any(h["state"] == "corroborated" for h in hypotheses), hypotheses
            assert len(report["findings"]) == (0 if name == "labs-good" else 17)
            if name == "labs-good":
                assert (
                    "No issues found in the checks that completed"
                    in (out / "labs-good-export.html").read_text()
                )
    print("M4 paired active controls and adaptive follow-up passed", flush=True)


if __name__ == "__main__":
    main()
