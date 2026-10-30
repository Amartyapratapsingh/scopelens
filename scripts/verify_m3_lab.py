"""Owned-lab M3 gate. Requires make run-m3; saves redacted exports and verifies runtime evidence."""

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from scopelens.config import Settings


def main():
    settings = Settings()
    out = Path("runs/m3-verification")
    out.mkdir(parents=True, exist_ok=True)
    client = httpx.Client(base_url="http://127.0.0.1:8090", timeout=20)
    login = client.post(
        "/api/auth/login",
        json={
            "username": settings.operator_username,
            "password": settings.operator_password.get_secret_value(),
        },
    )
    login.raise_for_status()
    ids = {}
    for name in ["labs-good", "labs-bad"]:
        response = client.post(
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
        response.raise_for_status()
        response = client.post("/api/scans", json={"scope_version_id": response.json()["id"]})
        response.raise_for_status()
        ids[name] = response.json()["id"]
    (out / "scan_ids.json").write_text(json.dumps(ids))
    print("Started owned fixture scans", ids, flush=True)
    for name, scan_id in ids.items():
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            status = client.get(f"/api/scans/{scan_id}").json()["status"]
            if status in {"completed", "completed_partial", "failed", "cancelled"}:
                break
            time.sleep(2)
        else:
            raise AssertionError("scan timed out")
        for suffix in ["export.json", "export.html", "summary", "browser", "scanners", "evidence"]:
            response = client.get(f"/api/scans/{scan_id}/{suffix}")
            response.raise_for_status()
            (out / f"{name}-{suffix}").write_text(response.text)
        report = json.loads((out / f"{name}-export.json").read_text())
        tools = {item["tool"]: item for item in report["scanner_results"]}
        print(
            name,
            status,
            {
                name: (r["state"], len(r["observations"]), r.get("assessed_rule_ids"))
                for name, r in tools.items()
            },
            flush=True,
        )
        assert tools["zap"]["state"] == "completed", tools["zap"]["errors"]
        assert tools["nuclei"]["state"] == "completed", tools["nuclei"]["errors"]
        assert any(
            "TLS1_2" in rule or "TLS1_3" in rule for rule in tools["testssl"]["assessed_rule_ids"]
        ), tools["testssl"]
        assert len(tools["conditional-config"]["observations"]) == 2
        endpoints = report["attack_surface"]["endpoints"]
        assert any(
            e["route"] == "/browser-only.json" and e["discovered_via"] == "browser"
            for e in endpoints
        )
        assert not any(
            e["route"] == "/browser-only.json" and e["discovered_via"] != "browser"
            for e in endpoints
        )
        browser = client.get(f"/api/scans/{scan_id}/browser").json()
        assert (
            browser["states"]
            and browser["actions"]
            and browser["context_id"]
            and not browser["gaps"]
        ), browser
        assert browser["evidence_refs"]
        records = {r["id"]: r for r in client.get(f"/api/scans/{scan_id}/evidence").json()}
        captures = []
        for ref in browser["evidence_refs"]:
            response = client.get(f"/api/scans/{scan_id}/evidence/{ref}/download")
            response.raise_for_status()
            assert response.headers["x-content-type-options"] == "nosniff"
            assert records[ref]["producer_hash"] and records[ref]["run_id"]
            assert hashlib.sha256(response.content).hexdigest() == records[ref]["content_hash"]
            captures.append(response.json())
        assert any(a["kind"] == "browser_state" and a["data"]["screenshot_jpeg"] for a in captures)
        assert len(report["findings"]) == (0 if name == "labs-good" else 12)
        own_ids = {f["id"] for f in report["findings"]}
        for tool in tools.values():
            for observation in tool["observations"]:
                assert observation["status"] == "potential"
                if observation["finding_id"]:
                    assert observation["finding_id"] in own_ids
        print(
            name,
            "browser-only state, source provenance, scanner observations and exports verified",
            flush=True,
        )
    print("M3 lab gate passed", flush=True)


if __name__ == "__main__":
    main()
