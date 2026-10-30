#!/usr/bin/env python3
"""Verify the owned lab pair and a CSP fix/regression retest; always restore lab config.

Requires make labs-up and the dev stack. Writes redacted reports under runs/m2-verification.
Temporarily changes only the bad fixture's CSP header, then restores and reloads nginx.
"""

import json
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from scopelens.config import Settings


def main():
    settings = Settings()
    output = Path("runs/m2-verification")
    output.mkdir(parents=True, exist_ok=True)
    client = httpx.Client(base_url="http://127.0.0.1:8090", timeout=20)
    response = client.post(
        "/api/auth/login",
        json={
            "username": settings.operator_username,
            "password": settings.operator_password.get_secret_value(),
        },
    )
    response.raise_for_status()

    def request(method, path, **kwargs):
        response = client.request(method, path, **kwargs)
        response.raise_for_status()
        return response

    def complete(scan_id, label):
        for _ in range(180):
            detail = request("GET", f"/api/scans/{scan_id}").json()
            if detail["status"] in {"completed", "completed_partial", "cancelled", "failed"}:
                break
            time.sleep(2)
        else:
            raise RuntimeError("Lab scan did not finish")
        assert detail["status"] == "completed", detail["status_reason"]
        for suffix in ["summary", "export.json", "export.html"]:
            response = request("GET", f"/api/scans/{scan_id}/{suffix}")
            (output / f"{label}-{suffix}").write_text(response.text)
        return request("GET", f"/api/scans/{scan_id}/summary").json()

    ids, summaries = {}, {}
    for name in ["labs-good", "labs-bad"]:
        scope = request(
            "POST",
            "/api/scopes",
            json={
                "authority_domain": "lab",
                "scheme": "https",
                "lab_service": name,
                "lab_port": 8443,
                "transport_http_port": 80,
                "authorization_expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
        ).json()
        scan = request("POST", "/api/scans", json={"scope_version_id": scope["id"]}).json()
        ids[name] = scan["id"]
        summaries[name] = complete(scan["id"], name)
        print(name, json.dumps(summaries[name]), flush=True)
    assert summaries["labs-good"]["findings_count"] == 0
    assert (
        "No issues found in the checks that completed"
        in (output / "labs-good-export.html").read_text()
    )
    findings = request("GET", f"/api/scans/{ids['labs-bad']}/findings").json()
    finding = next(f for f in findings if f["check_id"] == "SL-C04-CSP-01")
    config = Path("labs/fixtures/bad/nginx.conf")
    original = config.read_text()

    def reload_fixture():
        subprocess.run(
            ["docker", "exec", "scopelens-labs-bad", "nginx", "-t"], check=True, capture_output=True
        )
        subprocess.run(
            ["docker", "exec", "scopelens-labs-bad", "nginx", "-s", "reload"],
            check=True,
            capture_output=True,
        )
        time.sleep(0.5)

    def retest(label, expected):
        fresh = request("POST", f"/api/findings/{finding['id']}/retest").json()
        complete(fresh["scan_id"], label)
        current = request("GET", f"/api/findings/{finding['id']}").json()
        assert current["retest_state"] == expected, current["retest_state"]
        assert current["status"] == ("resolved" if expected == "fixed" else "open")
        print(label, current["retest_state"], current["status"], flush=True)
        ids[label] = fresh["scan_id"]

    try:
        # Add at http scope, inherited by all servers/locations unless overridden.
        # The bad fixture has local add_header blocks, so add alongside each one.
        lines = []
        for line in original.splitlines(True):
            lines.append(line)
            if "add_header" in line and not line.lstrip().startswith("#"):
                indent = line[: len(line) - len(line.lstrip())]
                lines.append(
                    indent
                    + "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none'; object-src 'none'\" always;\n"
                )
        config.write_text("".join(lines))
        reload_fixture()
        retest("retest-fixed", "fixed")
    finally:
        config.write_text(original)
        reload_fixture()
    retest("retest-regression", "still_present")
    (output / "scan_ids.json").write_text(json.dumps(ids, indent=2))
    (output / "verification.json").write_text(
        json.dumps({"scans": summaries, "retest": ["fixed", "still_present"]}, indent=2)
    )
    client.close()


if __name__ == "__main__":
    main()
