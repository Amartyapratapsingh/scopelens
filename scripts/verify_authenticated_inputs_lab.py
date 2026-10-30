"""Verify encrypted credential resolution and existing authenticated redirect checks.

Only labs-browser-workflows:8080 is registered. This script accepts no external target
or credentials; the fixture password is public synthetic test data. It never follows
redirects to the collector's .invalid marker destinations.
"""

import argparse
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from scopelens.config import Settings
from scopelens.domain.expansion import AssessmentConfiguration

FIXTURE_PASSWORD = "scopelens-synthetic-role-A-password"
CONTROL = "SL-C04-REDIRECT-01"


def configuration(scope, variant, credential_reference):
    path = f"/{variant}/protected-redirect"
    base = scope["origin"] + "/" + variant
    template_id = "authenticated-redirect-" + variant
    return {
        "scope_version_id": scope["id"],
        "identities": [
            {
                "id": "A",
                "role": "fixture-reader",
                "login": {
                    "request": {
                        "method": "POST",
                        "url": base + "/credential-login",
                        "json_body": {"role": "A"},
                        "secret_fields": {"password": credential_reference},
                    }
                },
                "probe": {"request": {"url": base + "/identity"}, "expected_identity": "A"},
            }
        ],
        "templates": [
            {
                "id": template_id,
                "origin": scope["origin"],
                "path": path,
                "route_template": path,
                "method": "GET",
                "role_id": "A",
                "baseline_complete": True,
                "baseline_observed": False,
                "provenance": ["operator-reviewed-disposable-authenticated-fixture"],
                "inputs": [
                    {
                        "location": "query",
                        "name": "next",
                        "baseline_value": "/safe",
                        "required": True,
                        "mutable": True,
                    }
                ],
            }
        ],
        "policies": [
            {
                "template_id": template_id,
                "role_id": "A",
                "classification": "read_only",
                "approval_ref": "owned-authenticated-redirect-fixture-v1",
                "control_ids": [CONTROL],
            }
        ],
    }


def verify_report(report, html, evidence, captures, variant):
    expected = "confirmed_issue" if variant == "bad" else "pass"
    outcome = next(row for row in report["check_outcomes"] if row["check_id"] == CONTROL)
    assert outcome["status"] == expected, {
        "control": CONTROL,
        "status": outcome["status"],
        "summary": outcome["summary"],
    }
    assert outcome["required_instances"] and set(outcome["required_instances"]) == set(
        outcome["completed_instances"]
    ), "authenticated task coverage incomplete"
    assert outcome["evidence_refs"], "trusted authenticated input proof missing"
    metadata = {row["id"]: row for row in evidence}
    for ref in outcome["evidence_refs"]:
        assert (
            metadata[ref]["trusted"] and metadata[ref]["producer"] == "reviewed_expansion_capture"
        )
        capture = captures[ref]
        assert capture["kind"] == "expanded_active_probe"
        data = capture["data"]
        assert data["control_id"] == CONTROL and data["role_id"] == "A"
        proof = data["identity_proof"]
        assert proof["version"] == "authenticated-input-v1" and proof["role_id"] == "A"
        assert proof["task_id"] == data["task_id"] and proof["plan_id"] == data["plan_id"]
        assert [row["phase"] for row in proof["probes"]] == ["before", "after"]
        assert all(
            row["status"] == 200 and row["observed_identity"] == "A" for row in proof["probes"]
        )
    assert report["profile"] == "authenticated-api-v1"
    assert "authenticated-api-v1" in html and CONTROL in html
    serialized = json.dumps({"report": report, "evidence": evidence, "captures": captures}) + html
    assert FIXTURE_PASSWORD not in serialized, "fixture secret leaked into exported output"
    assert "sid=A" not in serialized, "session cookie leaked into exported output"
    return outcome


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/authenticated-inputs-deployed"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    settings = Settings()
    receipts = []
    with httpx.Client(
        base_url="http://127.0.0.1:8090", timeout=30, follow_redirects=False
    ) as client:

        def post(path, value):
            response = client.post(path, json=value)
            response.raise_for_status()
            return response.json()

        def get(path):
            response = client.get(path)
            response.raise_for_status()
            return response

        post(
            "/api/auth/login",
            {
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        expires = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        scope = post(
            "/api/scopes",
            {
                "authority_domain": "lab",
                "scheme": "http",
                "lab_service": "labs-browser-workflows",
                "lab_port": 8080,
                "allowed_methods": ["GET", "HEAD", "POST"],
                "allowed_check_profile": "authenticated-api-v1",
                "authorization_expires_at": expires,
            },
        )
        credential = post(
            "/api/assessments/credentials",
            {"scope_version_id": scope["id"], "value": FIXTURE_PASSWORD, "expires_at": expires},
        )
        for variant in ("bad", "fixed"):
            frozen = configuration(scope, variant, credential["reference"])
            AssessmentConfiguration.model_validate(frozen)
            config = post("/api/assessments/configurations", frozen)
            scan = post(
                "/api/scans",
                {
                    "scope_version_id": scope["id"],
                    "assessment_configuration_id": config["id"],
                    "adaptive": False,
                },
            )
            ident = scan["id"]
            print(f"authenticated-redirect/{variant}: scan {ident}", flush=True)
            (args.output / f"{variant}-scan-id.txt").write_text(ident)
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                state = get(f"/api/scans/{ident}").json()["status"]
                if state in {"completed", "completed_partial", "failed", "cancelled"}:
                    break
                time.sleep(2)
            else:
                post(f"/api/scans/{ident}/cancel", {})
                raise AssertionError(
                    "authenticated lab scan exceeded deadline; cancellation requested"
                )
            report_response = get(f"/api/scans/{ident}/export.json")
            report = report_response.json()
            html = get(f"/api/scans/{ident}/export.html").text
            evidence = get(f"/api/scans/{ident}/evidence").json()
            outcome = next(row for row in report["check_outcomes"] if row["check_id"] == CONTROL)
            captures = {
                ref: get(f"/api/scans/{ident}/evidence/{ref}/download").json()
                for ref in outcome["evidence_refs"]
            }
            # Check redaction before writing report/evidence artifacts to disk.
            verified = verify_report(report, html, evidence, captures, variant)
            (args.output / f"{variant}.json").write_text(report_response.text)
            (args.output / f"{variant}.html").write_text(html)
            (args.output / f"{variant}-identity-proof.json").write_text(
                json.dumps(captures, indent=2)
            )
            receipt = {
                "scan_id": ident,
                "variant": variant,
                "scan_status": state,
                "control_status": verified["status"],
                "proof_refs": verified["evidence_refs"],
                "completed_instances": verified["completed_instances"],
            }
            receipts.append(receipt)
            (args.output / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
            print(
                f"  {verified['status']}; before/after identity proof verified; HTML/JSON exported",
                flush=True,
            )


if __name__ == "__main__":
    main()
