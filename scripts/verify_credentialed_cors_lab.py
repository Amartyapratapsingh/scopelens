"""Deployed native-browser credentialed CORS gate on owned synthetic lab origins.

Cross-origin, same-site (ports 8080/8081) only. No protected record writes. The
fixed case remains inconclusive rather than converting a blocked read into a pass.
"""

import argparse
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from scripts.verify_authenticated_inputs_lab import FIXTURE_PASSWORD

from scopelens.config import Settings

CONTROL = "SL-C04-CORSDATA-01"
MARKER = "scopelens-owned-cors-marker-84721"


def configuration(primary, foreign, variant, reference):
    base = primary["origin"] + "/" + variant
    return {
        "scope_version_id": primary["id"],
        "related_origins": [
            {
                "origin": foreign["origin"],
                "purpose": "scan",
                "grant_id": "owned-cors-foreign-page",
                "scope_version_id": foreign["id"],
            }
        ],
        "identities": [
            {
                "id": "A",
                "role": "synthetic-owner",
                "login": {
                    "request": {
                        "method": "POST",
                        "url": base + "/credential-login",
                        "json_body": {"role": "A"},
                        "secret_fields": {"password": reference},
                    }
                },
                "probe": {"request": {"url": base + "/identity"}, "expected_identity": "A"},
            },
            {"id": "anonymous", "role": "anonymous", "anonymous": True},
        ],
        "cors_recipes": [
            {
                "id": "credentialed-cors-" + variant,
                "foreign_url": foreign["origin"] + "/foreign",
                "foreign_scope_version_id": foreign["id"],
                "foreign_grant_id": "owned-cors-foreign-page",
                "target": {
                    "id": "static-synthetic-cors-record",
                    "owner_identity": "A",
                    "request": {"url": base + "/cors-record"},
                    "marker_pointer": "/private",
                    "marker": MARKER,
                },
            }
        ],
    }


def verify(report, html, evidence, captures, variant, foreign):
    expected = "confirmed_issue" if variant == "bad" else "inconclusive"
    outcome = next(row for row in report["check_outcomes"] if row["check_id"] == CONTROL)
    assert outcome["status"] == expected, outcome
    assert bool(outcome["completed_instances"]) == (variant == "bad")
    assert outcome["required_instances"] == ["credentialed-cors-" + variant]
    assert outcome["evidence_refs"], "trusted browser facts missing"
    by_id = {row["id"]: row for row in evidence}
    for ref in outcome["evidence_refs"]:
        assert (
            by_id[ref]["trusted"] and by_id[ref]["producer"] == "reviewed_expansion_browser_capture"
        )
        data = captures[ref]["data"]
        assert data["kind"] == "credentialed_cors_proof" and data["error"] is None
        assert data["context_ids"]["A"] != data["context_ids"]["anonymous"]
        facts = data["facts"]
        assert [row["phase"] for row in facts] == [
            "before",
            "owner_baseline",
            "anonymous_baseline",
            "foreign_page",
            "read_1",
            "read_2",
            "after",
        ]
        assert facts[0]["observed_identity"] == facts[-1]["observed_identity"] == "A"
        assert facts[1]["selected_value"] == MARKER and facts[2]["status"] == 403
        for row in facts[4:6]:
            assert len(row["requests"]) == 1
            request = row["requests"][0]
            assert request["origin"] == foreign["origin"] and request["cookie_present"]
            assert not request["authorization_present"]
            assert row["readable"] == (variant == "bad")
    serialized = json.dumps({"report": report, "captures": captures, "evidence": evidence}) + html
    assert FIXTURE_PASSWORD not in serialized and "sid=A" not in serialized
    assert CONTROL in html
    return outcome


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/credentialed-cors-deployed"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    settings, receipts = Settings(), []
    with httpx.Client(
        base_url="http://127.0.0.1:8090", timeout=30, follow_redirects=False
    ) as client:

        def post(path, body):
            response = client.post(path, json=body)
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
        expiry = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        base = {
            "authority_domain": "lab",
            "scheme": "http",
            "lab_service": "labs-browser-workflows",
            "allowed_check_profile": "authenticated-api-v1",
            "authorization_expires_at": expiry,
        }
        primary = post(
            "/api/scopes", {**base, "lab_port": 8080, "allowed_methods": ["GET", "HEAD", "POST"]}
        )
        foreign = post(
            "/api/scopes",
            {
                **base,
                "lab_port": 8081,
                "allowed_methods": ["GET", "HEAD"],
                "allowed_path_prefixes": ["/foreign"],
            },
        )
        credential = post(
            "/api/assessments/credentials",
            {"scope_version_id": primary["id"], "value": FIXTURE_PASSWORD, "expires_at": expiry},
        )
        for variant in ("bad", "fixed"):
            frozen = post(
                "/api/assessments/configurations",
                configuration(primary, foreign, variant, credential["reference"]),
            )
            scan = post(
                "/api/scans",
                {
                    "scope_version_id": primary["id"],
                    "assessment_configuration_id": frozen["id"],
                    "adaptive": False,
                },
            )
            ident = scan["id"]
            print(f"credentialed-cors/{variant}: scan {ident}", flush=True)
            (args.output / f"{variant}-scan-id.txt").write_text(ident)
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                status = get(f"/api/scans/{ident}").json()["status"]
                if status in {"completed", "completed_partial", "failed", "cancelled"}:
                    break
                time.sleep(2)
            else:
                post(f"/api/scans/{ident}/cancel", {})
                raise AssertionError("CORS gate exceeded deadline; cancellation requested")
            report = get(f"/api/scans/{ident}/export.json").json()
            html = get(f"/api/scans/{ident}/export.html").text
            evidence = get(f"/api/scans/{ident}/evidence").json()
            outcome = next(row for row in report["check_outcomes"] if row["check_id"] == CONTROL)
            captures = {
                ref: get(f"/api/scans/{ident}/evidence/{ref}/download").json()
                for ref in outcome["evidence_refs"]
            }
            # Keep redacted artifacts even when the gate rejects a runtime result.
            (args.output / f"{variant}-report.json").write_text(json.dumps(report, indent=2))
            (args.output / f"{variant}-report.html").write_text(html)
            (args.output / f"{variant}-proof.json").write_text(json.dumps(captures, indent=2))
            outcome = verify(report, html, evidence, captures, variant, foreign)
            receipts.append(
                {
                    "scan_id": ident,
                    "variant": variant,
                    "scan_status": status,
                    "control_status": outcome["status"],
                    "required_instances": outcome["required_instances"],
                    "completed_instances": outcome["completed_instances"],
                    "evidence_refs": outcome["evidence_refs"],
                    "limitation": "cross-origin same-site ports; no cross-site cookie-policy claim",
                }
            )
            (args.output / "receipts.json").write_text(json.dumps(receipts, indent=2))
            print(
                f"  {outcome['status']}; native browser proof and redacted reports verified",
                flush=True,
            )


if __name__ == "__main__":
    main()
