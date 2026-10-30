"""Exercise deployed browser workflows through API, broker, VM, evidence and reports.

Only the exact synthetic labs-browser-workflows binding is used. No external URLs
or credentials are accepted. All six cases run sequentially over disposable records.
"""

import argparse
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from scopelens.config import Settings
from scopelens.expansion.proof_aggregation import BROWSER_WORKFLOW_CONTROLS


def configuration(scope, foreign, variant, family):
    base = scope["origin"] + "/" + variant
    identities = [
        {
            "id": role,
            "role": role,
            "login": {
                "request": {"method": "POST", "url": base + "/login", "json_body": {"role": role}}
            },
            "probe": {"request": {"url": base + "/identity"}, "expected_identity": role},
        }
        for role in ("A", "B")
    ]
    recipe = {
        "id": family + "_" + variant,
        "family": family,
        "resource_id": variant,
        "action_grant_id": "owned-disposable-browser-fixture-v1",
        "authority": "lab",
        "disposable": True,
        "synchronous_write": True,
        "actor_identity": "A",
        "viewer_identity": "A" if family == "csrf" else "B",
        "cleanup_identity": "A",
        "readback": {"url": base + "/record"},
        "seed": {"pointer": "/seed", "value": "scopelens-disposable-record"},
        "before": {"pointer": "/content", "value": ""},
        "mutation": {
            "method": "POST",
            "url": base + ("/upload" if family == "upload_serving" else "/mutate"),
        },
        "mutation_field": "content",
        "cleanup": {"method": "POST", "url": base + "/cleanup"},
        "viewer_url": base + ("/file" if family == "upload_serving" else "/viewer"),
    }
    if family == "csrf":
        recipe["foreign_url"] = foreign["origin"] + "/foreign"
    if family == "upload_serving":
        recipe.update(
            upload_form_url=base + "/form",
            upload_selector='input[name="file"]',
            upload_submit_selector='button[type="submit"]',
        )
    return {
        "scope_version_id": scope["id"],
        "identities": identities,
        "browser_workflows": [recipe],
        "related_origins": [
            {
                "origin": foreign["origin"],
                "purpose": "scan",
                "grant_id": "controlled-local-foreign-port",
                "scope_version_id": foreign["id"],
            }
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/expanded-browser-deployed"))
    parser.add_argument(
        "--families",
        nargs="+",
        choices=list(BROWSER_WORKFLOW_CONTROLS),
        default=list(BROWSER_WORKFLOW_CONTROLS),
    )
    parser.add_argument("--variants", nargs="+", choices=["bad", "fixed"], default=["bad", "fixed"])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    settings = Settings()
    receipts = []
    with httpx.Client(base_url="http://127.0.0.1:8090", timeout=30) as client:

        def post(path, payload):
            response = client.post(path, json=payload)
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

        def scope(port):
            return post(
                "/api/scopes",
                {
                    "authority_domain": "lab",
                    "scheme": "http",
                    "lab_service": "labs-browser-workflows",
                    "lab_port": port,
                    "allowed_methods": ["GET", "HEAD", "POST"],
                    "allowed_check_profile": "staging-stateful-v1",
                    "authorization_expires_at": (
                        datetime.now(UTC) + timedelta(hours=2)
                    ).isoformat(),
                },
            )

        primary, foreign = scope(8080), scope(8081)
        for family in args.families:
            for variant in args.variants:
                config = post(
                    "/api/assessments/configurations",
                    configuration(primary, foreign, variant, family),
                )
                scan = post(
                    "/api/scans",
                    {
                        "scope_version_id": primary["id"],
                        "assessment_configuration_id": config["id"],
                        "adaptive": False,
                    },
                )
                ident = scan["id"]
                print(f"{family}/{variant}: scan {ident}", flush=True)
                (args.output / f"{family}-{variant}-scan-id.txt").write_text(ident)
                deadline = time.monotonic() + 600
                while time.monotonic() < deadline:
                    state = get(f"/api/scans/{ident}").json()["status"]
                    if state in {"completed", "completed_partial", "failed", "cancelled"}:
                        break
                    time.sleep(2)
                else:
                    post(f"/api/scans/{ident}/cancel", {})
                    raise AssertionError("lab scan timed out; cancellation requested")
                report_response = get(f"/api/scans/{ident}/export.json")
                html = get(f"/api/scans/{ident}/export.html").text
                evidence = get(f"/api/scans/{ident}/evidence").json()
                prefix = args.output / f"{family}-{variant}"
                prefix.with_suffix(".json").write_text(report_response.text)
                prefix.with_suffix(".html").write_text(html)
                report = report_response.json()
                outcome = next(
                    o
                    for o in report["check_outcomes"]
                    if o["check_id"] == BROWSER_WORKFLOW_CONTROLS[family]
                )
                expected = "confirmed_issue" if variant == "bad" else "pass"
                assert outcome["status"] == expected, {"scan": ident, "outcome": outcome}
                assert outcome["completed_instances"] == [family + "_" + variant], outcome
                assert outcome["evidence_refs"], outcome
                assert any(
                    e["producer"] == "reviewed_expansion_browser_capture" and e["trusted"]
                    for e in evidence
                )
                assert family + "_" + variant in html
                receipt = {
                    "scan_id": ident,
                    "family": family,
                    "variant": variant,
                    "status": state,
                    "control_status": outcome["status"],
                    "completed_instances": outcome["completed_instances"],
                    "proof_refs": outcome["evidence_refs"],
                }
                receipts.append(receipt)
                (args.output / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
                print(
                    f"  {expected}; cleanup and coverage complete; HTML/JSON exported", flush=True
                )


if __name__ == "__main__":
    main()
