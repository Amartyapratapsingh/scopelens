"""Deployed owned-lab OpenAPI/HAR -> immutable configuration -> proof/report gate.

Uses only the existing synthetic authenticated redirect fixture. Does not exercise a
public resume API: coordinator-side revisions have separate durable integration tests.
"""

import argparse
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from scripts.verify_authenticated_inputs_lab import (
    CONTROL,
    FIXTURE_PASSWORD,
    configuration,
    verify_report,
)

from scopelens.config import Settings


def import_document(scope, variant, kind):
    path = f"/{variant}/protected-redirect"
    if kind == "openapi":
        return {
            "openapi": "3.0.0",
            "servers": [{"url": scope["origin"]}],
            "paths": {
                path: {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "next",
                                "example": "private-import-sample",
                                "schema": {"type": "string"},
                            }
                        ]
                    }
                }
            },
        }
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": scope["origin"] + path + "?next=private-import-sample",
                        "method": "GET",
                        "headers": [{"name": "Cookie", "value": "sid=private-import-cookie"}],
                    },
                    "response": {"content": {"text": "private-import-body"}},
                }
            ]
        }
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/import-intake-deployed"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    settings = Settings()
    receipts = []
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
        expires = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        primary = post(
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
            {"scope_version_id": primary["id"], "value": FIXTURE_PASSWORD, "expires_at": expires},
        )
        for kind, variant in (("openapi", "bad"), ("har", "fixed")):
            normalized = post(
                "/api/assessments/imports",
                {
                    "scope_version_id": primary["id"],
                    "kind": kind,
                    "role_id": "A",
                    "document": import_document(primary, variant, kind),
                },
            )
            assert "private-import-" not in json.dumps(normalized)
            assert len(normalized["catalogue"]["templates"]) == 1
            template = normalized["catalogue"]["templates"][0]
            assert not template["baseline_complete"]
            frozen = configuration(primary, variant, credential["reference"])
            frozen["imports"] = [normalized]
            frozen["templates"][0]["id"] = template["id"]
            frozen["policies"][0]["template_id"] = template["id"]
            saved = post("/api/assessments/configurations", frozen)
            assert "private-import-" not in json.dumps(saved)
            scan = post(
                "/api/scans",
                {
                    "scope_version_id": primary["id"],
                    "assessment_configuration_id": saved["id"],
                    "adaptive": False,
                },
            )
            ident = scan["id"]
            (args.output / f"{kind}-scan-id.txt").write_text(ident)
            print(f"import/{kind}/{variant}: scan {ident}", flush=True)
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                state = get(f"/api/scans/{ident}").json()["status"]
                if state in {"completed", "completed_partial", "failed", "cancelled"}:
                    break
                time.sleep(2)
            else:
                post(f"/api/scans/{ident}/cancel", {})
                raise AssertionError("import lab scan exceeded deadline; cancellation requested")
            report = get(f"/api/scans/{ident}/export.json").json()
            html = get(f"/api/scans/{ident}/export.html").text
            evidence = get(f"/api/scans/{ident}/evidence").json()
            outcome = next(o for o in report["check_outcomes"] if o["check_id"] == CONTROL)
            captures = {
                ref: get(f"/api/scans/{ident}/evidence/{ref}/download").json()
                for ref in outcome["evidence_refs"]
            }
            verify_report(report, html, evidence, captures, variant)
            history = get(f"/api/assessments/scans/{ident}/plans").json()
            assert len(history["revisions"]) == 1 and history["execution_claims"] >= 1
            revision = history["revisions"][0]
            assert template["id"] in revision["catalogue"]["template_ids"]
            assert revision["plan"]["denominator"] == sum(
                t["coverage_weight"] for t in revision["plan"]["tasks"]
            )
            serialized = json.dumps({"report": report, "history": history}) + html
            assert (
                "private-import-" not in serialized
                and FIXTURE_PASSWORD not in serialized
                and "sid=A" not in serialized
            )
            (args.output / f"{kind}-report.json").write_text(json.dumps(report, indent=2))
            (args.output / f"{kind}-report.html").write_text(html)
            (args.output / f"{kind}-plans.json").write_text(json.dumps(history, indent=2))
            receipts.append(
                {
                    "kind": kind,
                    "variant": variant,
                    "scan_id": ident,
                    "status": state,
                    "control_status": outcome["status"],
                    "source_sha256": normalized["source_sha256"],
                    "plan_id": revision["plan"]["id"],
                    "denominator": revision["plan"]["denominator"],
                    "execution_claims": history["execution_claims"],
                }
            )
            (args.output / "receipts.json").write_text(json.dumps(receipts, indent=2))
            print(
                f"  {outcome['status']}; frozen import and trusted identity proof verified",
                flush=True,
            )


if __name__ == "__main__":
    main()
