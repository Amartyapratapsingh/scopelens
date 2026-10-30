"""Deployed gate for authenticated HTML rendering on the owned isolated browser lab.

Uses the credential API and frozen single-control policy. Accepts no target URL or
credentials. Does not mutate fixture records or follow redirects.
"""

import argparse
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from scripts.verify_authenticated_inputs_lab import FIXTURE_PASSWORD
from scripts.verify_authenticated_inputs_lab import configuration as base_configuration

from scopelens.config import Settings
from scopelens.discovery.planner import plan_assessment
from scopelens.domain.assessment import DiscoveryCatalogue
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.authenticated_browser import evaluate_browser_input_identity

CONTROL = "SL-C03-HTML-01"


def configuration(scope, variant, credential_reference):
    result = base_configuration(scope, variant, credential_reference)
    template = result["templates"][0]
    template["id"] = "authenticated-html-" + variant
    template["path"] = template["route_template"] = f"/{variant}/protected-html"
    template["inputs"] = [
        {
            "location": "query",
            "name": "q",
            "baseline_value": "ordinary",
            "required": True,
            "mutable": True,
        }
    ]
    result["policies"][0].update(
        template_id=template["id"],
        approval_ref="owned-authenticated-browser-fixture-v1",
        control_ids=[CONTROL],
    )
    return result


def verify_report(report, html, evidence, captures, variant, frozen, *, trusted_capabilities=None):
    config = AssessmentConfiguration.model_validate(frozen)
    catalogue = DiscoveryCatalogue(origin=config.templates[0].origin, templates=config.templates)
    expected_plan = plan_assessment(
        catalogue,
        scope_version=str(config.scope_version_id),
        policies=config.policies,
        reviewed_control_ids=(CONTROL,),
        profile="authenticated-api-v1",
    )
    assert len(expected_plan.tasks) == 1
    task = expected_plan.tasks[0]
    expected = "confirmed_issue" if variant == "bad" else "pass"
    outcome = next(row for row in report["check_outcomes"] if row["check_id"] == CONTROL)
    assert outcome["status"] == expected, {
        "control": CONTROL,
        "status": outcome["status"],
        "summary": outcome["summary"],
    }
    assert set(outcome["required_instances"]) == set(outcome["completed_instances"]) == {task.id}, (
        "authenticated browser task coverage incomplete"
    )
    assert outcome["evidence_refs"], "trusted authenticated browser proof missing"
    metadata = {row["id"]: row for row in evidence}
    for ref in outcome["evidence_refs"]:
        assert (
            metadata[ref]["trusted"]
            and metadata[ref]["producer"] == "reviewed_expansion_browser_capture"
        )
        capture = captures[ref]
        assert capture["kind"] == "expanded_active_probe"
        data = capture["data"]
        assert data["control_id"] == CONTROL and data["role_id"] == "A" and data["kind"] == "html"
        assert data["task_id"] == task.id and data["template_id"] == config.templates[0].id
        assert data["route"] == config.templates[0].path and data["method"] == "GET"
        assert data["plan_id"]
        valid, reason = evaluate_browser_input_identity(
            config.identities[0],
            task,
            config.templates[0],
            data["plan_id"],
            data.get("browser_identity_proofs"),
            data.get("captures"),
        )
        assert valid, reason
        # The proof evaluator requires three distinct IDs and each exact named pair.
        assert len({item["context_id"] for item in data["browser_identity_proofs"]}) == 3
    assert report["profile"] == "authenticated-api-v1"
    assert "authenticated-api-v1" in html and CONTROL in html
    capabilities = report["capabilities"]
    if trusted_capabilities is not None:
        assert capabilities == trusted_capabilities, "capability export differs from trusted replay"
    else:
        for key in ("installed_tools", "executable_checks", "independently_qualified_families"):
            assert capabilities[key]["count"] is None, (
                "unmeasured capability was presented as measured"
            )
            assert capabilities[key]["evidence_state"] == "unknown"
    reach = report["reach"]
    assert reach["profile"] == "authenticated-api-v1"
    assert reach["planned"] == sum(
        reach[key] for key in ("fully_assessed", "blocked", "error", "unassessed", "not_applicable")
    ), "reach total does not balance"
    role_route = next(
        group
        for group in reach["groups"]
        if group["role_id"] == "A" and group["route"] == config.templates[0].path
    )
    assert role_route["planned"] >= 1 and role_route["fully_assessed"] >= 1
    assert role_route["planned"] == sum(
        role_route[key]
        for key in ("fully_assessed", "blocked", "error", "unassessed", "not_applicable")
    )
    assert all(
        key not in report.get("assessment_plan", {})
        for key in (
            "expansion_config",
            "request_catalogue",
            "input_assessment_plan",
            "capability_snapshot",
        )
    ), "private assessment inputs were exported"
    serialized = json.dumps({"report": report, "evidence": evidence, "captures": captures}) + html
    assert FIXTURE_PASSWORD not in serialized, "fixture secret leaked into exported output"
    assert "sid=A" not in serialized, "session cookie leaked into exported output"
    return outcome


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/authenticated-browser-deployed"))
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
            print(f"authenticated-browser/{variant}: scan {ident}", flush=True)
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
            from scripts.verify_runtime_capability_lab import trusted_lab_projection

            capabilities = trusted_lab_projection(settings, ident, report)
            verified = verify_report(
                report,
                html,
                evidence,
                captures,
                variant,
                frozen,
                trusted_capabilities=capabilities,
            )
            discovery = [
                row
                for row in evidence
                if row.get("summary") == "Captured browser_request_template artifact"
            ]
            assert discovery, "deployed explorer did not capture request intentions"
            for row in discovery:
                assert row["trusted"] and row["producer"] == "reviewed_browser_capture"
                observed = get(f"/api/scans/{ident}/evidence/{row['id']}/download").json()
                assert observed["kind"] == "browser_request_template"
                assert observed["data"]["state"] == "observed_intent"
                assert observed["data"]["template"]["baseline_observed"] is False
            summary = get(f"/api/scans/{ident}/summary").json()
            assert summary["capabilities"] == report["capabilities"]
            assert summary["reach"] == report["reach"]
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
                "browser_discovery_refs": [row["id"] for row in discovery],
            }
            receipts.append(receipt)
            (args.output / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
            print(
                f"  {verified['status']}; three fresh browser contexts and before/after identity facts verified; HTML/JSON exported",
                flush=True,
            )


if __name__ == "__main__":
    main()
