"""Deployed discovery -> reviewed policy -> input proof on owned ephemeral labs.

No endpoint templates are submitted. Policies refer only to template IDs returned by
the first scan's safe review API. Baselines and credential references stay private.
"""

import argparse
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from scopelens.checks.expanded_active import evaluate_expanded
from scopelens.config import Settings
from scopelens.domain.assessment import stable_id
from scopelens.domain.expansion import PlanTemplateReviewView

SQL = "SL-C03-SQL-01"
DOM = "SL-C03-DOMXSS-01"


def reviewed_templates(get, scan_id, scope):
    history = get(f"/api/assessments/scans/{scan_id}/plans").json()
    assert history["revisions"], "discovery plan was not frozen"
    plan = history["revisions"][-1]["plan"]
    offset, templates = 0, []
    while True:
        review = PlanTemplateReviewView.model_validate(
            get(
                f"/api/assessments/scans/{scan_id}/plans/{plan['id']}/templates?offset={offset}&limit=200"
            ).json()
        )
        assert str(review.scan_id) == scan_id and str(review.scope_version_id) == scope["id"]
        assert review.plan_id == plan["id"] and review.catalogue_hash == plan["catalogue_hash"]
        templates.extend(review.templates)
        if review.next_offset is None:
            assert len(templates) == review.total
            assert len({t.id for t in templates}) == review.total
            return tuple(templates)
        assert review.next_offset > offset
        offset = review.next_offset


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/discovery-deployed"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    settings = Settings()
    receipts = []
    with httpx.Client(base_url="http://127.0.0.1:8090", timeout=30) as client:

        def post(path, value):
            response = client.post(path, json=value)
            response.raise_for_status()
            return response.json()

        def get(path):
            response = client.get(path)
            response.raise_for_status()
            return response

        def run(scope, config_id=None):
            body = {"scope_version_id": scope["id"], "adaptive": False}
            if config_id is None:
                config_id = post(
                    "/api/assessments/configurations", {"scope_version_id": scope["id"]}
                )["id"]
            body["assessment_configuration_id"] = config_id
            scan_id = post("/api/scans", body)["id"]
            print(f"{scope['origin']} {scope['allowed_check_profile']}: {scan_id}", flush=True)
            deadline = time.monotonic() + 900
            while time.monotonic() < deadline:
                status = get(f"/api/scans/{scan_id}").json()["status"]
                if status in {"completed", "completed_partial", "failed", "cancelled"}:
                    break
                time.sleep(2)
            else:
                post(f"/api/scans/{scan_id}/cancel", {})
                raise AssertionError("owned discovery gate timed out; cancellation requested")
            report = get(f"/api/scans/{scan_id}/export.json").json()
            (args.output / f"{scan_id}.json").write_text(json.dumps(report, indent=2))
            (args.output / f"{scan_id}.html").write_text(
                get(f"/api/scans/{scan_id}/export.html").text
            )
            metadata = get(f"/api/scans/{scan_id}/evidence").json()
            captures = {}
            for row in metadata:
                if row["trusted"] and row["producer"] in {
                    "reviewed_browser_capture",
                    "reviewed_crawler_capture",
                    "reviewed_expansion_capture",
                    "reviewed_expansion_browser_capture",
                }:
                    captures[row["id"]] = get(
                        f"/api/scans/{scan_id}/evidence/{row['id']}/download"
                    ).json()
            return scan_id, status, report, captures

        post(
            "/api/auth/login",
            {
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        for service, variant in (("labs-discovery-a", "bad"), ("labs-discovery-b", "fixed")):
            common = {
                "authority_domain": "lab",
                "scheme": "http",
                "lab_service": service,
                "lab_port": 8080,
                "allowed_methods": ["GET", "HEAD", "POST"],
                "authorization_expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
            }
            discovery = post(
                "/api/scopes", {**common, "allowed_check_profile": "external-discovery-v2"}
            )
            first_id, first_status, _, captures = run(discovery)
            templates = reviewed_templates(get, first_id, discovery)
            locations = {i.location for t in templates for i in t.inputs}
            assert {"query", "form", "json", "path"} <= locations, (
                f"discovery missed input kinds: {locations}"
            )
            assert any(
                c.get("kind") == "browser_request_template"
                and any(i["location"] == "json" for i in c["data"]["template"]["inputs"])
                for c in captures.values()
            ), "SPA JSON intention not captured by browser"
            active = post("/api/scopes", {**common, "allowed_check_profile": "external-active-v2"})
            config = post(
                "/api/assessments/configurations",
                {
                    "scope_version_id": active["id"],
                    "policies": [
                        {
                            "template_id": t.id,
                            "role_id": t.role_id,
                            "classification": "read_only",
                            "approval_ref": "owned-memory-only-read-query",
                            "control_ids": [SQL, DOM],
                        }
                        for t in templates
                    ],
                },
            )
            second_id, second_status, report, proofs = run(active, config["id"])
            by_template = {t.id: t for t in templates}
            expected = "confirmed" if variant == "bad" else "pass"
            sql_locations, dom_states, proof_refs = set(), [], []
            for ref, capture in proofs.items():
                if capture.get("kind") != "expanded_active_probe":
                    continue
                data = capture["data"]
                if data.get("control_id") == SQL and data.get("state") == expected:
                    assert evaluate_expanded("sql", data.get("captures", []))[0] == expected
                    template = by_template.get(data["template_id"])
                    assert template is not None, "assessment used an undiscovered template"
                    input_id = stable_id([template.id, data["input_key"]])
                    matched = [i for i in template.inputs if i.id == input_id]
                    assert len(matched) == 1, "proof input was not in reviewed discovery"
                    sql_locations.add(matched[0].location)
                    proof_refs.append(ref)
                if data.get("control_id") == DOM:
                    if data.get("state") in {"confirmed", "pass"}:
                        assert capture.get("source") == "expansion_browser"
                        assert (
                            evaluate_expanded("dom_xss", data.get("captures", []))[0]
                            == data["state"]
                        )
                    dom_states.append(data.get("state"))
                    if data.get("state") == "confirmed":
                        proof_refs.append(ref)
            assert {"query", "form", "json", "path"} <= sql_locations, sql_locations
            if variant == "bad":
                assert "confirmed" in dom_states, dom_states
            else:
                assert dom_states and "confirmed" not in dom_states and "pass" in dom_states
            expected_status = "confirmed_issue" if variant == "bad" else "pass"
            sql_outcome = next(o for o in report["check_outcomes"] if o["check_id"] == SQL)
            # Some unrelated inputs may remain inconclusive; their denominator stays visible.
            assert sql_outcome["completed_instances"] and sql_outcome["required_instances"]
            if variant == "bad":
                assert sql_outcome["status"] == expected_status
            receipts.append(
                {
                    "variant": variant,
                    "discovery_scan": first_id,
                    "assessment_scan": second_id,
                    "discovery_status": first_status,
                    "assessment_status": second_status,
                    "discovered_locations": sorted(locations),
                    "proved_sql_locations": sorted(sql_locations),
                    "dom_states": dom_states,
                    "proof_refs": proof_refs,
                    "templates_submitted": 0,
                    "independent_qualification": False,
                }
            )
            (args.output / "receipts.json").write_text(json.dumps(receipts, indent=2) + "\n")
            print(f"{variant}: four SQL input locations and browser DOM proof verified", flush=True)


if __name__ == "__main__":
    main()
