"""Local fixture and deployed-gate construction; no deployed containers or scans."""

import json
from http.server import ThreadingHTTPServer
from threading import Thread
from uuid import uuid4

import httpx
import pytest
from labs.expansion_browser.app import FIXTURE_PASSWORD, handler
from pydantic import SecretStr
from scripts.verify_authenticated_inputs_lab import CONTROL, configuration, verify_report

from scopelens.checks.expanded_active import evaluate_expanded
from scopelens.discovery.planner import plan_assessment
from scopelens.domain.assessment import DiscoveryCatalogue
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.authenticated_inputs import (
    evaluate_input_identity,
    run_authenticated_inputs,
)


@pytest.fixture
def app():
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler({"bad": "", "fixed": ""}))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("variant", ["bad", "fixed"])
def test_password_login_rejects_absent_wrong_or_other_role_and_query_path_is_parsed(app, variant):
    with httpx.Client(follow_redirects=False) as client:
        base = app + "/" + variant
        assert (
            client.get(
                base + "/protected-redirect?next=https%3A%2F%2Fmarker.invalid%2F"
            ).status_code
            == 403
        )
        assert client.get(base + "/credential-login").status_code == 405
        for body in (
            {"role": "A"},
            {"role": "A", "password": "wrong"},
            {"role": "B", "password": FIXTURE_PASSWORD},
        ):
            response = client.post(base + "/credential-login?fixture=1", json=body)
            assert response.status_code == 401 and "set-cookie" not in response.headers
        assert (
            client.post(
                base + "/credential-login", json={"role": "A", "password": FIXTURE_PASSWORD}
            ).status_code
            == 200
        )
        assert client.get(base + "/identity?probe=1").json() == {"identity": "A"}
        response = client.get(
            base + "/protected-redirect", params={"next": "https://marker.invalid/"}
        )
        assert response.status_code == (302 if variant == "bad" else 200)
        if variant == "bad":
            assert response.headers["location"] == "https://marker.invalid/"
        else:
            assert "location" not in response.headers


@pytest.mark.parametrize("variant,expected", [("bad", "confirmed"), ("fixed", "pass")])
def test_existing_authenticated_input_collector_handles_secret_reference_fixture(
    app, variant, expected
):
    config = AssessmentConfiguration.model_validate(
        configuration({"id": str(uuid4()), "origin": app}, variant, "fixture-ref")
    )
    assert FIXTURE_PASSWORD not in config.model_dump_json()
    catalogue = DiscoveryCatalogue(origin=app, templates=config.templates)
    plan = plan_assessment(
        catalogue,
        scope_version=str(config.scope_version_id),
        policies=config.policies,
        reviewed_control_ids=(CONTROL,),
        profile="authenticated-api-v1",
    )
    resolved = []

    def secret(reference):
        assert reference == "fixture-ref"
        resolved.append(reference)
        return SecretStr(FIXTURE_PASSWORD)

    with httpx.Client(follow_redirects=False) as anonymous:
        records = run_authenticated_inputs(
            catalogue,
            plan,
            anonymous,
            config.identities,
            lambda _: httpx.Client(follow_redirects=False),
            secret,
        )
    assert resolved == ["fixture-ref"]
    data = records[0]["data"]
    assert data["state"] == expected, data
    assert evaluate_expanded("redirect", data["captures"])[0] == expected
    assert evaluate_input_identity(
        config.identities[0], plan.tasks[0], config.templates[0], plan.id, data["identity_proof"]
    )[0]
    assert [item["phase"] for item in data["identity_proof"]["probes"]] == ["before", "after"]
    assert FIXTURE_PASSWORD not in json.dumps(records) and "sid=A" not in json.dumps(records)


def test_deployed_gate_requires_identity_proof_and_secret_free_exports():
    proof = {
        "version": "authenticated-input-v1",
        "role_id": "A",
        "task_id": "task",
        "plan_id": "plan",
        "probes": [
            {"phase": phase, "status": 200, "observed_identity": "A"}
            for phase in ("before", "after")
        ],
    }
    captures = {
        "trusted-id": {
            "kind": "expanded_active_probe",
            "data": {
                "control_id": CONTROL,
                "role_id": "A",
                "task_id": "task",
                "plan_id": "plan",
                "identity_proof": proof,
            },
        }
    }
    report = {
        "profile": "authenticated-api-v1",
        "check_outcomes": [
            {
                "check_id": CONTROL,
                "status": "pass",
                "summary": "tested",
                "required_instances": ["task"],
                "completed_instances": ["task"],
                "evidence_refs": ["trusted-id"],
            }
        ],
    }
    evidence = [{"id": "trusted-id", "trusted": True, "producer": "reviewed_expansion_capture"}]
    html = "authenticated-api-v1 " + CONTROL
    verify_report(report, html, evidence, captures, "fixed")
    with pytest.raises(AssertionError, match="secret leaked"):
        verify_report(report, html + FIXTURE_PASSWORD, evidence, captures, "fixed")
    proof["probes"].pop()
    with pytest.raises(AssertionError):
        verify_report(report, html, evidence, captures, "fixed")
