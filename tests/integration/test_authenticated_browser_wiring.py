"""Actual worker collector to trusted analysis using the owned in-process lab fixture."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from types import SimpleNamespace
from uuid import uuid4

import pytest
from labs.expansion_browser.app import FIXTURE_PASSWORD, handler
from playwright.sync_api import sync_playwright
from pydantic import SecretStr
from scripts.verify_authenticated_browser_lab import CONTROL, configuration

from scopelens.discovery.planner import plan_assessment
from scopelens.domain.assessment import DiscoveryCatalogue
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.registry import load_registry
from scopelens.expansion.analysis import expansion_controls
from scopelens.expansion.browser_worker import collect_browser_assessments


@pytest.fixture(scope="module", params=["bad", "fixed"])
def collected(request):
    records = {"bad": "", "fixed": ""}
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(records))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    config = AssessmentConfiguration.model_validate(
        configuration({"id": str(uuid4()), "origin": origin}, request.param, "fixture-secret")
    )
    catalogue = DiscoveryCatalogue(origin=origin, templates=config.templates)
    plan = plan_assessment(
        catalogue,
        scope_version=str(config.scope_version_id),
        policies=config.policies,
        reviewed_control_ids=(CONTROL,),
        profile="authenticated-api-v1",
    )
    artifacts, resolutions = [], []

    def resolve(ref):
        assert ref == "fixture-secret"
        resolutions.append(ref)
        return SecretStr(FIXTURE_PASSWORD)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            summary = collect_browser_assessments(
                config,
                catalogue,
                plan,
                browser,
                SimpleNamespace(secret=resolve),
                SimpleNamespace(origin=origin, allowed_path_prefixes=("/",), excluded_paths=()),
                lambda kind, data: artifacts.append({"kind": kind, "data": data}),
                owner="owned-wiring-test",
                token="synthetic-egress",
                cancelled=lambda: False,
            )
            assert not browser.contexts
        finally:
            browser.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
    assert len(artifacts) == 1 and summary["complete"]
    assert summary["requests"] == 12 and summary["cleanup_requests"] == 0
    assert len(resolutions) == 3
    assert records == {"bad": "", "fixed": ""}
    artifacts[0].update(
        source="expansion_browser",
        run_id="reviewed-browser-test",
        evidence_ref="trusted-browser-evidence",
    )
    frozen = {
        "expansion_config": config.model_dump(mode="json"),
        "request_catalogue": catalogue.model_dump(mode="json"),
        "input_assessment_plan": plan.model_dump(mode="json"),
    }
    yield artifacts, frozen, request.param


def assess(artifacts, frozen, trusted=True):
    controls = expansion_controls(
        artifacts,
        frozen,
        load_registry(Path("checks_registry")),
        trusted_refs={"trusted-browser-evidence"} if trusted else set(),
    )
    return next(control.evaluate(None) for control in controls if control.check_id == CONTROL)


def test_worker_wiring_collects_three_contexts_and_analysis_recomputes_marker_outcome(collected):
    artifacts, frozen, variant = deepcopy(collected)
    data = artifacts[0]["data"]
    assert len({proof["context_id"] for proof in data["browser_identity_proofs"]}) == 3
    # A worker verdict contrary to observed marker facts cannot change the result.
    data["state"] = "pass" if variant == "bad" else "confirmed"
    outcome = assess(artifacts, frozen)
    assert outcome.status.value == ("confirmed_issue" if variant == "bad" else "pass")
    assert outcome.is_fully_assessed


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "missing_after",
        "wrong_before",
        "revoked_after",
        "expired",
        "wrong_task",
        "wrong_plan",
        "wrong_role",
        "duplicate_context",
        "wrong_capture_context",
        "method",
        "path",
        "no_catalogue",
        "untrusted",
        "http_downgrade",
        "adaptive_downgrade",
        "boolean_only",
    ],
)
def test_analysis_rejects_tampered_browser_identity_and_request_facts(collected, change):
    artifacts, frozen, _ = deepcopy(collected)
    data = artifacts[0]["data"]
    data["state"] = "confirmed"
    proofs = data["browser_identity_proofs"]
    proof = proofs[1]["identity_proof"]
    if change == "missing":
        data.pop("browser_identity_proofs")
    elif change == "missing_after":
        proof["probes"].pop()
    elif change == "wrong_before":
        proof["probes"][0]["observed_identity"] = "B"
    elif change == "revoked_after":
        proof["probes"][1]["status"] = 401
    elif change == "expired":
        frozen["expansion_config"]["identities"][0]["expires_at"] = (
            datetime.now(UTC) - timedelta(days=1)
        ).isoformat()
    elif change in {"wrong_task", "wrong_plan", "wrong_role"}:
        proof[change.removeprefix("wrong_") + "_id"] = "other"
    elif change == "duplicate_context":
        proofs[1]["context_id"] = proofs[0]["context_id"]
    elif change == "wrong_capture_context":
        data["captures"][1]["context_id"] = "different"
    elif change == "method":
        data["method"] = "DELETE"
    elif change == "path":
        data["route"] = "/different"
    elif change == "no_catalogue":
        frozen.pop("request_catalogue")
    elif change in {"http_downgrade", "adaptive_downgrade"}:
        # A single HTTP pair cannot stand in for three independent browser contexts.
        artifacts[0]["source"] = "expansion" if change == "http_downgrade" else "adaptive"
        data["identity_proof"] = proof
        data.pop("browser_identity_proofs")
    elif change == "boolean_only":
        proof["probes"] = [{"phase": phase, "verified": True} for phase in ("before", "after")]
    outcome = assess(artifacts, frozen, trusted=change != "untrusted")
    assert outcome.status.value == "inconclusive", outcome
    assert not outcome.is_fully_assessed and not outcome.completed_instances
