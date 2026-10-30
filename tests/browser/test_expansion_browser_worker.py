"""Expanded collector integration against the existing disposable browser fixture.

Browser injection here deliberately targets local fixture servers; production proxy launch
is separately asserted. This is not a deployed containment claim.
"""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import SecretStr
from test_browser_workflows import workflow_app as workflow_app

from scopelens.domain.assessment import (
    AssessmentPlanVersion,
    DiscoveryCatalogue,
    RelatedOriginGrant,
)
from scopelens.domain.browser_workflow import BrowserWorkflowRecipe
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import IdentityProfile, IdentityRequest, LoginRecipe, SessionProbe
from scopelens.domain.workflow import StateAssertion
from scopelens.expansion.browser_worker import RequestGuard, _Route, collect_browser_assessments
from scopelens.identities.sessions import SessionUnavailable
from scopelens.workflows.cleanup import SQLiteCleanupJournal


def setup(workflow_app, tmp_path, variant, family):
    origin, foreign, browser, _ = workflow_app
    base = origin + "/" + variant
    profiles = tuple(
        IdentityProfile(
            id=name,
            role=name,
            login=LoginRecipe(
                request=IdentityRequest(
                    method="POST", url=base + "/login", json_body={"role": name}
                )
            ),
            probe=SessionProbe(
                request=IdentityRequest(url=base + "/identity"), expected_identity=name
            ),
        )
        for name in ("A", "B")
    )
    recipe = BrowserWorkflowRecipe(
        id=family + "_" + variant,
        family=family,
        resource_id=variant,
        action_grant_id="fixture-reviewed",
        authority="lab",
        disposable=True,
        synchronous_write=True,
        actor_identity="A",
        viewer_identity="A" if family == "csrf" else "B",
        cleanup_identity="A",
        readback=IdentityRequest(url=base + "/record"),
        seed=StateAssertion(pointer="/seed", value="scopelens-disposable-record"),
        before=StateAssertion(pointer="/content", value=""),
        mutation=IdentityRequest(
            method="POST", url=base + ("/upload" if family == "upload_serving" else "/mutate")
        ),
        mutation_field="content",
        cleanup=IdentityRequest(method="POST", url=base + "/cleanup"),
        viewer_url=base + ("/file" if family == "upload_serving" else "/viewer"),
        foreign_url=foreign if family == "csrf" else None,
        upload_form_url=base + "/form" if family == "upload_serving" else None,
        upload_selector='input[name="file"]' if family == "upload_serving" else None,
        upload_submit_selector='button[type="submit"]' if family == "upload_serving" else None,
    )
    from scopelens.discovery.catalogue import canonical_origin

    config = AssessmentConfiguration(
        scope_version_id=uuid4(),
        identities=profiles,
        browser_workflows=(recipe,),
        related_origins=(
            RelatedOriginGrant(
                origin=canonical_origin(foreign),
                purpose="scan",
                grant_id="fixture",
                scope_version_id=str(uuid4()),
            ),
        ),
    )
    catalogue = DiscoveryCatalogue(origin=origin)
    plan = AssessmentPlanVersion(
        id="plan",
        revision=1,
        scope_version=str(config.scope_version_id),
        catalogue_hash="fixture",
        tasks=(),
        denominator=0,
    )
    crawl = SimpleNamespace(origin=origin, allowed_path_prefixes=("/",), excluded_paths=())
    journal = SQLiteCleanupJournal(tmp_path / "journal.db")
    control = SimpleNamespace(
        secret=lambda _: SecretStr("unused"), claim=journal.claim, mark=journal.mark
    )
    return config, catalogue, plan, crawl, browser, control


@pytest.mark.parametrize("family", ["stored_xss", "csrf", "upload_serving"])
@pytest.mark.parametrize("variant,expected", [("bad", "confirmed"), ("fixed", "pass")])
def test_integrated_browser_collector_keeps_proof_binding_and_cleans(
    workflow_app, tmp_path, family, variant, expected
):
    config, catalogue, plan, crawl, browser, control = setup(
        workflow_app, tmp_path, variant, family
    )
    artifacts = []
    summary = collect_browser_assessments(
        config,
        catalogue,
        plan,
        browser,
        control,
        crawl,
        lambda kind, data, artifacts=artifacts: artifacts.append({"kind": kind, "data": data}),
        owner="fixture-worker-owner",
        token="fixture-egress",
        cancelled=lambda: False,
    )
    result = next(a["data"] for a in artifacts if a["kind"] == "workflow_capture")
    assert result["state"] == expected, result
    assert result["cleanup_state"] == "clean"
    observations = [a["data"] for a in artifacts if a["kind"] == "identity_observation"]
    assert observations
    assert all(
        item["proof_type"] == "browser_workflow"
        and item["proof_id"] == config.browser_workflows[0].id
        for item in observations
    )
    assert set(result["evidence_refs"]) == {"pending-intake"}
    assert summary["requests"] > 0 and summary["cleanup_requests"] > 0
    assert summary["complete"] is True
    assert workflow_app[3][variant] == ""
    # Exercise the same proof adapter used by report analysis, with supervisor IDs.
    from pathlib import Path

    from scopelens.domain.enums import ControlOutcome
    from scopelens.domain.registry import load_registry
    from scopelens.expansion.analysis import expansion_controls
    from scopelens.expansion.proof_aggregation import BROWSER_WORKFLOW_CONTROLS

    for index, artifact in enumerate(artifacts):
        artifact.update(
            source="expansion_browser", run_id="browser-fixture-run", evidence_ref=f"stored-{index}"
        )
        if artifact["kind"] == "workflow_capture":
            artifact["data"]["state"] = "pass" if expected == "confirmed" else "confirmed"

    def evaluate(rows=artifacts, cleanup="clean", trusted=None):
        controls = expansion_controls(
            rows,
            {"expansion_config": config.model_dump(mode="json")},
            load_registry(Path("checks_registry")),
            trusted_refs={a["evidence_ref"] for a in artifacts} if trusted is None else trusted,
            cleanup_states={config.browser_workflows[0].id: cleanup},
        )
        return next(
            c.evaluate(None) for c in controls if c.check_id == BROWSER_WORKFLOW_CONTROLS[family]
        )

    outcome = evaluate()
    assert outcome.status == (
        ControlOutcome.CONFIRMED_ISSUE if expected == "confirmed" else ControlOutcome.PASS
    )
    assert outcome.is_fully_assessed
    assert "pending-intake" not in outcome.proof.evidence_refs
    assert not evaluate(cleanup="mutation_sent").is_fully_assessed
    if expected == "confirmed":
        assert evaluate(cleanup="mutation_sent").status == ControlOutcome.CONFIRMED_ISSUE
    assert evaluate(trusted=set()).status == ControlOutcome.INCONCLUSIVE
    assert (
        evaluate([a for a in artifacts if a["kind"] != "identity_response"]).status
        == ControlOutcome.INCONCLUSIVE
    )
    from copy import deepcopy

    mixed = deepcopy(artifacts)
    for a in mixed:
        if a["data"].get("kind") == "browser_proof":
            a["run_id"] = "another-attempt"
            break
    assert evaluate(mixed).status == ControlOutcome.INCONCLUSIVE


def test_cancellation_stops_mutation_and_budget_failure_is_visible(workflow_app, tmp_path):
    config, catalogue, plan, crawl, browser, control = setup(
        workflow_app, tmp_path, "bad", "stored_xss"
    )
    for cancelled, budget in ((lambda: True, 100), (lambda: False, 1)):
        artifacts = []
        summary = collect_browser_assessments(
            config,
            catalogue,
            plan,
            browser,
            control,
            crawl,
            lambda kind, data, artifacts=artifacts: artifacts.append({"kind": kind, "data": data}),
            owner="fixture-owner",
            token="fixture-token",
            cancelled=cancelled,
            max_requests=budget,
        )
        result = next(a["data"] for a in artifacts if a["kind"] == "workflow_capture")
        assert result["state"] == "blocked"
        assert not summary["complete"] and summary["incomplete_instances"]
        assert result["cleanup_state"] == "not_needed"
        assert workflow_app[3]["bad"] == ""


def test_local_guards_block_unreviewed_write_origin_and_cleanup_replay(workflow_app, tmp_path):
    config, catalogue, plan, crawl, _, _ = setup(workflow_app, tmp_path, "bad", "stored_xss")
    guard = RequestGuard(config, catalogue, plan, crawl, cancelled=lambda: False, limit=5)
    with pytest.raises(SessionUnavailable, match="not_granted"):
        guard.admit("POST", crawl.origin + "/unreviewed-write")
    with pytest.raises(SessionUnavailable, match="origin_not_granted"):
        guard.admit("GET", "http://unapproved.invalid/")
    cleanup = RequestGuard(
        config, catalogue, plan, crawl, cancelled=lambda: False, limit=5, cleanup=True
    )
    with pytest.raises(SessionUnavailable, match="cleanup_request_not_granted"):
        cleanup.admit("POST", config.browser_workflows[0].mutation.url)
    cleanup.admit("POST", config.browser_workflows[0].cleanup.url)
    assert cleanup.used == 1


def test_route_guard_checks_effective_overridden_method(workflow_app, tmp_path):
    config, catalogue, plan, crawl, _, _ = setup(workflow_app, tmp_path, "bad", "stored_xss")
    guard = RequestGuard(config, catalogue, plan, crawl, cancelled=lambda: False, limit=5)
    calls = []
    route = SimpleNamespace(
        request=SimpleNamespace(url=crawl.origin + "/arbitrary", method="GET", headers={}),
        abort=lambda: calls.append("aborted"),
        continue_=lambda **_: calls.append("continued"),
    )
    _Route(route, guard, "token").continue_(method="POST")
    assert calls == ["aborted"]
    assert guard.used == 0


def test_csrf_requires_authenticated_cookie_identity_and_capture(workflow_app, tmp_path):
    from pydantic import ValidationError

    from scopelens.browser.workflow_checks import evaluate_browser_workflow

    config, _, _, _, _, _ = setup(workflow_app, tmp_path, "bad", "csrf")
    payload = config.model_dump(mode="json")
    payload["identities"][0] = {"id": "A", "role": "A", "anonymous": True}
    with pytest.raises(ValidationError, match="cookie-authenticated"):
        AssessmentConfiguration.model_validate(payload)
    recipe = config.browser_workflows[0]
    observations = (
        {"kind": "baseline", "seed_matches": True, "before_matches": True},
        *(
            {
                "kind": "browser_proof",
                "nonce": nonce,
                "seed_matches": True,
                "forbidden_state": True,
                "browser_submitted": True,
                "viewer_verified": True,
            }
            for nonce in ("first", "second")
        ),
    )
    state, reason = evaluate_browser_workflow(recipe, observations)
    assert state == "inconclusive" and reason == "ambient_browser_session_required"


def test_production_entrypoint_requires_proxy_and_launches_restricted_browser(
    workflow_app, tmp_path, monkeypatch, capsys
):
    import json
    from contextlib import nullcontext

    from scopelens.expansion import browser_worker as worker

    config, catalogue, plan, crawl, _, _ = setup(workflow_app, tmp_path, "fixed", "stored_xss")
    events = []
    browser = SimpleNamespace(close=lambda: events.append("browser_closed"))

    def launch(**kwargs):
        events.append(kwargs)
        return browser

    class Controller:
        def __init__(self, config, proxy, owner):
            assert proxy == "http://127.0.0.1:12345"
            self.http = SimpleNamespace(close=lambda: events.append("control_closed"))

        def command(self, operation):
            events.append(operation)

    def bridge(upstream, token):
        assert upstream == "http://mandatory-proxy:8098"
        assert token == "scoped-test-token"
        return nullcontext("http://127.0.0.1:12345")

    monkeypatch.setenv(
        "SCOPELENS_EXPANSION_INPUT",
        json.dumps(
            {
                "configuration": config.model_dump(mode="json"),
                "catalogue": catalogue.model_dump(mode="json"),
                "plan": plan.model_dump(mode="json"),
            }
        ),
    )
    monkeypatch.setenv("HTTP_PROXY", "http://mandatory-proxy:8098")
    monkeypatch.setenv("SCOPELENS_BROWSER_OWNER", "durable-worker-owner")
    monkeypatch.setenv("SCOPELENS_EGRESS_TOKEN", "scoped-test-token")
    monkeypatch.setenv("SCOPELENS_EXPANSION_CAPABILITY", "scoped-capability")
    monkeypatch.setattr(worker, "_install_proxy_ca", lambda: events.append("ca_installed"))
    monkeypatch.setattr(worker, "config_from_env", lambda: crawl)
    monkeypatch.setattr(worker, "Bridge", bridge)
    monkeypatch.setattr(worker, "Controller", Controller)
    monkeypatch.setattr(
        worker, "Crawler", lambda _: SimpleNamespace(_http=lambda: nullcontext(object()))
    )
    monkeypatch.setattr(
        worker,
        "sync_playwright",
        lambda: nullcontext(SimpleNamespace(chromium=SimpleNamespace(launch=launch))),
    )
    monkeypatch.setattr(
        worker,
        "collect_browser_assessments",
        lambda *args, **kwargs: {"requests": 0, "complete": True},
    )
    monkeypatch.setattr(worker, "_cancelled", False)
    assert worker.main() == 0
    launch_settings = next(item for item in events if isinstance(item, dict))
    assert launch_settings["chromium_sandbox"] is True
    assert launch_settings["proxy"] == {"server": "http://127.0.0.1:12345"}
    assert "--disable-quic" in launch_settings["args"]
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in launch_settings["args"]
    assert "--no-sandbox" not in launch_settings["args"]
    assert events.index("open") < events.index(launch_settings)
    assert events.index("browser_closed") < events.index("close")
    output = capsys.readouterr().out
    assert "scoped-test-token" not in output and "scoped-capability" not in output
    events.clear()
    monkeypatch.delenv("HTTP_PROXY")
    with pytest.raises(KeyError):
        worker.main()
    assert not any(isinstance(item, dict) for item in events)
