"""Stateful browser packs use real local forms, persistence, cookies and read-back."""

from http.server import ThreadingHTTPServer
from threading import Thread
from typing import ClassVar

import pytest
from playwright.sync_api import sync_playwright
from pydantic import SecretStr, ValidationError

from scopelens.browser.workflow_checks import run_browser_workflow
from scopelens.domain.browser_workflow import BrowserWorkflowRecipe
from scopelens.domain.identity import IdentityProfile, IdentityRequest, LoginRecipe, SessionProbe
from scopelens.domain.workflow import StateAssertion
from scopelens.identities.browser import BrowserIdentitySessions
from scopelens.identities.cors import origin as canonical_origin
from scopelens.workflows.cleanup import SQLiteCleanupJournal


@pytest.fixture(scope="module")
def workflow_app():
    records = {"bad": "", "fixed": ""}

    from labs.expansion_browser.app import handler

    App = handler(records)

    servers = [ThreadingHTTPServer(("127.0.0.1", 0), App) for _ in range(2)]
    threads = [Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads:
        thread.start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                yield (
                    f"http://127.0.0.1:{servers[0].server_port}",
                    f"http://127.0.0.1:{servers[1].server_port}/foreign",
                    browser,
                    records,
                )
            finally:
                browser.close()
    finally:
        for server, thread in zip(servers, threads, strict=True):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def execute(
    workflow_app,
    tmp_path,
    variant,
    family,
    *,
    cancelled=lambda: False,
    cleanup_cancelled=lambda: False,
    journal=None,
):
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
    sessions = BrowserIdentitySessions(
        profiles,
        lambda ref: SecretStr("unused"),
        lambda identity: browser.new_context(service_workers="block"),
        cancelled=cancelled,
    )
    cleanup = BrowserIdentitySessions(
        profiles,
        lambda ref: SecretStr("unused"),
        lambda identity: browser.new_context(service_workers="block"),
        cancelled=cleanup_cancelled,
    )
    journal = journal or SQLiteCleanupJournal(tmp_path / "cleanup.db")
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
    evidence = []

    def capture(item):
        evidence.append(item)
        return f"trusted:{len(evidence)}"

    try:
        result = run_browser_workflow(
            recipe,
            sessions,
            cleanup,
            journal,
            capture,
            admit=lambda recipe: True,
            allowed_foreign_origins=frozenset({canonical_origin(foreign)}),
            action_owner="fixture",
        )
        return result, journal
    finally:
        sessions.close()
        cleanup.close()


@pytest.mark.parametrize("family", ["stored_xss", "csrf", "upload_serving"])
def test_real_stateful_browser_vulnerable_fixed_and_cleanup(workflow_app, tmp_path, family):
    bad, journal = execute(workflow_app, tmp_path, "bad", family)
    assert bad.state == "confirmed", bad
    assert bad.cleanup_state == "clean", bad
    assert journal.state(family + "_bad", "bad") == "clean"
    assert workflow_app[3]["bad"] == ""
    fixed, _ = execute(workflow_app, tmp_path, "fixed", family)
    assert fixed.state == "pass", fixed
    assert fixed.cleanup_state == "clean", fixed
    assert workflow_app[3]["fixed"] == ""


def test_pending_cleanup_prevents_browser_write(workflow_app, tmp_path):
    journal = SQLiteCleanupJournal(tmp_path / "pending.db")
    assert journal.claim("stored_xss_bad", "bad")
    result, _ = execute(workflow_app, tmp_path, "bad", "stored_xss", journal=journal)
    assert result.state == "blocked"
    assert result.reason == "prior_cleanup_pending"
    assert workflow_app[3]["bad"] == ""


class StrictTransitionJournal:
    """Fixture mirror of the production cleanup RPC's allowed state transitions.

    ``expansion.control`` refuses ``mutation_sent -> mutation_sent``; re-marking the
    intent on every attempt would be denied there and lose the whole result.
    """

    ALLOWED: ClassVar[dict[str, set[str]]] = {
        "pending": {"mutation_sent", "cleanup_failed", "clean"},
        "mutation_sent": {"cleanup_failed", "clean"},
        "cleanup_failed": set(),
        "clean": set(),
    }

    def __init__(self, path):
        self.inner = SQLiteCleanupJournal(path)

    def claim(self, recipe_id, resource_id):
        return self.inner.claim(recipe_id, resource_id)

    def mark(self, recipe_id, resource_id, state):
        if state not in self.ALLOWED.get(self.inner.state(recipe_id, resource_id), set()):
            raise PermissionError("invalid_cleanup_transition")
        self.inner.mark(recipe_id, resource_id, state)

    def state(self, recipe_id, resource_id):
        return self.inner.state(recipe_id, resource_id)


@pytest.mark.parametrize("family", ["stored_xss", "csrf", "upload_serving"])
def test_workflow_respects_journal_transition_state_machine(workflow_app, tmp_path, family):
    journal = StrictTransitionJournal(tmp_path / "strict.db")
    bad, _ = execute(workflow_app, tmp_path, "bad", family, journal=journal)
    assert bad.state == "confirmed", bad
    assert bad.cleanup_state == "clean", bad
    assert journal.state(family + "_bad", "bad") == "clean"
    fixed, _ = execute(workflow_app, tmp_path, "fixed", family, journal=journal)
    assert fixed.state == "pass", fixed
    assert fixed.cleanup_state == "clean", fixed


@pytest.mark.parametrize("state", ["mutation_sent", "cleanup_failed"])
def test_unresolved_cleanup_states_prevent_browser_write(workflow_app, tmp_path, state):
    journal = SQLiteCleanupJournal(tmp_path / f"{state}.db")
    assert journal.claim("stored_xss_bad", "bad")
    journal.mark("stored_xss_bad", "bad", state)
    result, _ = execute(workflow_app, tmp_path, "bad", "stored_xss", journal=journal)
    assert result.state == "blocked"
    assert result.reason == "prior_cleanup_pending"
    assert journal.state("stored_xss_bad", "bad") == state
    assert workflow_app[3]["bad"] == ""


def test_cleanup_failure_retains_partial_evidence(workflow_app, tmp_path):
    # The cleanup channel is unavailable, so the workflow result must keep every
    # collected proof, report cleanup_failed and leave the resource fenced.
    workflow_app[3]["bad"] = ""
    bad, journal = execute(
        workflow_app, tmp_path, "bad", "stored_xss", cleanup_cancelled=lambda: True
    )
    assert bad.state == "confirmed", bad
    assert bad.cleanup_state == "cleanup_failed", bad
    assert [o["kind"] for o in bad.observations] == [
        "baseline",
        "plain_control",
        "browser_proof",
        "browser_proof",
    ]
    assert len(bad.evidence_refs) == 4
    assert all(bad.evidence_refs)
    assert journal.state("stored_xss_bad", "bad") == "cleanup_failed"
    assert workflow_app[3]["bad"] != ""


def test_cancellation_after_marker_write_still_cleans_up(workflow_app, tmp_path):
    # Cancellation flips once the second (SVG) marker is stored: the read-back after
    # that mutation must refuse, no further mutation may be sent, and the separate
    # cleanup channel still restores the seeded record.
    records = workflow_app[3]
    records["bad"] = ""

    def cancelled():
        return "<svg" in records["bad"]

    result, journal = execute(workflow_app, tmp_path, "bad", "stored_xss", cancelled=cancelled)
    assert result.state == "blocked"
    assert result.reason == "browser session expired or cancelled"
    assert [o["kind"] for o in result.observations] == [
        "baseline",
        "plain_control",
        "cleanup_readback",
    ]
    assert len(result.evidence_refs) == 3
    assert all(result.evidence_refs)
    assert result.cleanup_state == "clean"
    assert journal.state("stored_xss_bad", "bad") == "clean"
    assert records["bad"] == ""


def test_recipe_requires_separate_writer_and_viewer():
    def recipe(**overrides):
        return {
            "id": "stored_xss_bad",
            "family": "stored_xss",
            "resource_id": "bad",
            "action_grant_id": "fixture-reviewed",
            "authority": "lab",
            "disposable": True,
            "synchronous_write": True,
            "actor_identity": "A",
            "viewer_identity": "B",
            "cleanup_identity": "A",
            "readback": {"url": "http://127.0.0.1:1/bad/record"},
            "seed": {"pointer": "/seed", "value": "scopelens-disposable-record"},
            "before": {"pointer": "/content", "value": ""},
            "mutation": {"method": "POST", "url": "http://127.0.0.1:1/bad/mutate"},
            "mutation_field": "content",
            "cleanup": {"method": "POST", "url": "http://127.0.0.1:1/bad/cleanup"},
            "viewer_url": "http://127.0.0.1:1/bad/viewer",
            **overrides,
        }

    BrowserWorkflowRecipe.model_validate(recipe())
    with pytest.raises(ValidationError):
        BrowserWorkflowRecipe.model_validate(recipe(viewer_identity="A"))
    with pytest.raises(ValidationError):
        BrowserWorkflowRecipe.model_validate(
            recipe(
                family="upload_serving",
                viewer_identity="A",
                upload_form_url="http://127.0.0.1:1/bad/form",
                upload_selector='input[name="file"]',
                upload_submit_selector='button[type="submit"]',
            )
        )
    with pytest.raises(ValidationError):
        # CSRF without a registered controlled foreign page is not a valid recipe.
        BrowserWorkflowRecipe.model_validate(
            recipe(family="csrf", foreign_url=None, form_fields={"content": ""})
        )
