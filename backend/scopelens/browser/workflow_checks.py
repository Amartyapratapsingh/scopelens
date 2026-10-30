"""Stateful browser proof with independent reads and durable cleanup before further writes."""

from __future__ import annotations

import hashlib
import uuid
from contextlib import suppress

from playwright.sync_api import Error as PlaywrightError

from scopelens.domain.browser_workflow import BrowserWorkflowRecipe
from scopelens.domain.workflow import WorkflowResult
from scopelens.identities.cors import origin
from scopelens.identities.sessions import SessionUnavailable, pointer


def evaluate_browser_workflow(
    recipe: BrowserWorkflowRecipe, observations: tuple[dict, ...]
) -> tuple[str, str]:
    baseline = [r for r in observations if r.get("kind") == "baseline"]
    proofs = [r for r in observations if r.get("kind") == "browser_proof"]
    if (
        len(baseline) != 1
        or not baseline[0].get("seed_matches")
        or not baseline[0].get("before_matches")
        or len(proofs) != 2
    ):
        return "inconclusive", "complete_seeded_browser_sequence_required"
    if len({p.get("nonce") for p in proofs}) != 2 or any(not p.get("seed_matches") for p in proofs):
        return "inconclusive", "independent_markers_on_same_seeded_record_required"
    if recipe.family == "stored_xss":
        controls = [r for r in observations if r.get("kind") == "plain_control"]
        if len(controls) != 1 or controls[0].get("executed") or not controls[0].get("persisted"):
            return "inconclusive", "stored_plain_marker_negative_required"
        positive = [
            p.get("persisted") and p.get("executed") and p.get("viewer_verified") for p in proofs
        ]
        if all(positive):
            return "confirmed", "stored_marker_executed_twice_in_separate_verified_viewer"
        if all(
            p.get("persisted") and not p.get("executed") and p.get("viewer_verified")
            for p in proofs
        ):
            return "pass", "stored_marker_did_not_execute_in_verified_viewer"
    elif recipe.family == "csrf":
        if any(p.get("ambient_session_present") is not True for p in proofs):
            return "inconclusive", "ambient_browser_session_required"
        if all(
            p.get("forbidden_state") and p.get("browser_submitted") and p.get("viewer_verified")
            for p in proofs
        ):
            return "confirmed", "foreign_browser_changed_seeded_record_twice_with_ambient_session"
        if all(
            p.get("unchanged")
            and p.get("browser_status") in {403, 405}
            and p.get("viewer_verified")
            for p in proofs
        ):
            return "pass", "cross_origin_mutation_explicitly_refused_and_state_unchanged"
    else:
        if all(
            p.get("persisted") and p.get("policy_violation") and p.get("viewer_verified")
            for p in proofs
        ):
            return "confirmed", "benign_uploaded_file_violates_declared_serving_policy"
        if all(
            p.get("persisted") and p.get("policy_enforced") and p.get("viewer_verified")
            for p in proofs
        ):
            return "pass", "benign_upload_serving_policy_enforced"
    return "inconclusive", "browser_workflow_proof_inconsistent"


def run_browser_workflow(
    recipe,
    sessions,
    cleanup_sessions,
    journal,
    capture,
    *,
    admit,
    allowed_foreign_origins=frozenset(),
    action_owner,
):
    observations, refs = [], []
    state, reason, cleanup_state = "blocked", "browser_workflow_not_admitted", "not_needed"
    claimed = False

    def save(item):
        ref = capture({"recipe_id": recipe.id, "family": recipe.family, **item})
        if not ref:
            raise SessionUnavailable("trusted_browser_workflow_evidence_missing")
        observations.append(item)
        refs.append(ref)

    def read(sessions, *, expected=None):
        if not sessions.verify(recipe.actor_identity, action_owner=action_owner):
            raise SessionUnavailable("writer_session_unavailable")
        status, body = sessions.request(
            recipe.actor_identity, recipe.readback, action_owner=action_owner
        )
        seeded = status == 200 and pointer(body, recipe.seed.pointer) == recipe.seed.value
        value = pointer(body, recipe.before.pointer)
        return seeded, value, status

    def browser_view(identity, url, nonce):
        # Recreate the viewer to exclude a marker left by an earlier navigation.
        if identity in sessions.contexts:
            sessions.release(identity, action_owner=action_owner)
        if not sessions.verify(identity, action_owner=action_owner):
            raise SessionUnavailable("viewer_session_unavailable")
        context = sessions.context(identity, action_owner=action_owner)
        page = context.new_page()
        try:
            response = page.goto(url, wait_until="networkidle", timeout=10000)
            if response is None or origin(page.url) != origin(url):
                raise SessionUnavailable("viewer_navigation_unavailable")
            executed = page.evaluate("nonce => window.__scopelensMarker === nonce", nonce)
            if not sessions.verify(identity, action_owner=action_owner):
                raise SessionUnavailable("viewer_session_expired")
            return response.status, bool(executed), response.headers
        finally:
            page.close()

    try:
        if not admit(recipe):
            raise SessionUnavailable("explicit_disposable_workflow_grant_missing")
        if recipe.family == "csrf" and (
            origin(recipe.foreign_url) not in allowed_foreign_origins
            or origin(recipe.foreign_url) == origin(recipe.mutation.url)
        ):
            raise SessionUnavailable("controlled_foreign_origin_grant_missing")
        seeded, before, _ = read(sessions)
        save(
            {
                "kind": "baseline",
                "seed_matches": seeded,
                "before_matches": before == recipe.before.value,
            }
        )
        if not seeded or before != recipe.before.value:
            raise SessionUnavailable("seeded_baseline_unavailable")
        if sessions.cancelled():
            raise SessionUnavailable("cancelled_before_mutation")
        if not journal.claim(recipe.id, recipe.resource_id):
            raise SessionUnavailable("prior_cleanup_pending")
        claimed, cleanup_state = True, "pending"
        for iteration in range(3 if recipe.family == "stored_xss" else 2):
            if sessions.cancelled():
                raise SessionUnavailable("cancelled_before_mutation")
            nonce = uuid.uuid4().hex
            if iteration == 0:
                # Persist before the first send: an interrupted request may have run.
                # Later attempts reuse the existing intent; re-marking mutation_sent is
                # not a valid journal transition and the resource stays fenced anyway.
                journal.mark(recipe.id, recipe.resource_id, "mutation_sent")
            if recipe.family == "stored_xss":
                payload = (
                    f"ScopeLens plain {nonce}"
                    if iteration == 0
                    else f"<svg onload=\"window.__scopelensMarker='{nonce}'\"></svg>"
                )
                mutation = recipe.mutation.model_copy(
                    update={
                        "json_body": {**recipe.mutation.json_body, recipe.mutation_field: payload}
                    }
                )
                status, _ = sessions.request(
                    recipe.actor_identity, mutation, action_owner=action_owner
                )
                if not 200 <= status < 300:
                    raise SessionUnavailable("reviewed_marker_write_failed")
                seeded, value, _ = read(sessions)
                _, executed, _ = browser_view(recipe.viewer_identity, recipe.viewer_url, nonce)
                save(
                    {
                        "kind": "plain_control" if iteration == 0 else "browser_proof",
                        "nonce": nonce,
                        "seed_matches": seeded,
                        "persisted": value == payload,
                        "executed": executed,
                        "viewer_verified": True,
                    }
                )
            elif recipe.family == "csrf":
                if not sessions.verify(recipe.viewer_identity, action_owner=action_owner):
                    raise SessionUnavailable("csrf_victim_session_unavailable")
                context = sessions.context(recipe.viewer_identity, action_owner=action_owner)
                if not context.cookies([recipe.mutation.url]):
                    raise SessionUnavailable("csrf_ambient_browser_session_missing")
                page = context.new_page()
                try:
                    response = page.goto(
                        recipe.foreign_url, wait_until="domcontentloaded", timeout=10000
                    )
                    if (
                        response is None
                        or response.status != 200
                        or origin(page.url) != origin(recipe.foreign_url)
                    ):
                        raise SessionUnavailable("controlled_foreign_page_unavailable")
                    fields = {**recipe.form_fields, recipe.mutation_field: nonce}
                    with page.expect_response(
                        lambda r: r.url == recipe.mutation.url, timeout=10000
                    ) as mutation_response:
                        page.evaluate(
                            """({url,fields}) => { const f=document.createElement('form'); f.method='POST'; f.action=url; for (const [name,value] of Object.entries(fields)){const i=document.createElement('input');i.name=name;i.value=value;f.appendChild(i);} document.body.appendChild(f);f.submit(); }""",
                            {"url": recipe.mutation.url, "fields": fields},
                        )
                    status = mutation_response.value.status
                    seeded, value, _ = read(sessions)
                    verified = sessions.verify(recipe.viewer_identity, action_owner=action_owner)
                    save(
                        {
                            "kind": "browser_proof",
                            "nonce": nonce,
                            "seed_matches": seeded,
                            "browser_submitted": True,
                            "ambient_session_present": True,
                            "browser_status": status,
                            "forbidden_state": value == nonce,
                            "unchanged": value == recipe.before.value,
                            "viewer_verified": verified,
                        }
                    )
                finally:
                    page.close()
                # Restore between attempts to make two independent before/after comparisons.
                if not cleanup_sessions.verify(recipe.cleanup_identity, action_owner=action_owner):
                    raise SessionUnavailable("cleanup_identity_unavailable")
                cleanup_sessions.request(
                    recipe.cleanup_identity, recipe.cleanup, action_owner=action_owner
                )
                seeded, value, _ = read(cleanup_sessions)
                if not seeded or value != recipe.before.value:
                    raise SessionUnavailable("intermediate_cleanup_failed")
            else:
                if not sessions.verify(recipe.actor_identity, action_owner=action_owner):
                    raise SessionUnavailable("upload_writer_session_unavailable")
                context = sessions.context(recipe.actor_identity, action_owner=action_owner)
                page = context.new_page()
                payload = f"ScopeLens benign upload {nonce}"
                try:
                    response = page.goto(
                        recipe.upload_form_url, wait_until="domcontentloaded", timeout=10000
                    )
                    if response is None or response.status != 200:
                        raise SessionUnavailable("upload_form_unavailable")
                    page.locator(recipe.upload_selector).set_input_files(
                        {
                            "name": recipe.upload_filename,
                            "mimeType": "text/plain",
                            "buffer": payload.encode(),
                        }
                    )
                    # Response headers alone do not finish a form navigation. Closing
                    # that page immediately can hang Chromium on the worker VM and
                    # prevent cleanup. Register the bounded completion waiter before
                    # clicking so even a fast completed response cannot be missed.
                    with (
                        page.expect_request_finished(
                            lambda r: (
                                r.url == recipe.mutation.url and r.method == recipe.mutation.method
                            ),
                            timeout=10000,
                        ) as upload_finished,
                        page.expect_response(
                            lambda r: r.url == recipe.mutation.url, timeout=10000
                        ) as upload_response,
                    ):
                        page.locator(recipe.upload_submit_selector).click()
                    if upload_finished.value != upload_response.value.request:
                        raise SessionUnavailable("upload_response_request_mismatch")
                    if not 200 <= upload_response.value.status < 300:
                        raise SessionUnavailable("benign_upload_failed")
                finally:
                    page.close()
                seeded, value, _ = read(sessions)
                if not sessions.verify(recipe.viewer_identity, action_owner=action_owner):
                    raise SessionUnavailable("upload_viewer_unavailable")
                viewer = sessions.context(recipe.viewer_identity, action_owner=action_owner)
                result = viewer.request.get(recipe.viewer_url, max_redirects=0, timeout=10000)
                try:
                    if len(result.body()) > 1048576:
                        raise SessionUnavailable("upload_read_exceeds_cap")
                    marker_read = result.status == 200 and nonce in result.text()
                    attachment = (
                        result.headers.get("content-disposition", "")
                        .lower()
                        .startswith("attachment")
                    )
                    violation = (
                        marker_read
                        if recipe.upload_expected_mode == "private"
                        else marker_read and not attachment
                    )
                    enforced = (
                        result.status in {403, 404}
                        if recipe.upload_expected_mode == "private"
                        else marker_read and attachment
                    )
                    save(
                        {
                            "kind": "browser_proof",
                            "nonce": nonce,
                            "seed_matches": seeded,
                            "persisted": value == payload,
                            "policy_violation": violation,
                            "policy_enforced": enforced,
                            "viewer_verified": sessions.verify(
                                recipe.viewer_identity, action_owner=action_owner
                            ),
                            "body_sha256": hashlib.sha256(result.body()).hexdigest(),
                        }
                    )
                finally:
                    result.dispose()
        state, reason = evaluate_browser_workflow(recipe, tuple(observations))
    except SessionUnavailable as exc:
        state, reason = "blocked", str(exc)
    except (PlaywrightError, ValueError, KeyError, PermissionError):
        state, reason = "error", "browser_workflow_operation_failed"
    finally:
        if claimed:
            try:
                if not cleanup_sessions.verify(recipe.cleanup_identity, action_owner=action_owner):
                    raise SessionUnavailable("cleanup_identity_unavailable")
                cleanup_sessions.request(
                    recipe.cleanup_identity, recipe.cleanup, action_owner=action_owner
                )
                seeded, value, _ = read(cleanup_sessions)
                save(
                    {
                        "kind": "cleanup_readback",
                        "seed_matches": seeded,
                        "before_matches": value == recipe.before.value,
                    }
                )
                if not seeded or value != recipe.before.value:
                    raise SessionUnavailable("cleanup_readback_failed")
                journal.mark(recipe.id, recipe.resource_id, "clean")
                cleanup_state = "clean"
            except (SessionUnavailable, PlaywrightError, ValueError, KeyError, PermissionError):
                # A denied or failed cleanup RPC must not discard the partial evidence
                # collected above; the durable pending/mutation_sent intent keeps the
                # resource fenced against further mutations either way.
                cleanup_state = "cleanup_failed"
                with suppress(PermissionError, ValueError):
                    journal.mark(recipe.id, recipe.resource_id, "cleanup_failed")
    return WorkflowResult(
        recipe_id=recipe.id,
        family=recipe.family,
        state=state,
        reason=reason,
        cleanup_state=cleanup_state,
        evidence_refs=tuple(refs),
        observations=tuple(observations),
    )
