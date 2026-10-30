"""Worker diagnostics and supervisor-owned callback proof snapshots.

The worker receives nonce URLs transiently through control RPC. Only the supervisor
reads durable dispatch/receipt records, and its public snapshots never contain those URLs.
"""

from __future__ import annotations

import math
from collections.abc import Callable

from sqlalchemy.exc import SQLAlchemyError

from scopelens.callbacks.client import CallbackControlClient, collect_remote_callback
from scopelens.callbacks.probes import evaluate_callback_assessment
from scopelens.callbacks.runtime import FrozenCallbackTask, evaluate_stored_callback_proof
from scopelens.domain.callback import CallbackAssessment

CAPTURE_KIND = "callback_capture"
CAPTURE_SOURCE = "callback_broker"


def frozen_callback_tasks(configuration, *, owner_id, scan_id):
    return tuple(
        FrozenCallbackTask(
            owner_id=str(owner_id), scan_id=str(scan_id), recipe_id=named.id, recipe=named.recipe
        )
        for named in configuration.callback_recipes
    )


def collect_callback_diagnostics(
    configuration,
    control,
    client,
    *,
    owner_id,
    scan_id,
    emit: Callable[[str, dict], None],
    cancelled=lambda: False,
):
    """Fixed worker path uses its existing mandatory proxy and narrow control facade."""
    for task in frozen_callback_tasks(configuration, owner_id=owner_id, scan_id=scan_id):
        remote = CallbackControlClient(control.callback_rpc, task)
        result = collect_remote_callback(client, remote, cancelled=cancelled)
        # Worker state is diagnostic only; never emit URLs, receipts, tokens or proof refs.
        emit(
            "callback_diagnostic",
            {
                "recipe_id": task.recipe_id,
                "family": task.recipe.family,
                "state": result.state,
                "nonce_count": len(result.nonce_ids),
                "receipt_count": len(result.receipts),
                "control_unavailable": remote.failed,
            },
        )
        if cancelled():
            break


def _safe_snapshot(runtime, task):
    dispatches = []
    reason = "callback_runtime_unavailable"
    if runtime is not None:
        try:
            dispatches = runtime.stored_dispatch_evidence(task)
            reason = "stored_dispatches_available"
        except (ValueError, PermissionError, SQLAlchemyError):
            reason = "callback_dispatch_incomplete_or_repeated"
    return {
        "recipe_id": task.recipe_id,
        "family": task.recipe.family,
        "recipe_digest": task.recipe_digest,
        "task_id": task.task_id,
        "reason": reason,
        "dispatches": [
            {
                "dispatch_ref": d.evidence_ref,
                "nonce_id": d.nonce_id,
                "method": d.method,
                "response_status": d.response_status,
                "sent_at": d.sent_at,
            }
            for d in dispatches
        ],
    }, dispatches


def capture_callback_artifacts(runtime, configuration, *, owner_id, scan_id):
    """Call in the trusted supervisor after discarding worker callback captures.

    Persist each returned artifact through normal trusted evidence intake and attach its
    actual evidence_ref before calling evaluate_callback_artifacts.
    """
    return [
        {
            "kind": CAPTURE_KIND,
            "source": CAPTURE_SOURCE,
            "data": {
                **_safe_snapshot(runtime, task)[0],
                "finished_at": runtime.service.now() if runtime else None,
            },
        }
        for task in frozen_callback_tasks(configuration, owner_id=owner_id, scan_id=scan_id)
    ]


def _inconclusive(task):
    return evaluate_callback_assessment(
        CallbackAssessment(
            family=task.recipe.family,
            state="inconclusive",
            reason="Independent callback dispatch and receipt proof incomplete",
        ),
        None,
    )


def evaluate_callback_artifacts(
    runtime,
    configuration,
    *,
    owner_id,
    scan_id,
    artifacts,
    trusted_refs: set[str],
):
    """Recompute proof from private durable state, never the worker's claimed verdict."""
    results = []
    for task in frozen_callback_tasks(configuration, owner_id=owner_id, scan_id=scan_id):
        matching = [
            a
            for a in artifacts
            if a.get("kind") == CAPTURE_KIND
            and isinstance(a.get("data"), dict)
            and a["data"].get("recipe_id") == task.recipe_id
        ]
        if runtime is None or len(matching) != 1:
            results.append(_inconclusive(task))
            continue
        snapshot, dispatches = _safe_snapshot(runtime, task)
        capture = matching[0]
        ref = capture.get("evidence_ref")
        captured_data = dict(capture["data"])
        finished_at = captured_data.pop("finished_at", None)
        if (
            capture.get("source") != CAPTURE_SOURCE
            or ref not in trusted_refs
            or captured_data != snapshot
            or not isinstance(finished_at, (int, float))
            or not math.isfinite(finished_at)
            or not dispatches
        ):
            results.append(_inconclusive(task))
            continue
        rebound = [d.model_copy(update={"evidence_ref": ref}) for d in dispatches]
        try:
            outcome = evaluate_stored_callback_proof(
                runtime,
                task,
                rebound,
                trusted_refs={ref},
                finished_at=finished_at,
            )
        except SQLAlchemyError:
            outcome = _inconclusive(task)
        if outcome.proof:
            outcome = outcome.model_copy(
                update={
                    "proof": outcome.proof.model_copy(
                        update={"evidence_refs": tuple(dict.fromkeys(outcome.proof.evidence_refs))}
                    )
                }
            )
        results.append(outcome)
    return results


def callback_controls(runtime, configuration, *, owner_id, scan_id, artifacts, trusted_refs):
    """Aggregate frozen recipes per control without dropping incomplete instances."""
    from urllib.parse import urlsplit

    from scopelens.domain.check import Location
    from scopelens.domain.enums import ControlOutcome as Outcome

    tasks = frozen_callback_tasks(configuration, owner_id=owner_id, scan_id=scan_id)
    evaluated = evaluate_callback_artifacts(
        runtime,
        configuration,
        owner_id=owner_id,
        scan_id=scan_id,
        artifacts=artifacts,
        trusted_refs=trusted_refs,
    )
    grouped = {}
    for task, outcome in zip(tasks, evaluated, strict=True):
        grouped.setdefault(outcome.check_id, []).append((task, outcome))
    results = []
    for instances in grouped.values():
        confirmed = [
            (task, row) for task, row in instances if row.status is Outcome.CONFIRMED_ISSUE
        ]
        representative = (confirmed or instances)[0][1]
        required = tuple(task.recipe_id for task, _ in instances)
        completed = tuple(task.recipe_id for task, row in instances if row.is_fully_assessed)
        incomplete = tuple(
            f"Callback recipe {task.recipe_id}: independent proof incomplete"
            for task, row in instances
            if not row.is_fully_assessed
        )
        locations = {
            (urlsplit(task.recipe.target_url).path or "/", task.recipe.parameter): Location(
                route=urlsplit(task.recipe.target_url).path or "/",
                parameter=task.recipe.parameter,
                detail="Correlated canary HTTP interaction",
            )
            for task, _ in confirmed
        }
        proof = representative.proof
        if proof:
            refs = tuple(
                dict.fromkeys(
                    ref
                    for _, row in confirmed
                    for ref in (row.proof.evidence_refs if row.proof else ())
                )
            )
            proof = proof.model_copy(update={"evidence_refs": refs})
        results.append(
            representative.model_copy(
                update={
                    "required_instances": required,
                    "completed_instances": completed,
                    "incomplete_reasons": incomplete,
                    "locations": tuple(locations.values()),
                    "proof": proof,
                }
            )
        )
    return results
