"""Context-specific follow-ups, with no stateful recipe or identity replay."""

import json
from dataclasses import replace
from datetime import UTC, datetime

from scopelens.domain.assessment import AssessmentPlanVersion, DiscoveryCatalogue
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.execution.supervisor import ARTIFACT_MARKER, SupervisorError, WorkerResult
from scopelens.expansion.integration import run_expanded_browser
from scopelens.orchestration.expansion import Hypothesis
from scopelens.persistence.models import ScanRow
from scopelens.persistence.session import session_scope


def access_configuration(raw, proof_id):
    """Only existing supplied sessions and read-only probes can be repeated."""
    try:
        configuration = AssessmentConfiguration.model_validate(raw)
        matrix = configuration.permission_matrix
        rule = next(rule for rule in matrix.rules if rule.id == proof_id)
        target = next(obj for obj in matrix.objects if obj.id == rule.object_id)
        if (
            target.request.json_body
            or target.request.secret_fields
            or target.request.secret_headers
        ):
            return None
        profiles = tuple(
            profile
            for profile in configuration.identities
            if profile.id in {rule.identity_id, target.owner_identity}
        )
        if len(profiles) != len({rule.identity_id, target.owner_identity}):
            return None
        for profile in profiles:
            if profile.anonymous:
                continue
            if (
                profile.login
                or not profile.supplied_headers
                or profile.probe is None
                or profile.probe.request.method not in {"GET", "HEAD"}
                or profile.probe.request.json_body
                or profile.probe.request.secret_fields
                or profile.probe.request.secret_headers
                or (profile.expires_at and profile.expires_at <= datetime.now(UTC))
            ):
                return None
        return AssessmentConfiguration(
            scope_version_id=configuration.scope_version_id,
            identities=profiles,
            related_origins=configuration.related_origins,
            permission_matrix=matrix.model_copy(update={"objects": (target,), "rules": (rule,)}),
        )
    except (ValueError, TypeError, AttributeError, StopIteration):
        return None


def reflection_payload(saved, candidate, *, scan_id, scope):
    """Project exactly one frozen anonymous GET task and no workflow recipes."""
    hypothesis = Hypothesis.model_validate(candidate)
    catalogue = DiscoveryCatalogue.model_validate(saved["request_catalogue"])
    plan = AssessmentPlanVersion.model_validate(saved["input_assessment_plan"])
    if (
        hypothesis.state != "ready"
        or hypothesis.operation != "browser-reflection-proof"
        or hypothesis.plan_id != plan.id
        or hypothesis.scope_version != str(scope.id)
        or hypothesis.catalogue_hash != plan.catalogue_hash
        or catalogue.origin != scope.origin
    ):
        raise SupervisorError("reflection follow-up binding changed")
    from scopelens.domain.assessment import stable_id

    if plan.catalogue_hash != stable_id(catalogue.model_dump(mode="json")):
        raise SupervisorError("reflection catalogue binding changed")
    task = next((task for task in plan.tasks if task.id == hypothesis.task_id), None)
    template = next(
        (template for template in catalogue.templates if task and template.id == task.template_id),
        None,
    )
    if (
        task is None
        or template is None
        or task.state != "ready"
        or task.control_id != hypothesis.control
        or task.template_id != hypothesis.template_id
        or template.method != "GET"
        or template.role_id != "anonymous"
        or template.authority != "primary"
        or not template.baseline_complete
        or template.origin + template.path != hypothesis.url
        or any(item.secret_ref for item in template.inputs)
        or hypothesis.max_requests != 6
    ):
        raise SupervisorError("reflection follow-up requires reviewed anonymous GET input")
    return json.dumps(
        {
            "owner_id": str(saved.get("operator_id", "")),
            "scan_id": str(scan_id),
            "catalogue": catalogue.model_dump(mode="json"),
            "plan": plan.model_copy(
                update={"tasks": (task,), "denominator": task.coverage_weight}
            ).model_dump(mode="json"),
            "configuration": AssessmentConfiguration(scope_version_id=scope.id).model_dump(
                mode="json"
            ),
        },
        separators=(",", ":"),
    )


def run_reflection_followup(settings, supervisor, spec, *, candidate, scan_id, run_id, scope):
    with session_scope(settings) as session:
        row = session.get(ScanRow, scan_id)
        if row.cancel_requested_at or row.cancel_epoch != row.egress_token_epoch:
            raise SupervisorError("reflection follow-up authority revoked")
        saved = dict(row.assessment_plan or {})
        payload = reflection_payload(saved, candidate, scan_id=scan_id, scope=scope)
    if len(payload.encode()) > 100000:
        raise SupervisorError("reflection follow-up payload exceeds limit")
    return run_expanded_browser(
        settings,
        supervisor,
        spec,
        run_id=run_id,
        scan_id=scan_id,
        payload=payload,
        capability="",
    )


def append_callback_observations(settings, output, *, scan_id):
    from scopelens.callbacks.deployment import runtime_from_settings
    from scopelens.callbacks.integration import capture_callback_artifacts

    with session_scope(settings) as session:
        row = session.get(ScanRow, scan_id)
        config = AssessmentConfiguration.model_validate(row.assessment_plan["expansion_config"])
        owner_id = row.operator_id
    artifacts = capture_callback_artifacts(
        runtime_from_settings(settings),
        config,
        owner_id=owner_id,
        scan_id=scan_id,
    )
    artifacts = [{**item, "kind": "callback_investigation"} for item in artifacts]
    return replace(
        output,
        stdout=output.stdout
        + "\n"
        + "\n".join(ARTIFACT_MARKER + json.dumps(item) for item in artifacts),
    )


def verify_callback_followup(settings, *, candidate, scan_id, run_id):
    """Re-read durable signed receipts. Never issue a nonce or replay target requests."""
    from scopelens.callbacks.deployment import runtime_from_settings
    from scopelens.callbacks.integration import frozen_callback_tasks
    from scopelens.callbacks.runtime import evaluate_stored_callback_proof

    hypothesis = Hypothesis.model_validate(candidate)
    with session_scope(settings) as session:
        row = session.get(ScanRow, scan_id)
        if row.cancel_requested_at or row.cancel_epoch != row.egress_token_epoch:
            raise SupervisorError("callback follow-up authority revoked")
        configuration = AssessmentConfiguration.model_validate(
            row.assessment_plan["expansion_config"]
        )
        owner_id = row.operator_id
    runtime = runtime_from_settings(settings)
    task = next(
        (
            task
            for task in frozen_callback_tasks(configuration, owner_id=owner_id, scan_id=scan_id)
            if task.recipe_id == hypothesis.proof_id
        ),
        None,
    )
    if (
        runtime is None
        or task is None
        or hypothesis.max_requests != 0
        or task.recipe.target_url != hypothesis.url
    ):
        raise SupervisorError("callback follow-up frozen collector unavailable")
    dispatches = runtime.stored_dispatch_evidence(task)
    outcome = evaluate_stored_callback_proof(
        runtime,
        task,
        dispatches,
        trusted_refs={item.evidence_ref for item in dispatches},
        finished_at=runtime.service.now(),
    )
    from scopelens.domain.enums import ControlOutcome

    verification = {
        "state": "corroborated"
        if outcome.status == ControlOutcome.CONFIRMED_ISSUE
        else "inconclusive",
        "reason": outcome.summary,
        "proof_state": outcome.status.value,
    }
    artifact = {
        "kind": "callback_followup_verification",
        "source": "callback_broker",
        "data": {"hypothesis_id": hypothesis.id, "verification": verification},
    }
    return WorkerResult(run_id, 0, ARTIFACT_MARKER + json.dumps(artifact), "", 0)
