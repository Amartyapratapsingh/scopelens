"""Recompute expanded proof from captured facts and retain every planned task."""

from collections import defaultdict

from scopelens.checks.engine import Control, validate_outcome
from scopelens.checks.expanded_active import CONTROL_KINDS, evaluate_expanded
from scopelens.checks.packs.exposure import ExposurePackResult, evaluate_exposure_pack
from scopelens.domain.assessment import AssessmentTask, DiscoveryCatalogue
from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import ControlOutcome as State
from scopelens.domain.enums import EvidenceStatus, Severity
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.authenticated_browser import evaluate_browser_input_identity
from scopelens.expansion.authenticated_inputs import evaluate_input_identity
from scopelens.expansion.proof_aggregation import admitted_artifacts, identity_workflow_outcomes

SEVERITIES = {
    "sql": Severity.HIGH,
    "xss": Severity.HIGH,
    "dom_xss": Severity.HIGH,
    "html": Severity.MEDIUM,
    "redirect": Severity.MEDIUM,
    "cors": Severity.LOW,
    "header_injection": Severity.MEDIUM,
}


def expansion_controls(artifacts, frozen, registry, *, trusted_refs, cleanup_states=None):
    from scopelens.expansion.integration import prior_capture_plan_id

    artifacts = admitted_artifacts(artifacts, trusted_refs)
    outcomes = identity_workflow_outcomes(
        artifacts, frozen, registry, cleanup_states=cleanup_states
    )
    config = (
        AssessmentConfiguration.model_validate(frozen["expansion_config"])
        if frozen.get("expansion_config")
        else None
    )
    profiles = {p.id: p for p in config.identities} if config else {}
    catalogue = (
        DiscoveryCatalogue.model_validate(frozen["request_catalogue"])
        if frozen.get("request_catalogue")
        else None
    )
    templates = {t.id: t for t in catalogue.templates} if catalogue else {}
    for artifact in artifacts:
        if artifact.get("kind") == "exposure_pack" and artifact.get("evidence_ref"):
            for outcome in evaluate_exposure_pack(
                ExposurePackResult.model_validate(artifact["data"]), artifact["evidence_ref"]
            ):
                outcomes[outcome.check_id] = outcome
    tasks = defaultdict(list)
    for task in frozen.get("input_assessment_plan", {}).get("tasks", []):
        tasks[task["control_id"]].append(task)
    captures = {}
    for a in artifacts:
        if a.get("kind") == "expanded_active_probe" and a.get("evidence_ref"):
            captures.setdefault(a["data"].get("task_id"), []).append(a)
    for control_id, planned in tasks.items():
        entry = registry.get(control_id)
        if entry is None:
            continue
        complete, reasons, locations, evidence, verdicts = [], [], [], [], []
        for task in planned:
            rows = captures.get(task["id"], [])
            # HTTP and browser collectors may emit one blocked and one actual observation.
            rows = [a for a in rows if a["data"].get("state") != "blocked"] or rows
            if task["state"] == "blocked" or not rows:
                reasons.append(
                    f"{task['id']}: {task['reason'] if task['state'] == 'blocked' else 'capture_missing'}"
                )
                continue
            artifact = rows[-1]
            data = artifact["data"]
            template = templates.get(task["template_id"])
            capture_plan_id = prior_capture_plan_id(frozen, task, template, data.get("plan_id"))
            if (
                not capture_plan_id
                or data.get("template_id") != task["template_id"]
                or data.get("control_id") != control_id
                or data.get("input_key") != task.get("input_key")
            ):
                reasons.append(f"{task['id']}: capture_binding_mismatch")
                continue
            kind = CONTROL_KINDS[control_id]
            if kind in {"xss", "html", "dom_xss"} and artifact.get("source") != "expansion_browser":
                reasons.append(f"{task['id']}: reviewed_browser_capture_required")
                continue
            if (
                template is None
                or data.get("method") != template.method
                or data.get("route") != template.path
            ):
                reasons.append(f"{task['id']}: capture_request_binding_mismatch")
                continue
            role_id = template.role_id
            if data.get("role_id", "anonymous") != role_id:
                reasons.append(f"{task['id']}: identity_role_binding_mismatch")
                continue
            if role_id != "anonymous":
                profile = profiles.get(role_id)
                if profile is None:
                    reasons.append(f"{task['id']}: frozen_identity_profile_missing")
                    continue
                args = (
                    profile,
                    AssessmentTask.model_validate(task),
                    template,
                    capture_plan_id,
                )
                if artifact.get("source") == "expansion_browser":
                    valid, reason = evaluate_browser_input_identity(
                        *args, data.get("browser_identity_proofs"), data.get("captures")
                    )
                else:
                    valid, reason = evaluate_input_identity(*args, data.get("identity_proof"))
                if not valid:
                    reasons.append(f"{task['id']}: {reason}")
                    continue
            if data.get("state") == "blocked":
                state, reason = "blocked", data.get("reason", "blocked")
            else:
                state, reason = evaluate_expanded(
                    kind, data.get("captures", []), error=data.get("error")
                )
            verdicts.append(state)
            if state in {"confirmed", "pass"}:
                complete.append(task["id"])
                evidence.append(artifact["evidence_ref"])
            else:
                reasons.append(f"{task['id']}: {reason}")
            if state == "confirmed":
                locations.append(
                    Location(
                        route=template.path,
                        parameter=data.get("input_key"),
                        detail=f"{template.method} / role={role_id} / {reason}",
                    )
                )
        confirmed = bool(locations)
        status = (
            State.CONFIRMED_ISSUE
            if confirmed
            else State.PASS
            if len(complete) == len(planned)
            else State.INCONCLUSIVE
        )
        outcome = ControlOutcome(
            check_id=control_id,
            canonical_control=entry.canonical_control,
            category=entry.category,
            status=status,
            summary=f"{len(complete)}/{len(planned)} discovered input instances assessed",
            proposed_severity=SEVERITIES[CONTROL_KINDS[control_id]] if confirmed else None,
            locations=tuple(locations),
            required_instances=tuple(t["id"] for t in planned),
            completed_instances=tuple(complete),
            incomplete_reasons=tuple(reasons),
            proof=ProofResult(
                satisfied=confirmed,
                status=EvidenceStatus.CONFIRMED if confirmed else EvidenceStatus.INCONCLUSIVE,
                evidence_refs=tuple(dict.fromkeys(evidence)),
                reasons=("Reviewed proof recomputed from bound captured request series",),
            ),
        )
        validate_outcome(outcome)
        outcomes[control_id] = outcome
    return tuple(
        Control(check_id=ident, evaluate=lambda context, value=value: value)
        for ident, value in outcomes.items()
    )
