"""Freeze deterministic control/input denominators without granting execution authority."""

import re

from scopelens.domain.assessment import (
    ActionPolicy,
    AssessmentPlanVersion,
    AssessmentTask,
    DiscoveryCatalogue,
    stable_id,
)

REVIEWED_INPUT_CONTROLS = (
    "SL-C03-XSS-01",
    "SL-C03-DOMXSS-01",
    "SL-C03-SQL-01",
    "SL-C03-HTML-01",
    "SL-C04-REDIRECT-01",
    "SL-C04-HDRINJECT-01",
)
DEFAULT_REVIEWED_CONTROLS = (*REVIEWED_INPUT_CONTROLS, "SL-C04-CORS-01")
SIDE_EFFECT = re.compile(
    r"(?:^|[/_.-])(logout|delete|remove|destroy|pay|purchase|checkout|send|invite|unsubscribe|reset|transfer)(?:$|[/_.-])",
    re.I,
)
REDIRECT_INPUT = re.compile(r"redirect|return|next|url|dest|continue|callback", re.I)


def plan_assessment(
    catalogue: DiscoveryCatalogue,
    *,
    scope_version: str,
    policies: tuple[ActionPolicy, ...] = (),
    previous: AssessmentPlanVersion | None = None,
    reviewed_control_ids: tuple[str, ...] | None = None,
    profile: str = "external-active-v2",
) -> AssessmentPlanVersion:
    """Create ready/blocked tasks. The broker must independently admit each execution.

    Revisions retain every prior task so a later discovery cannot remove failed work from
    the denominator. Execution results belong to the task ledger, never this frozen plan.
    """
    if previous and (previous.scope_version != scope_version or previous.profile != profile):
        raise ValueError("plan revisions cannot change scope or profile")
    reviewed = set(
        DEFAULT_REVIEWED_CONTROLS if reviewed_control_ids is None else reviewed_control_ids
    )
    by_policy = {}
    for policy in policies:
        key = (policy.template_id, policy.role_id)
        if key in by_policy:
            raise ValueError("ambiguous duplicate action policies")
        by_policy[key] = policy
    tasks = {t.id: t for t in previous.tasks} if previous else {}
    for template in catalogue.templates:
        policy = by_policy.get((template.id, template.role_id))
        reason = None
        if template.authority in {"unapproved", "resource_only"}:
            reason = "origin_not_granted_for_assessment"
        elif policy and policy.classification == "deny":
            reason = "operator_denied_action"
        elif (
            template.method not in {"GET", "HEAD"} or SIDE_EFFECT.search(template.path)
        ) and not policy:
            reason = "action_requires_operator_classification"
        elif not template.baseline_complete:
            reason = "request_baseline_incomplete"
        elif "{" in template.path or "}" in template.path:
            reason = "unresolved_path_baseline"
        elif any(
            i.required and i.baseline_value is None and not i.secret_ref for i in template.inputs
        ):
            reason = "required_baseline_missing"
        # Secret material is resolved and refreshed immediately before execution.
        candidates = [("SL-C04-CORS-01", None)]
        for location in template.inputs:
            if not location.mutable or location.location not in {"query", "path", "form", "json"}:
                continue
            for control in REVIEWED_INPUT_CONTROLS:
                if control == "SL-C04-REDIRECT-01" and not REDIRECT_INPUT.search(location.name):
                    continue
                if control in {
                    "SL-C03-XSS-01",
                    "SL-C03-DOMXSS-01",
                    "SL-C03-HTML-01",
                    "SL-C04-HDRINJECT-01",
                } and location.value_type not in {"string", "null"}:
                    continue
                candidates.append((control, location.key))
        for control, key in candidates:
            if control not in reviewed:
                continue
            blocked = reason
            if policy and policy.control_ids and control not in policy.control_ids:
                blocked = blocked or "control_not_in_action_policy"
            ident = stable_id([template.id, control, key])
            task = AssessmentTask(
                id=ident,
                template_id=template.id,
                control_id=control,
                input_key=key,
                state="blocked" if blocked else "ready",
                reason=blocked or "reviewed_applicable_control",
            )
            tasks.setdefault(ident, task)
    ordered = tuple(tasks[k] for k in sorted(tasks))
    catalogue_hash = stable_id(catalogue.model_dump(mode="json"))
    revision = previous.revision + 1 if previous else 1
    identity = [
        scope_version,
        profile,
        revision,
        previous.id if previous else None,
        catalogue_hash,
        [t.model_dump() for t in ordered],
    ]
    return AssessmentPlanVersion(
        id=stable_id(identity),
        revision=revision,
        previous_id=previous.id if previous else None,
        scope_version=scope_version,
        catalogue_hash=catalogue_hash,
        profile=profile,
        tasks=ordered,
        denominator=sum(t.coverage_weight for t in ordered),
        carried_task_ids=tuple(t.id for t in previous.tasks) if previous else (),
    )
