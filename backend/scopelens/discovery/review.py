"""Explicit display projection of immutable private catalogues; never executable input."""

from urllib.parse import quote, urlsplit

from scopelens.domain.assessment import AssessmentPlanVersion, DiscoveryCatalogue, stable_id
from scopelens.domain.expansion import (
    PlanTemplateReviewView,
    RequestTemplateReviewView,
    ReviewInputView,
    ReviewTaskCounts,
)
from scopelens.security.redaction import redact_text


def project_review(
    *, scan_id, scope_version_id, profile, origin, frozen, plan_id, offset=0, limit=100
):
    """Select and validate exactly one persisted revision before projecting any content."""
    if offset < 0 or not 1 <= limit <= 200:
        raise ValueError("invalid pagination")
    revisions = frozen.get("assessment_plan_revisions", [])
    matches = [row for row in revisions if row.get("plan", {}).get("id") == plan_id]
    if not matches:
        raise LookupError("missing revision")
    if len(matches) != 1:
        raise ValueError("duplicate revision")
    plan = AssessmentPlanVersion.model_validate(matches[0]["plan"])
    catalogue = DiscoveryCatalogue.model_validate(matches[0]["catalogue"])
    if (
        str(plan.scope_version) != str(scope_version_id)
        or plan.profile != profile
        or catalogue.origin != origin
        or plan.catalogue_hash != stable_id(catalogue.model_dump(mode="json"))
        or plan.id
        != stable_id(
            [
                plan.scope_version,
                plan.profile,
                plan.revision,
                plan.previous_id,
                plan.catalogue_hash,
                [task.model_dump() for task in plan.tasks],
            ]
        )
    ):
        raise ValueError("revision binding mismatch")
    templates = {item.id: item for item in catalogue.templates}
    if len(templates) != len(catalogue.templates):
        raise ValueError("duplicate template")
    for task in plan.tasks:
        template = templates.get(task.template_id)
        if (
            template is None
            or (
                task.input_key is not None
                and task.input_key not in {i.key for i in template.inputs}
            )
            or task.id != stable_id([task.template_id, task.control_id, task.input_key])
        ):
            raise ValueError("task template binding mismatch")
    ordered = sorted(templates)
    selected = ordered[offset : offset + limit]
    views = []
    for ident in selected:
        template = templates[ident]
        # Explicit fields only: no model_dump of a private template/input. Scrub known
        # private strings too if target metadata accidentally repeats them in a label.
        private = {
            value
            for item in template.inputs
            for value in (item.secret_ref, item.baseline_value)
            if isinstance(value, str) and len(value) >= 4
        }

        def label(value, private=private):
            if value is None:
                return None
            result = redact_text(value)
            for secret in sorted(private, key=len, reverse=True):
                result = result.replace(secret, "[redacted]").replace(
                    quote(secret, safe=""), "[redacted]"
                )
            return result

        route = template.route_template
        parsed = urlsplit(route)
        # route_template is source metadata, not a validated request path. Never
        # surface a provenance URL, query or fragment smuggled into this label.
        if parsed.scheme or parsed.netloc or not route.startswith("/"):
            route = "[redacted]"
        else:
            route = parsed.path
            for item in template.inputs:
                if item.location == "path" and item.baseline_value is not None:
                    value = str(item.baseline_value)
                    if value:
                        route = route.replace(value, "{input}").replace(
                            quote(value, safe=""), "{input}"
                        )
            route = label(route)
        inputs = tuple(
            ReviewInputView(
                id=stable_id([template.id, item.key]),
                location=item.location,
                name=label(item.name),
                pointer=label(item.pointer),
                occurrence=item.occurrence,
                value_type=item.value_type,
                required=item.required,
                mutable=item.mutable,
                refresh_required=bool(item.secret_ref),
                label_redacted=label(item.name) != item.name or label(item.pointer) != item.pointer,
            )
            for item in template.inputs
        )
        tasks = [task for task in plan.tasks if task.template_id == ident]
        views.append(
            RequestTemplateReviewView(
                id=template.id,
                origin=label(template.origin),
                route=route,
                method=template.method,
                role_id=label(template.role_id),
                content_type=label(template.content_type),
                baseline_complete=template.baseline_complete,
                baseline_observed=template.baseline_observed,
                label_redacted=(
                    route != template.route_template
                    or label(template.origin) != template.origin
                    or label(template.role_id) != template.role_id
                    or label(template.content_type) != template.content_type
                ),
                inputs=inputs,
                tasks=ReviewTaskCounts(
                    planned=len(tasks),
                    ready=sum(task.state == "ready" for task in tasks),
                    blocked=sum(task.state == "blocked" for task in tasks),
                    carried=sum(task.id in plan.carried_task_ids for task in tasks),
                    control_ids=tuple(sorted({task.control_id for task in tasks})),
                ),
            )
        )
    end = offset + len(selected)
    return PlanTemplateReviewView(
        scan_id=scan_id,
        scope_version_id=scope_version_id,
        profile=profile,
        plan_id=plan.id,
        revision=plan.revision,
        catalogue_hash=plan.catalogue_hash,
        templates=tuple(views),
        total=len(ordered),
        offset=offset,
        next_offset=end if end < len(ordered) else None,
    )
