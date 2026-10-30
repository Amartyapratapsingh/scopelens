"""Extend the existing scan lifecycle; no separate queue, lease or request budget."""

import hashlib
import json
import secrets
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from scopelens.checks.analyze import responses_from_artifacts, surface_from_artifacts
from scopelens.discovery import discover_catalogue, plan_assessment
from scopelens.domain.assessment import (
    AssessmentPlanVersion,
    DiscoveryCatalogue,
    RequestTemplate,
    stable_id,
)
from scopelens.domain.capabilities import canonical_sha256
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.execution.supervisor import (
    ARTIFACT_MARKER,
    RESULT_MARKER,
    SupervisorError,
    WorkerResult,
)
from scopelens.persistence.models import BrowserSessionRow, ScanRow
from scopelens.persistence.repositories import record_audit, scope_row_to_domain
from scopelens.persistence.session import session_scope


def prepare_browser_owner(settings, scan_id, token, owner):
    """Only the coordinator assigns a successor after the prior context has closed."""
    from scopelens.broker.policy import scan_for_token
    from scopelens.execution.leases import lease_is_live

    with session_scope(settings) as session:
        scan = scan_for_token(session, token)
        if scan is None or scan.id != scan_id:
            raise SupervisorError("expanded browser authority unavailable")
        session.refresh(scan, with_for_update=True)
        now = datetime.now(UTC)
        if (
            scan.cancel_requested_at
            or scan.cancel_epoch != scan.egress_token_epoch
            or not lease_is_live(session, scan_id, now=now)
            or scan.scope_version.authorization_expires_at <= now
        ):
            raise SupervisorError("expanded browser authority expired or revoked")
        row = session.get(BrowserSessionRow, scan_id)
        if row and (row.status != "closed" or row.inflight or row.owner == owner):
            raise SupervisorError("prior browser context is not closed")
        old_context = row.context_id if row else None
        if row is None:
            row = BrowserSessionRow(scan_id=scan_id)
            session.add(row)
        row.owner, row.context_id = owner, str(uuid.uuid4())
        row.scope_revision = scope_row_to_domain(scan.scope_version).content_hash()
        row.expires_at = min(
            now + timedelta(minutes=15), scan.scope_version.authorization_expires_at
        )
        row.sequence, row.status, row.inflight = 0, "active", False
        row.cancel_epoch, row.actions = scan.cancel_epoch, []
        record_audit(
            session,
            actor="coordinator",
            action="browser.successor",
            subject_type="scan",
            subject_id=str(scan_id),
            outcome="admitted",
            detail={
                "previous_context_id": old_context,
                "context_id": row.context_id,
                "owner": owner,
            },
        )


def run_expanded_browser(settings, supervisor, spec, *, run_id, scan_id, payload, capability):
    browser_id = run_id + "-expansion-browser"
    try:
        if not settings.browser_enabled:
            raise SupervisorError("expanded browser disabled")
        prepare_browser_owner(
            settings, scan_id, spec.environment["SCOPELENS_EGRESS_TOKEN"], browser_id
        )
        browser_spec = replace(
            spec,
            image=settings.browser_worker_image,
            browser=True,
            command=["python", "-m", "scopelens.expansion.browser_worker"],
            environment={
                **spec.environment,
                "SCOPELENS_EXPANSION_INPUT": payload,
                "SCOPELENS_EXPANSION_CAPABILITY": capability,
                "SCOPELENS_BROWSER_OWNER": browser_id,
                "SCOPELENS_BROWSER_MAX_ACTIONS": str(settings.browser_max_actions),
                "SCOPELENS_BROWSER_MAX_ACTIVE_ACTIONS": str(settings.browser_max_active_actions),
            },
            labels={**spec.labels, "scopelens.run_id": browser_id},
        )
        return supervisor.run(browser_spec, run_id=browser_id)
    except SupervisorError as exc:
        return WorkerResult(browser_id, 1, "", str(exc), 0)


def prepare_catalogue(origin, captures, config, prior=None):
    observed = discover_catalogue(
        origin,
        surface=surface_from_artifacts(captures),
        responses=responses_from_artifacts(captures),
        grants=config.related_origins,
        browser_requests=[a["data"] for a in captures if a.get("kind") == "browser_request"],
    )
    # Operator request templates can supply baselines and secret references. Authority is
    # derived again, never accepted from an imported field.
    grants = {g.origin: g.purpose for g in config.related_origins}
    templates = {t.id: t for t in prior.templates} if prior else {}
    imported = {t.id for item in config.imports for t in item.catalogue.templates}
    gaps = [*(prior.gaps if prior else ()), *observed.gaps]
    for item in config.imports:
        gaps.extend(item.catalogue.gaps)
        for template in item.catalogue.templates:
            templates[template.id] = template
    # An observation cannot upgrade an imported operation without operator review.
    for template in observed.templates:
        if template.id not in imported:
            templates[template.id] = template
    for capture in captures:
        if capture.get("kind") != "browser_request_template":
            continue
        try:
            template = RequestTemplate.model_validate(capture["data"]["template"])
        except (KeyError, TypeError, ValueError):
            continue
        if template.id not in imported:
            templates[template.id] = template
    policies = {(p.template_id, p.role_id): p for p in config.policies}
    for template in config.templates:
        if template.id in imported and (template.id, template.role_id) not in policies:
            template = template.model_copy(update={"baseline_complete": False})
        if any(i.secret_ref and i.secret_ref.startswith("refresh:") for i in template.inputs):
            template = template.model_copy(update={"baseline_complete": False})
        templates[template.id] = template
    for ident, template in templates.items():
        if any(i.secret_ref and i.secret_ref.startswith("refresh:") for i in template.inputs):
            template = template.model_copy(update={"baseline_complete": False})
        authority = (
            "primary" if template.origin == origin else grants.get(template.origin, "unapproved")
        )
        templates[ident] = template.model_copy(update={"authority": authority})
    unique_gaps = {stable_id(g.model_dump()): g for g in gaps}
    instances = {
        stable_id(i.model_dump()): i
        for i in (*((prior.instances) if prior else ()), *observed.instances)
    }
    return observed.model_copy(
        update={
            "templates": tuple(templates[k] for k in sorted(templates)),
            "gaps": tuple(unique_gaps[k] for k in sorted(unique_gaps)),
            "instances": tuple(instances[k] for k in sorted(instances)),
        }
    )


def prior_capture_plan_id(frozen, task, template, capture_plan_id):
    """Accept only a durable prior binding, never a worker-supplied plan assertion."""
    current = frozen.get("input_assessment_plan", {})
    if capture_plan_id == current.get("id"):
        return capture_plan_id
    if hasattr(task, "model_dump"):
        task = task.model_dump(mode="json")
    if hasattr(template, "model_dump"):
        template = template.model_dump(mode="json")
    if not template:
        return None
    for revision in frozen.get("assessment_plan_revisions", []):
        plan = revision.get("plan", {})
        if plan.get("id") != capture_plan_id:
            continue
        if plan.get("scope_version") != current.get("scope_version") or plan.get(
            "profile"
        ) != current.get("profile"):
            continue
        if task not in plan.get("tasks", []):
            continue
        if template in revision.get("catalogue", {}).get("templates", []):
            return capture_plan_id
    return None


def freeze_revision(frozen, catalogue, config, *, scope, run_id):
    """Pure write-ahead plan/execution projection; caller persists under the scan lock."""
    prior = (
        AssessmentPlanVersion.model_validate(frozen["input_assessment_plan"])
        if frozen.get("input_assessment_plan")
        else None
    )
    revisions = list(frozen.get("assessment_plan_revisions", []))
    if len(revisions) >= 32:
        raise SupervisorError("assessment revision limit reached")
    plan = plan_assessment(
        catalogue,
        scope_version=str(scope.id),
        policies=config.policies,
        previous=prior,
        profile=scope.allowed_check_profile.value,
        reviewed_control_ids=None if scope.allowed_check_profile.includes_active_pack else (),
    )
    claims = dict(frozen.get("assessment_execution_claims", {}))
    # Legacy plans may have executed even if no claim was recorded. Never retry them.
    if prior:
        for task in prior.tasks:
            if task.state == "ready":
                claims.setdefault(
                    "task:" + task.id, {"plan_id": prior.id, "state": "outcome_unknown"}
                )
    runnable = []
    for task in plan.tasks:
        key = "task:" + task.id
        if task.state == "ready" and key in claims:
            runnable.append(
                task.model_copy(
                    update={"state": "blocked", "reason": "prior_execution_not_replayed"}
                )
            )
        else:
            runnable.append(task)
            if task.state == "ready":
                claims[key] = {"plan_id": plan.id, "run_id": run_id, "state": "admitted"}
    # Session logout, permission tests and recipes can mutate state too. Reserve each
    # group before dispatch, including an outcome-unknown attempt; never infer success.
    changes = {}
    for field in (
        "workflows",
        "browser_workflows",
        "read_probes",
        "callback_recipes",
        "session_policies",
        "cors_recipes",
    ):
        values = []
        for item in getattr(config, field):
            key = field + ":" + stable_id(item.model_dump(mode="json"))
            if key not in claims and not prior:
                values.append(item)
                claims[key] = {"plan_id": plan.id, "run_id": run_id, "state": "admitted"}
        changes[field] = tuple(values)
    if config.permission_matrix:
        key = "permission_matrix:" + stable_id(config.permission_matrix.model_dump(mode="json"))
        if key in claims or prior:
            changes["permission_matrix"] = None
        else:
            claims[key] = {"plan_id": plan.id, "run_id": run_id, "state": "admitted"}
    snapshot = {
        "plan": plan.model_dump(mode="json"),
        "catalogue": catalogue.model_dump(mode="json"),
        "run_id": run_id,
    }
    if prior and not any(r.get("plan", {}).get("id") == prior.id for r in revisions):
        revisions.append(
            {
                "plan": prior.model_dump(mode="json"),
                "catalogue": frozen.get("request_catalogue", {}),
                "run_id": None,
            }
        )
    revisions.append(snapshot)
    updated = {
        **frozen,
        "input_assessment_plan": snapshot["plan"],
        "request_catalogue": snapshot["catalogue"],
        "assessment_plan_revisions": revisions,
        "assessment_execution_claims": claims,
    }
    execution_plan = plan.model_copy(update={"tasks": tuple(runnable)})
    return updated, plan, execution_plan, config.model_copy(update=changes)


def run_expansion(settings, supervisor, spec, previous, *, run_id, scan_id, scope):
    with session_scope(settings) as session:
        scan = session.get(ScanRow, scan_id)
        session.refresh(scan, with_for_update=True)
        config = AssessmentConfiguration.model_validate(scan.assessment_plan["expansion_config"])
        owner_id = str(scan.operator_id)
        prior_catalogue = (
            DiscoveryCatalogue.model_validate(scan.assessment_plan["request_catalogue"])
            if scan.assessment_plan.get("request_catalogue")
            else None
        )
        catalogue = prepare_catalogue(scope.origin, previous.artifacts(), config, prior_catalogue)
        frozen, plan, execution_plan, execution_config = freeze_revision(
            scan.assessment_plan, catalogue, config, scope=scope, run_id=run_id
        )
        capability = secrets.token_urlsafe(32)
        scan.assessment_plan = {
            **frozen,
            "expansion_capability_hash": hashlib.sha256(capability.encode()).hexdigest(),
            "request_catalogue": catalogue.model_dump(mode="json"),
            "input_assessment_plan": plan.model_dump(mode="json"),
        }
        if scan.assessment_plan.get("capability_measurement"):
            from scopelens.execution.capability_producer import bind_measurement

            scan.assessment_plan = bind_measurement(
                scan.assessment_plan,
                scan_id=scan_id,
                scope=scope,
                settings=settings,
                measurement=scan.assessment_plan["capability_measurement"],
            )
        record_audit(
            session,
            actor="coordinator",
            action="assessment.plan.frozen",
            subject_type="scan",
            subject_id=str(scan_id),
            outcome="created",
            detail={
                "plan_id": plan.id,
                "denominator": plan.denominator,
                "catalogue_hash": stable_id(catalogue.model_dump(mode="json")),
            },
        )
    surface = surface_from_artifacts(previous.artifacts())
    payload = {
        "owner_id": owner_id,
        "scan_id": str(scan_id),
        "catalogue": catalogue.model_dump(mode="json"),
        "plan": execution_plan.model_dump(mode="json"),
        "configuration": execution_config.model_dump(mode="json"),
        "configuration_binding": canonical_sha256(config.model_dump(mode="json")),
        "technologies": [t.name for t in surface.tech] if surface else [],
    }
    serialized = json.dumps(payload, separators=(",", ":"))
    expansion_id = run_id + "-expansion"
    # Docker/exec environment is bounded. Keep the durable full plan and report the gap;
    # never silently truncate tasks or remove them from the denominator.
    if len(serialized.encode()) > 100_000:
        expanded = WorkerResult(expansion_id, 1, "", "assessment input exceeds worker envelope", 0)
    else:
        expansion_spec = replace(
            spec,
            command=["python", "-m", "scopelens.expansion.worker"],
            environment={
                **spec.environment,
                "SCOPELENS_EXPANSION_INPUT": serialized,
                "SCOPELENS_EXPANSION_CAPABILITY": capability,
            },
            labels={**spec.labels, "scopelens.run_id": expansion_id},
        )
        try:
            expanded = supervisor.run(expansion_spec, run_id=expansion_id)
        except SupervisorError:
            expanded = WorkerResult(expansion_id, 1, "", "expansion worker unavailable", 0)
    runs = [(expanded, "expansion")]
    from scopelens.browser.expanded_active import BROWSER_CONTROLS

    browser_needed = bool(
        execution_config.browser_workflows or execution_config.cors_recipes
    ) or any(
        task.state == "ready" and task.control_id in BROWSER_CONTROLS
        for task in execution_plan.tasks
    )
    if browser_needed and len(serialized.encode()) <= 100_000:
        runs.append(
            (
                run_expanded_browser(
                    settings,
                    supervisor,
                    spec,
                    run_id=run_id,
                    scan_id=scan_id,
                    payload=serialized,
                    capability=capability,
                ),
                "expansion_browser",
            )
        )
    artifacts = [
        {**a, "source": source, "run_id": result.run_id}
        for result, source in runs
        for a in result.artifacts()
    ]
    for result, source in runs:
        if not result.succeeded:
            artifacts.append(
                {
                    "kind": "expansion_gap",
                    "source": source,
                    "run_id": result.run_id,
                    "data": {
                        "reason": (
                            "worker_deadline_exceeded"
                            if result.timed_out
                            else "worker_authority_revoked"
                            if result.killed
                            else result.stderr or "expansion incomplete"
                        ),
                        "plan_id": plan.id,
                    },
                }
            )
    old = previous.declared_result() or {}
    success = all(
        result.succeeded and (result.declared_result() or {}).get("ok") for result, _ in runs
    )
    summary = {
        **old,
        "ok": bool(old.get("ok") and success),
        "expansion_ok": bool(success),
        "body_bytes": int(old.get("body_bytes", 0))
        + sum(int((r.declared_result() or {}).get("body_bytes", 0)) for r, _ in runs),
    }
    return WorkerResult(
        run_id,
        0 if summary["ok"] else 1,
        previous.stdout
        + "\n"
        + "\n".join(ARTIFACT_MARKER + json.dumps(a) for a in artifacts)
        + "\n"
        + RESULT_MARKER
        + json.dumps(summary),
        previous.stderr + "\n" + "\n".join(r.stderr for r, _ in runs),
        previous.duration_seconds + sum(r.duration_seconds for r, _ in runs),
        previous.timed_out or any(r.timed_out for r, _ in runs),
        previous.killed or any(r.killed for r, _ in runs),
    )
