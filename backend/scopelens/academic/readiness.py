"""Project frozen policy and trusted proof with no target traffic or secret resolution."""

from datetime import UTC, datetime
from uuid import UUID

from scopelens.academic.models import (
    AcademicReadiness,
    ActorView,
    CapabilityCounts,
    CaseView,
    CoverageView,
    FeatureView,
)
from scopelens.domain.assessment import stable_id
from scopelens.domain.capabilities import canonical_sha256
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.registry import CheckRegistry
from scopelens.domain.report_metadata import Capabilities, ReachCounts, ReachSummary
from scopelens.expansion.control import credential_references
from scopelens.expansion.proof_aggregation import (
    _cleanup_proved,
    _responses,
    _stream,
    identity_workflow_outcomes,
)
from scopelens.identities.lifecycle import evaluate_session_proof
from scopelens.identities.probe import probe_binding_matches
from scopelens.identities.proof import evaluate_access_proof
from scopelens.identities.readiness import evaluate_identity_readiness
from scopelens.identities.sessions import pointer, same_value


def validate_configuration(raw, digest, scope_version_id):
    """Verify the stored content before deriving any public readiness claim."""
    if canonical_sha256(raw) != digest:
        raise ValueError("configuration digest mismatch")
    config = AssessmentConfiguration.model_validate(raw)
    if config.scope_version_id != UUID(str(scope_version_id)):
        raise ValueError("configuration scope mismatch")
    return config


def opaque(config_hash, kind, ident):
    return stable_id(["academic-readiness-v1", config_hash, kind, ident])


def project_readiness(
    *,
    configuration_id,
    configuration_hash,
    config,
    profile,
    scan_id=None,
    frozen=None,
    artifacts=(),
    cleanup_rows=(),
    cleanup_states=None,
    report=None,
    now=None,
):
    """Artifacts must be loaded through the trusted loader, never worker/API inputs."""
    now = now or datetime.now(UTC)
    frozen = frozen or {}
    if scan_id is not None and (
        frozen.get("configuration_id") != str(configuration_id)
        or frozen.get("configuration_hash") != configuration_hash
        or frozen.get("expansion_config") != config.model_dump(mode="json")
    ):
        raise ValueError("scan configuration binding mismatch")
    profiles = {p.id: p for p in config.identities}
    claims = frozen.get("assessment_execution_claims", {})
    if not isinstance(claims, dict):
        raise ValueError("invalid execution claims")
    registry = CheckRegistry.model_validate(frozen["registry"]) if frozen.get("registry") else None
    actors = []
    actor_ids = {ident: opaque(configuration_hash, "actor", ident) for ident in profiles}
    for ident, p in sorted(profiles.items()):
        state = "not_observed"
        if p.probe:
            records = [
                r
                for r in _responses(artifacts)
                if r.identity_id == ident
                and r.url == p.probe.request.url
                and r.method == p.probe.request.method
            ]
            if records:
                state = (
                    "verified_probe"
                    if all(
                        r.status == 200
                        and probe_binding_matches(p.probe, r.probe_binding)
                        and same_value(
                            pointer(r.document, p.probe.identity_pointer), p.probe.expected_identity
                        )
                        for r in records
                    )
                    else "failed_probe"
                )
            else:
                readiness = [
                    a["data"]
                    for a in artifacts
                    if a.get("kind") == "identity_observation"
                    and a.get("source") == "expansion"
                    and a.get("evidence_ref")
                    and isinstance(a.get("data"), dict)
                    and a["data"].get("kind") == "identity_readiness"
                    and a["data"].get("identity_id") == ident
                    and a["data"].get("configuration_binding") == configuration_hash
                ]
                if readiness:
                    state = (
                        "verified_probe"
                        if all(
                            evaluate_identity_readiness(
                                p, record, configuration_binding=configuration_hash, now=now
                            )
                            for record in readiness
                        )
                        else "failed_probe"
                    )
        actors.append(
            ActorView(
                id=actor_ids[ident],
                anonymous=p.anonymous,
                probe_configured=bool(p.probe),
                login_configured=bool(p.login),
                credential_reference_count=len(credential_references(p.model_dump(mode="json"))),
                expired=bool(p.expires_at and p.expires_at <= now),
                identity_evidence=state,
            )
        )
    actor_views = {ident: next(a for a in actors if a.id == actor_ids[ident]) for ident in profiles}
    cases = []
    clean = (
        cleanup_states
        if cleanup_states is not None
        else {r["recipe_id"]: r["state"] for r in cleanup_rows if r["scan_id"] == str(scan_id)}
    )
    fenced_resources = {r["resource_id"] for r in cleanup_rows if r["state"] != "clean"}

    def reasons(ids, control):
        blocked = []
        if profile not in {"authenticated-api-v1", "staging-stateful-v1"}:
            blocked.append("authenticated_profile_required")
        for ident in sorted(set(ids)):
            p = profiles[ident]
            if actor_views[ident].expired:
                blocked.append("declared_identity_expired")
            if not p.anonymous and not (p.login or p.supplied_headers):
                blocked.append("credential_setup_required")
        if registry is not None and registry.get(control) is None:
            blocked.append("control_absent_from_frozen_registry")
        return blocked

    def admitted(key):
        claim = claims.get(key)
        # State strings are admission bookkeeping, never an observed execution claim.
        return isinstance(claim, dict) and claim.get("state") in {"admitted", "outcome_unknown"}

    def unexecuted(executed, blocked, is_admitted):
        if executed:
            return None
        if blocked:
            return "configuration_prerequisites_blocked"
        if scan_id is None:
            return "configuration_only_no_scan"
        return "admission_without_bound_capture" if is_admitted else "case_not_admitted"

    if config.permission_matrix:
        matrix = config.permission_matrix
        permission_admitted = admitted(
            "permission_matrix:" + stable_id(matrix.model_dump(mode="json"))
        )
        objects = {o.id: o for o in matrix.objects}
        for rule in sorted(matrix.rules, key=lambda r: r.id):
            obj = objects[rule.object_id]
            control = f"SL-C09-{rule.family.upper()}-01"
            blocked = reasons([rule.identity_id, obj.owner_identity], control)
            if rule.family == "tenant" and (
                not profiles[rule.identity_id].tenant
                or not profiles[obj.owner_identity].tenant
                or profiles[rule.identity_id].tenant == profiles[obj.owner_identity].tenant
            ):
                blocked.append("distinct_declared_tenants_required")
            rows = _stream(artifacts, "access", rule.id)
            captures = [
                a
                for a in artifacts
                if a["data"].get("proof_type") == "access" and a["data"].get("proof_id") == rule.id
            ]
            records = _responses(rows)
            observed = any(
                r.identity_id == rule.identity_id
                and r.url == obj.request.url
                and r.method == obj.request.method
                for r in _responses(captures)
            )
            result = evaluate_access_proof(matrix, config.identities, rule.id, records)
            proof = (
                ("confirmed_issue" if result.state == "confirmed" else result.state)
                if captures
                else "not_evaluated"
            )
            cases.append(
                CaseView(
                    id=opaque(configuration_hash, "permission", rule.id),
                    kind="permission",
                    family=rule.family,
                    actor_id=actor_ids[rule.identity_id],
                    owner_id=actor_ids[obj.owner_identity],
                    resource_id=opaque(configuration_hash, "object", obj.id),
                    expected_permission="allowed" if rule.allowed else "forbidden",
                    control_id=control,
                    configuration_ready=not blocked,
                    blocked_reasons=tuple(sorted(set(blocked))),
                    admitted=permission_admitted,
                    execution="observed" if observed else "not_observed",
                    proof=proof,
                    baseline="verified" if result.authorized_baseline else "not_observed",
                    evidence_refs=result.evidence_refs,
                    unexecuted_reason=unexecuted(observed, blocked, permission_admitted),
                )
            )
    for recipe in sorted(config.workflows, key=lambda r: r.id):
        control = "SL-C09-MASS-01" if recipe.family == "mass_assignment" else "SL-C11-WORKFLOW-01"
        blocked = reasons(
            [recipe.actor_identity, recipe.owner_identity, recipe.cleanup_identity], control
        )
        if profile != "staging-stateful-v1":
            blocked.append("stateful_profile_required")
        if recipe.resource_id in fenced_resources:
            blocked.append("resource_cleanup_fenced")
        rows = _stream(artifacts, "workflow", recipe.id)
        observations = tuple(a["data"] for a in rows if a["kind"] == "identity_observation")
        captures = [
            a
            for a in artifacts
            if a["data"].get("proof_type") == "workflow" and a["data"].get("proof_id") == recipe.id
        ]
        observed = any(
            a["kind"] == "identity_observation"
            and a["data"].get("kind") == "mutation"
            and isinstance(a["data"].get("status"), int)
            and a["data"].get("identity_id") == recipe.actor_identity
            and a["data"].get("method") == recipe.mutation.method
            and a["data"].get("url") == recipe.mutation.url
            for a in captures
        )
        restored = _cleanup_proved(recipe, observations, clean)
        is_admitted = admitted("workflows:" + stable_id(recipe.model_dump(mode="json")))
        proof = "not_evaluated"
        refs = ()
        if rows and registry is not None:
            singleton = config.model_copy(
                update={
                    "permission_matrix": None,
                    "workflows": (recipe,),
                    "session_policies": (),
                    "read_probes": (),
                    "browser_workflows": (),
                    "cors_recipes": (),
                }
            )
            outcome = identity_workflow_outcomes(
                rows,
                {"expansion_config": singleton.model_dump(mode="json")},
                registry,
                cleanup_states=clean,
            ).get(control)
            if outcome:
                proof = outcome.status.value
                refs = outcome.proof.evidence_refs if outcome.proof else ()
        elif captures:
            proof = "inconclusive"
        proven = proof in {"pass", "confirmed_issue"}
        cases.append(
            CaseView(
                id=opaque(configuration_hash, "workflow", recipe.id),
                kind="workflow",
                family=recipe.family,
                actor_id=actor_ids[recipe.actor_identity],
                owner_id=actor_ids[recipe.owner_identity],
                resource_id=opaque(configuration_hash, "resource", recipe.resource_id),
                expected_permission="forbidden",
                control_id=control,
                configuration_ready=not blocked,
                blocked_reasons=tuple(sorted(set(blocked))),
                admitted=is_admitted,
                execution="observed" if observed else "not_observed",
                proof=proof,
                baseline="verified" if proven else "not_observed",
                independent_readback="proven" if proven else "not_proven",
                restoration="verified"
                if restored
                else "fenced"
                if recipe.resource_id in fenced_resources
                else "not_proven",
                resource_fenced=recipe.resource_id in fenced_resources,
                evidence_refs=refs,
                unexecuted_reason=unexecuted(observed, blocked, is_admitted),
            )
        )
    for policy in sorted(config.session_policies, key=lambda p: p.identity_id):
        checks = (["rotation"] if policy.login_rotates else []) + (
            ["old_session"] if policy.old_session_revoked_on_login else []
        )
        if policy.logout and policy.logout_revokes:
            checks.append("logout")
        if policy.expiry_after_seconds is not None:
            checks.append("expiry")
        is_admitted = admitted("session_policies:" + stable_id(policy.model_dump(mode="json")))
        for check in checks:
            blocked = reasons([policy.identity_id], "SL-C08-SESSION-01")
            if profiles[policy.identity_id].login is None:
                blocked.append("login_recipe_required")
            rows = _stream(artifacts, "session", policy.identity_id)
            matches = [
                a
                for a in rows
                if a["kind"] == "identity_observation"
                and a["data"].get("kind") == "session_policy"
                and a["data"].get("check") == check
            ]
            proof = "not_evaluated"
            refs = ()
            observed = any(
                a["kind"] == "identity_observation"
                and a["data"].get("proof_type") == "session"
                and a["data"].get("proof_id") == policy.identity_id
                and a["data"].get("kind") == "session_policy"
                and a["data"].get("check") == check
                and isinstance(a["data"].get("initial_probe_status"), int)
                for a in artifacts
            )
            if observed:
                proof = "inconclusive"
            if len(matches) == 1:
                state, _ = evaluate_session_proof(
                    policy, profiles[policy.identity_id], matches[0]["data"]
                )
                proof = "confirmed_issue" if state == "confirmed" else state
                refs = (matches[0]["evidence_ref"],)
            cases.append(
                CaseView(
                    id=opaque(configuration_hash, "session", [policy.identity_id, check]),
                    kind="session",
                    family=check,
                    actor_id=actor_ids[policy.identity_id],
                    expected_permission="declared_session_policy",
                    control_id="SL-C08-SESSION-01",
                    configuration_ready=not blocked,
                    blocked_reasons=tuple(sorted(set(blocked))),
                    admitted=is_admitted,
                    execution="observed" if observed else "not_observed",
                    proof=proof,
                    evidence_refs=refs,
                    baseline="verified" if proof in {"pass", "confirmed_issue"} else "not_observed",
                    unexecuted_reason=unexecuted(observed, blocked, is_admitted),
                )
            )
    cases.sort(key=lambda c: c.id)
    capabilities, reach = None, None
    if report is not None:
        source = Capabilities.model_validate(report["capabilities"])
        capabilities = CapabilityCounts(
            **{k: getattr(source, k).count for k in CapabilityCounts.model_fields}
        )
        source_reach = ReachSummary.model_validate(report["reach"])
        reach = ReachCounts(**{k: getattr(source_reach, k) for k in ReachCounts.model_fields})
    features = (
        FeatureView(
            code="identity_setup",
            configured_cases=len(actors),
            reason_codes=() if actors else ("dedicated_test_identities_required",),
        ),
        FeatureView(
            code="permission_matrix",
            configured_cases=sum(c.kind == "permission" for c in cases),
            reason_codes=()
            if config.permission_matrix and config.permission_matrix.rules
            else ("explicit_permission_matrix_required",),
        ),
        FeatureView(
            code="protected_workflows",
            configured_cases=len(config.workflows),
            reason_codes=() if config.workflows else ("explicit_disposable_workflow_required",),
        ),
        FeatureView(
            code="protected_field_assignment",
            configured_cases=sum(r.family == "mass_assignment" for r in config.workflows),
            reason_codes=("ordinary_field_allowed_control_not_established",),
        ),
        FeatureView(
            code="allowed_permission_controls",
            configured_cases=sum(c.expected_permission == "allowed" for c in cases),
            reason_codes=()
            if any(c.expected_permission == "allowed" for c in cases)
            else ("explicit_allowed_permission_control_required",),
        ),
        FeatureView(
            code="single_action_workflow_transitions",
            configured_cases=sum(r.family == "workflow_authorization" for r in config.workflows),
            reason_codes=()
            if any(r.family == "workflow_authorization" for r in config.workflows)
            else ("explicit_single_action_workflow_required",),
        ),
        FeatureView(
            code="approval_sequence",
            configured_cases=0,
            reason_codes=("explicit_multistep_transition_contract_not_supported",),
        ),
        FeatureView(
            code="session_lifecycle",
            configured_cases=sum(c.kind == "session" for c in cases),
            reason_codes=(
                *(
                    ("expiry_transition_not_configured",)
                    if not any(p.expiry_after_seconds is not None for p in config.session_policies)
                    else ()
                ),
                "role_change_transition_not_established",
            ),
        ),
    )
    result = AcademicReadiness(
        revision="",
        configuration_id=configuration_id,
        configuration_hash=configuration_hash,
        scope_version_id=config.scope_version_id,
        scan_id=scan_id,
        profile=profile,
        actors=tuple(actors),
        cases=tuple(cases),
        features=features,
        capabilities=capabilities,
        reach=reach,
        coverage=CoverageView(
            configured=len(cases),
            ready=sum(c.configuration_ready for c in cases),
            blocked=sum(not c.configuration_ready for c in cases),
            admitted=sum(c.admitted for c in cases),
            executed=sum(c.execution == "observed" for c in cases),
            proven=sum(c.proof in {"pass", "confirmed_issue"} for c in cases),
            fully_assessed=sum(
                c.proof in {"pass", "confirmed_issue"}
                and c.restoration in {"not_applicable", "verified"}
                for c in cases
            ),
            confirmed_issues=sum(c.proof == "confirmed_issue" for c in cases),
        ),
    )
    return result.model_copy(
        update={"revision": canonical_sha256(result.model_dump(mode="json", exclude={"revision"}))}
    )
