"""Evaluate frozen identity policies using only supervisor-admitted artifact streams.

Worker verdicts and their provisional evidence IDs are never confirmation inputs.
Bindings prevent one recipe, rule or execution attempt from supplying another's proof.
"""

from collections import defaultdict

from pydantic import ValidationError

from scopelens.browser.workflow_checks import evaluate_browser_workflow
from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import ControlOutcome as State
from scopelens.domain.enums import EvidenceStatus, Severity
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.workflow import WorkflowRecipe, WorkflowResult
from scopelens.identities.assessment import as_control_outcome as access_outcome
from scopelens.identities.cors import cors_configuration_binding, evaluate_cors_proof
from scopelens.identities.lifecycle import evaluate_session_proof
from scopelens.identities.probe import probe_binding_matches
from scopelens.identities.proof import CapturedIdentityResponse, evaluate_access_proof
from scopelens.identities.sessions import pointer, same_value
from scopelens.workflows.assessment import as_control_outcome as workflow_outcome
from scopelens.workflows.assessment import evaluate_mutation_proof, evaluate_read_proof


def admitted_artifacts(artifacts, trusted_refs):
    """The caller supplies refs created by intake for this scan, never by the worker."""
    counts = defaultdict(int)
    for a in artifacts:
        counts[a.get("evidence_ref")] += 1
    return [
        a
        for a in artifacts
        if (
            a.get("source") in {"expansion", "expansion_browser"}
            or (
                a.get("source") == "adaptive"
                and a.get("kind") in {"expanded_active_probe", "exposure_pack"}
            )
        )
        and a.get("evidence_ref") in trusted_refs
        and counts[a.get("evidence_ref")] == 1
        and a.get("run_id")
        and isinstance(a.get("data"), dict)
    ]


def _stream(artifacts, proof_type, proof_id):
    rows = [
        a
        for a in artifacts
        if a["data"].get("proof_type") == proof_type and a["data"].get("proof_id") == proof_id
    ]
    # Never stitch partial attempts into a complete proof.
    if len({a["run_id"] for a in rows}) != 1:
        return []
    return rows


def _responses(rows):
    result = []
    for a in rows:
        if a["kind"] != "identity_response":
            continue
        data = {k: v for k, v in a["data"].items() if k not in {"proof_id", "proof_type"}}
        data["evidence_ref"] = a["evidence_ref"]
        try:
            result.append(CapturedIdentityResponse.model_validate(data))
        except ValidationError:
            return ()
    return tuple(result)


def _merge(parts, entry):
    required = tuple(i for o in parts for i in o.required_instances)
    completed = tuple(i for o in parts for i in o.completed_instances)
    reasons = tuple(r for o in parts for r in o.incomplete_reasons)
    locations = tuple(loc for o in parts for loc in o.locations)
    confirmed = any(o.status is State.CONFIRMED_ISSUE for o in parts)
    complete = bool(parts) and all(o.is_fully_assessed for o in parts)
    refs = tuple(dict.fromkeys(r for o in parts if o.proof for r in o.proof.evidence_refs))
    return ControlOutcome(
        check_id=entry.id,
        canonical_control=entry.canonical_control,
        category=entry.category,
        status=State.CONFIRMED_ISSUE
        if confirmed
        else State.PASS
        if complete
        else State.INCONCLUSIVE,
        summary=f"{len(completed)}/{len(required)} declared instances assessed",
        proposed_severity=Severity.HIGH if confirmed else None,
        locations=locations,
        required_instances=required,
        completed_instances=completed,
        incomplete_reasons=reasons,
        proof=ProofResult(
            satisfied=confirmed or complete,
            status=EvidenceStatus.CONFIRMED if confirmed else EvidenceStatus.INCONCLUSIVE,
            evidence_refs=refs,
            reasons=tuple(dict.fromkeys(o.summary for o in parts)),
        ),
    )


def _session_outcomes(config, artifacts, registry):
    entry = registry.get("SL-C08-SESSION-01")
    if entry is None:
        return []
    results = []
    profiles = {p.id: p for p in config.identities}
    for policy in config.session_policies:
        profile = profiles[policy.identity_id]
        rows = _stream(artifacts, "session", policy.identity_id)
        checks = []
        if policy.login_rotates:
            checks.append("rotation")
        if policy.old_session_revoked_on_login:
            checks.append("old_session")
        if policy.logout and policy.logout_revokes:
            checks.append("logout")
        if policy.expiry_after_seconds is not None:
            checks.append("expiry")
        for check in checks:
            matches = [
                a
                for a in rows
                if a["kind"] == "identity_observation"
                and a["data"].get("kind") == "session_policy"
                and a["data"].get("check") == check
            ]
            state, reason = "inconclusive", "unique trusted lifecycle capture missing"
            refs = ()
            if len(matches) == 1:
                state, reason = evaluate_session_proof(policy, profile, matches[0]["data"])
                refs = (matches[0]["evidence_ref"],)
            instance = f"session:{policy.identity_id}:{check}"
            complete = state in {"pass", "confirmed"}
            results.append(
                ControlOutcome(
                    check_id=entry.id,
                    canonical_control=entry.canonical_control,
                    category=entry.category,
                    status=State.CONFIRMED_ISSUE
                    if state == "confirmed"
                    else State.PASS
                    if complete
                    else State.INCONCLUSIVE,
                    summary=reason,
                    proposed_severity=Severity.HIGH if state == "confirmed" else None,
                    locations=(Location(route=profile.probe.request.url, detail=instance),)
                    if state == "confirmed"
                    else (),
                    required_instances=(instance,),
                    completed_instances=(instance,) if complete else (),
                    incomplete_reasons=() if complete else (f"{instance}: {reason}",),
                    proof=ProofResult(
                        satisfied=complete,
                        status=EvidenceStatus.CONFIRMED
                        if state == "confirmed"
                        else EvidenceStatus.INCONCLUSIVE,
                        evidence_refs=refs,
                        reasons=(reason,),
                    ),
                )
            )
    return results


def _workflow_sessions_valid(recipe, rows, profiles):
    # Check the actual session probes independently. Cleanup failures must not erase a
    # finding already established before cleanup began.
    core = rows
    if isinstance(recipe, WorkflowRecipe):
        ends = [
            i
            for i, a in enumerate(rows)
            if a["kind"] == "identity_observation" and a["data"].get("kind") == "readback"
        ]
        core = rows[: ends[-1] + 1] if ends else []
    records = _responses(core)
    counts = defaultdict(int)
    for record in records:
        profile = profiles.get(record.identity_id)
        if not profile or not profile.probe:
            continue
        probe = profile.probe
        if record.url == probe.request.url and record.method == probe.request.method:
            if (
                record.status != 200
                or not probe_binding_matches(probe, record.probe_binding)
                or not same_value(
                    pointer(record.document, probe.identity_pointer), probe.expected_identity
                )
            ):
                return False
            counts[profile.id] += 1
    needed = (
        {recipe.owner_identity: 3, recipe.actor_identity: 1}
        if isinstance(recipe, WorkflowRecipe)
        else {recipe.owner_identity: 1, recipe.actor_identity: 5}
    )
    return all(
        profiles[ident].anonymous or counts[ident] >= count for ident, count in needed.items()
    )


def _cleanup_proved(recipe, observations, ledger):
    rows = [
        r
        for r in observations
        if r.get("kind") == "cleanup_readback"
        and r.get("identity_id") == recipe.owner_identity
        and r.get("url") == recipe.readback.url
        and r.get("method") == "GET"
    ]
    return (
        ledger.get(recipe.id) == "clean"
        and len(rows) == 1
        and rows[0].get("status") == 200
        and all(
            a.pointer in rows[0].get("declared_values", {})
            and same_value(rows[0]["declared_values"][a.pointer], a.value)
            for a in (recipe.seed, recipe.before)
        )
    )


def identity_workflow_outcomes(artifacts, frozen, registry, *, cleanup_states=None):
    if not frozen.get("expansion_config"):
        return {}
    config = AssessmentConfiguration.model_validate(frozen["expansion_config"])
    groups = defaultdict(list)
    if config.permission_matrix:
        for rule in config.permission_matrix.rules:
            rows = _stream(artifacts, "access", rule.id)
            result = evaluate_access_proof(
                config.permission_matrix, config.identities, rule.id, _responses(rows)
            )
            outcome = access_outcome(result, config.permission_matrix)
            groups[outcome.check_id].append(outcome)
    for outcome in _session_outcomes(config, artifacts, registry):
        groups[outcome.check_id].append(outcome)
    profiles = {p.id: p for p in config.identities}
    cors_entry = registry.get("SL-C04-CORSDATA-01")
    if cors_entry:
        binding = cors_configuration_binding(config)
        for recipe in config.cors_recipes:
            rows = [
                a
                for a in _stream(artifacts, "credentialed_cors", recipe.id)
                if a.get("source") == "expansion_browser"
                and a.get("kind") == "identity_observation"
                and a["data"].get("kind") == "credentialed_cors_proof"
            ]
            state, reason = "inconclusive", "unique trusted credentialed CORS proof missing"
            if len(rows) == 1:
                state, reason = evaluate_cors_proof(
                    recipe, config.identities, rows[0]["data"], configuration_binding=binding
                )
            confirmed = state == "confirmed"
            groups[cors_entry.id].append(
                ControlOutcome(
                    check_id=cors_entry.id,
                    canonical_control=cors_entry.canonical_control,
                    category=cors_entry.category,
                    status=State.CONFIRMED_ISSUE if confirmed else State.INCONCLUSIVE,
                    summary=reason,
                    proposed_severity=Severity.HIGH if confirmed else None,
                    locations=(Location(route=recipe.target.request.url, detail=recipe.id),)
                    if confirmed
                    else (),
                    required_instances=(recipe.id,),
                    completed_instances=(recipe.id,) if confirmed else (),
                    incomplete_reasons=() if confirmed else (f"{recipe.id}: {reason}",),
                    proof=ProofResult(
                        satisfied=confirmed,
                        status=EvidenceStatus.CONFIRMED
                        if confirmed
                        else EvidenceStatus.INCONCLUSIVE,
                        evidence_refs=tuple(a["evidence_ref"] for a in rows),
                        reasons=(reason,),
                    ),
                )
            )
    for recipe in (*config.read_probes, *config.workflows):
        rows = _stream(artifacts, "workflow", recipe.id)
        captures = [a for a in rows if a["kind"] == "identity_observation"]
        observations = tuple(
            {k: v for k, v in a["data"].items() if k not in {"proof_id", "proof_type"}}
            for a in captures
        )
        mutation = isinstance(recipe, WorkflowRecipe)
        evaluate = evaluate_mutation_proof if mutation else evaluate_read_proof
        state, reason = evaluate(recipe, observations)
        if not _workflow_sessions_valid(recipe, rows, profiles):
            state, reason = "inconclusive", "verified workflow session sequence missing"
        cleanup = "not_needed"
        if mutation:
            cleanup = (
                "clean"
                if _cleanup_proved(recipe, observations, cleanup_states or {})
                else "pending"
            )
        result = WorkflowResult(
            recipe_id=recipe.id,
            family=recipe.family,
            state=state,
            reason=reason,
            cleanup_state=cleanup,
            observations=observations,
            evidence_refs=tuple(
                a["evidence_ref"]
                for a in rows
                if a["kind"] in {"identity_response", "identity_observation"}
            ),
        )
        outcome = workflow_outcome(result, recipe)
        groups[outcome.check_id].append(outcome)
    for recipe in config.browser_workflows:
        outcome = _browser_outcome(recipe, artifacts, profiles, registry, cleanup_states or {})
        if outcome:
            groups[outcome.check_id].append(outcome)
    return {
        ident: _merge(parts, entry)
        for ident, parts in groups.items()
        if (entry := registry.get(ident)) is not None
    }


BROWSER_WORKFLOW_CONTROLS = {
    "stored_xss": "SL-C03-STOREDXSS-01",
    "csrf": "SL-C04-CSRF-01",
    "upload_serving": "SL-C10-UPLOAD-01",
}


def _browser_outcome(recipe, artifacts, profiles, registry, cleanup_states):
    entry = registry.get(BROWSER_WORKFLOW_CONTROLS[recipe.family])
    if entry is None:
        return None
    rows = _stream(artifacts, "browser_workflow", recipe.id)
    rows = [a for a in rows if a.get("source") == "expansion_browser"]
    observations = tuple(
        a["data"]
        for a in rows
        if a["kind"] == "identity_observation"
        and a["data"].get("recipe_id") == recipe.id
        and a["data"].get("family") == recipe.family
    )
    state, reason = evaluate_browser_workflow(recipe, observations)
    # Only probes collected before the final proof qualify the test identities.
    # Cleanup can fail after a valid finding without erasing that finding.
    ends = [
        i
        for i, a in enumerate(rows)
        if a["kind"] == "identity_observation" and a["data"].get("kind") == "browser_proof"
    ]
    verified = set()
    for response in _responses(rows[: ends[-1] + 1] if ends else []):
        profile = profiles.get(response.identity_id)
        if profile and profile.probe:
            probe = profile.probe
            if response.url == probe.request.url and response.method == probe.request.method:
                if (
                    response.status != 200
                    or not probe_binding_matches(probe, response.probe_binding)
                    or not same_value(
                        pointer(response.document, probe.identity_pointer), probe.expected_identity
                    )
                ):
                    state, reason = "inconclusive", "browser identity probe failed"
                else:
                    verified.add(profile.id)
    required_identities = {recipe.actor_identity, recipe.viewer_identity}
    if any(
        not profiles[ident].anonymous and ident not in verified for ident in required_identities
    ):
        state, reason = "inconclusive", "trusted browser identity probes missing"
    restored = [o for o in observations if o.get("kind") == "cleanup_readback"]
    clean = (
        cleanup_states.get(recipe.id) == "clean"
        and len(restored) == 1
        and restored[0].get("seed_matches") is True
        and restored[0].get("before_matches") is True
    )
    complete = state in {"confirmed", "pass"} and clean
    confirmed = state == "confirmed"
    return ControlOutcome(
        check_id=entry.id,
        canonical_control=entry.canonical_control,
        category=entry.category,
        status=State.CONFIRMED_ISSUE
        if confirmed
        else State.PASS
        if complete
        else State.INCONCLUSIVE,
        summary=reason,
        proposed_severity=Severity.HIGH if confirmed else None,
        locations=(Location(route=recipe.mutation.url, detail=recipe.id),) if confirmed else (),
        required_instances=(recipe.id,),
        completed_instances=(recipe.id,) if complete else (),
        incomplete_reasons=()
        if complete
        else (reason + ("; cleanup not verified" if not clean else ""),),
        proof=ProofResult(
            satisfied=state in {"confirmed", "pass"},
            status=EvidenceStatus.CONFIRMED if confirmed else EvidenceStatus.INCONCLUSIVE,
            evidence_refs=tuple(
                a["evidence_ref"]
                for a in rows
                if a["kind"] in {"identity_response", "identity_observation"}
            ),
            reasons=(reason,),
        ),
    )
