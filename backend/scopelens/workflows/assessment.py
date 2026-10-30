"""Bounded workflow collectors and independent state proof rules."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from contextlib import suppress

import httpx

from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as OutcomeStatus
from scopelens.domain.workflow import (
    ReadProbeRecipe,
    StateAssertion,
    WorkflowRecipe,
    WorkflowResult,
)
from scopelens.identities.assessment import Capture
from scopelens.identities.sessions import (
    IdentitySessions,
    SessionUnavailable,
    response_value,
    same_value,
)
from scopelens.workflows.cleanup import CleanupJournal


def assertion_value(response: httpx.Response, path: str):
    return response.text if path == "/$body" else response_value(response, path)


def matches(response: httpx.Response, assertion: StateAssertion) -> bool:
    return response.status_code == 200 and same_value(
        assertion_value(response, assertion.pointer), assertion.value
    )


def observation(kind, identity, request, response, assertions):
    # Only exact declared synthetic values are retained. Other values, including secrets,
    # are absent. The trusted capture gives the observation its durable provenance.
    values = {
        a.pointer: a.value
        for a in assertions
        if same_value(assertion_value(response, a.pointer), a.value)
    }
    return {
        "kind": kind,
        "identity_id": identity,
        "method": request.method,
        "url": request.url,
        "status": response.status_code,
        "declared_values": values,
        "body_sha256": hashlib.sha256(response.content).hexdigest(),
    }


def evaluate_mutation_proof(
    recipe: WorkflowRecipe, observations: tuple[dict, ...]
) -> tuple[str, str]:
    def value(record, assertion):
        return (
            record.get("status") == 200
            and assertion.pointer in record.get("declared_values", {})
            and same_value(record["declared_values"][assertion.pointer], assertion.value)
        )

    baseline = [
        r
        for r in observations
        if r.get("kind") == "baseline"
        and r.get("identity_id") == recipe.owner_identity
        and r.get("url") == recipe.readback.url
        and r.get("method") == "GET"
    ]
    readbacks = [
        r
        for r in observations
        if r.get("kind") == "readback"
        and r.get("identity_id") == recipe.owner_identity
        and r.get("url") == recipe.readback.url
        and r.get("method") == "GET"
    ]
    mutations = [
        r
        for r in observations
        if r.get("kind") == "mutation"
        and r.get("identity_id") == recipe.actor_identity
        and r.get("url") == recipe.mutation.url
        and r.get("method") == recipe.mutation.method
    ]
    order = [
        r.get("kind") for r in observations if r.get("kind") in {"baseline", "mutation", "readback"}
    ]
    if (
        order != ["baseline", "mutation", "readback", "readback"]
        or len(baseline) != 1
        or len(readbacks) != 2
        or len(mutations) != 1
        or not value(baseline[0], recipe.seed)
        or not value(baseline[0], recipe.before)
    ):
        return (
            "inconclusive",
            "trusted baseline, admitted mutation or read-back sequence incomplete",
        )
    if not all(value(r, recipe.seed) for r in readbacks):
        return "inconclusive", "read-back did not identify the same disposable record"
    if all(value(r, recipe.forbidden_after) for r in readbacks):
        return "confirmed", "forbidden protected state reproduced by two independent owner reads"
    if all(value(r, recipe.before) for r in readbacks):
        return "pass", "declared synchronous mutation did not change the protected state"
    return "inconclusive", "read-back state was inconsistent or outside the declared proof"


def run_workflow(
    recipe: WorkflowRecipe,
    sessions: IdentitySessions,
    cleanup_sessions: IdentitySessions,
    journal: CleanupJournal,
    capture: Capture,
    *,
    admit: Callable[[WorkflowRecipe], bool],
) -> WorkflowResult:
    observations, refs = [], []
    state, reason = "blocked", "workflow not admitted"
    claimed = False
    cleanup_state = "not_needed"

    def collect(kind, identity, request, response):
        item = observation(
            kind, identity, request, response, (recipe.seed, recipe.before, recipe.forbidden_after)
        )
        ref = capture(item)
        if not ref:
            raise SessionUnavailable("trusted workflow evidence unavailable")
        observations.append(item)
        refs.append(ref)

    try:
        if not admit(recipe):
            raise SessionUnavailable("explicit disposable-workflow grant missing")
        if not sessions.verify(recipe.owner_identity) or not sessions.verify(recipe.actor_identity):
            raise SessionUnavailable("workflow identities could not be verified")
        baseline = sessions.request(recipe.owner_identity, recipe.readback)
        collect("baseline", recipe.owner_identity, recipe.readback, baseline)
        if not matches(baseline, recipe.seed) or not matches(baseline, recipe.before):
            raise SessionUnavailable("disposable seeded baseline unavailable")
        if sessions.cancelled():
            raise SessionUnavailable("workflow cancelled before mutation")
        if not journal.claim(recipe.id, recipe.resource_id):
            raise SessionUnavailable(
                "prior mutation needs cleanup recovery; new mutation suppressed"
            )
        claimed, cleanup_state = True, "pending"
        # Persist before sending: a crash/timeout during request still leaves cleanup pending.
        journal.mark(recipe.id, recipe.resource_id, "mutation_sent")
        mutation = sessions.request(recipe.actor_identity, recipe.mutation)
        collect("mutation", recipe.actor_identity, recipe.mutation, mutation)
        for _ in range(2):
            if not sessions.verify(recipe.owner_identity, allow_login=False):
                raise SessionUnavailable("owner session expired before read-back")
            response = sessions.request(recipe.owner_identity, recipe.readback)
            collect("readback", recipe.owner_identity, recipe.readback, response)
        state, reason = evaluate_mutation_proof(recipe, tuple(observations))
    except SessionUnavailable as exc:
        state, reason = "blocked", str(exc)
    except (httpx.HTTPError, PermissionError, ValueError, RuntimeError, OSError):
        state, reason = "error", "workflow request, credential or evidence operation failed"
    finally:
        if claimed:
            try:
                if not cleanup_sessions.verify(
                    recipe.cleanup_identity
                ) or not cleanup_sessions.verify(recipe.owner_identity):
                    raise SessionUnavailable("cleanup identity unavailable")
                reset = cleanup_sessions.request(recipe.cleanup_identity, recipe.cleanup)
                collect("cleanup", recipe.cleanup_identity, recipe.cleanup, reset)
                reset_view = cleanup_sessions.request(recipe.owner_identity, recipe.readback)
                collect("cleanup_readback", recipe.owner_identity, recipe.readback, reset_view)
                if not matches(reset_view, recipe.seed) or not matches(reset_view, recipe.before):
                    raise SessionUnavailable("cleanup read-back did not restore seeded baseline")
                journal.mark(recipe.id, recipe.resource_id, "clean")
                cleanup_state = "clean"
            except (RuntimeError, httpx.HTTPError, PermissionError, ValueError, OSError):
                cleanup_state = "cleanup_failed"
                # Revoked cleanup RPC leaves a durable pending/mutation_sent intent.
                with suppress(RuntimeError, httpx.HTTPError, PermissionError, ValueError, OSError):
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


def run_read_probe(
    recipe: ReadProbeRecipe,
    sessions: IdentitySessions,
    capture: Capture,
    *,
    admit: Callable[[ReadProbeRecipe], bool],
) -> WorkflowResult:
    refs, observations = [], []
    state, reason = "blocked", "read probe not admitted"
    try:
        if not admit(recipe):
            raise SessionUnavailable("explicit read-probe grant missing")
        if not sessions.verify(recipe.owner_identity) or not sessions.verify(recipe.actor_identity):
            raise SessionUnavailable("read-probe identities unavailable")
        # Cache pack ordering intentionally primes owner view before the other identity.
        baseline = sessions.request(recipe.owner_identity, recipe.baseline)
        item = observation(
            "baseline", recipe.owner_identity, recipe.baseline, baseline, (recipe.marker,)
        )
        refs.append(capture(item))
        observations.append(item)
        if recipe.family != "template_injection" and not matches(baseline, recipe.marker):
            raise SessionUnavailable("designated synthetic record/canary baseline unavailable")
        if recipe.family == "template_injection" and matches(baseline, recipe.marker):
            raise SessionUnavailable("template result already present in literal baseline")
        for _ in range(2):
            if not sessions.verify(recipe.actor_identity, allow_login=False):
                raise SessionUnavailable("read-probe identity expired")
            for kind, request in (("negative", recipe.negative_control), ("probe", recipe.probe)):
                response = sessions.request(recipe.actor_identity, request)
                assertions = (recipe.marker,) + ((recipe.denied,) if recipe.denied else ())
                item = observation(kind, recipe.actor_identity, request, response, assertions)
                refs.append(capture(item))
                observations.append(item)
            if not sessions.verify(recipe.actor_identity, allow_login=False):
                raise SessionUnavailable("read-probe session expired during comparison")
        if not all(refs):
            raise SessionUnavailable("trusted read-probe evidence unavailable")
        state, reason = evaluate_read_proof(recipe, tuple(observations))
    except SessionUnavailable as exc:
        state, reason = "blocked", str(exc)
    except (httpx.HTTPError, PermissionError, ValueError, RuntimeError, OSError):
        state, reason = "error", "read-probe request, credential or evidence operation failed"
    return WorkflowResult(
        recipe_id=recipe.id,
        family=recipe.family,
        state=state,
        reason=reason,
        evidence_refs=tuple(refs),
        observations=tuple(observations),
    )


def evaluate_read_proof(recipe: ReadProbeRecipe, observations: tuple[dict, ...]) -> tuple[str, str]:
    def match(record, assertion):
        return assertion.pointer in record.get("declared_values", {}) and same_value(
            record["declared_values"][assertion.pointer], assertion.value
        )

    def rows(kind, request, identity):
        return [
            r
            for r in observations
            if r.get("kind") == kind
            and r.get("url") == request.url
            and r.get("method") == request.method
            and r.get("identity_id") == identity
        ]

    baseline = rows("baseline", recipe.baseline, recipe.owner_identity)
    probes = rows("probe", recipe.probe, recipe.actor_identity)
    negatives = rows("negative", recipe.negative_control, recipe.actor_identity)
    if (
        [r.get("kind") for r in observations]
        != ["baseline", "negative", "probe", "negative", "probe"]
        or len(baseline) != 1
        or len(probes) != 2
        or len(negatives) != 2
    ):
        return "inconclusive", "read-probe sequence incomplete"
    if baseline[0].get("status") != 200 or (
        (recipe.family == "template_injection") == match(baseline[0], recipe.marker)
    ):
        return "inconclusive", "baseline did not establish the required control"
    if any(match(r, recipe.marker) for r in negatives) or any(
        r.get("status") not in {200, 403, 404} for r in negatives
    ):
        return "inconclusive", "negative control did not exclude ordinary reflection/public data"
    if all(r.get("status") == 200 and match(r, recipe.marker) for r in probes):
        return (
            ("confirmed", "forbidden synthetic marker/evaluation reproduced with negative controls")
            if recipe.forbidden
            else ("pass", "declared allowed read reproduced")
        )
    if recipe.denied and all(
        r.get("status") in {200, 403, 404} and match(r, recipe.denied) for r in probes
    ):
        return "pass", "declared application denial reproduced"
    return "inconclusive", "responses did not establish the required proof or declared denial"


def as_control_outcome(
    result: WorkflowResult, recipe: WorkflowRecipe | ReadProbeRecipe
) -> ControlOutcome:
    codes = {
        "mass_assignment": ("SL-C09-MASS-01", Category.C09_AUTHORIZATION),
        "workflow_authorization": ("SL-C11-WORKFLOW-01", Category.C11_BUSINESS_RULES),
        "graphql_authorization": ("SL-C09-GRAPHQL-01", Category.C09_AUTHORIZATION),
        "private_cache": ("SL-C05-CACHE-01", Category.C05_DATA_EXPOSURE),
        "path_traversal": ("SL-C10-TRAVERSAL-01", Category.C10_FILE_HANDLING),
        "template_injection": ("SL-C03-TEMPLATE-01", Category.C03_INJECTION),
    }
    check_id, category = codes[result.family]
    statuses = {
        "confirmed": OutcomeStatus.CONFIRMED_ISSUE,
        "pass": OutcomeStatus.PASS,
        "blocked": OutcomeStatus.BLOCKED,
        "inconclusive": OutcomeStatus.INCONCLUSIVE,
        "error": OutcomeStatus.ERROR,
    }
    complete = result.state in {"pass", "confirmed"} and result.cleanup_state in {
        "clean",
        "not_needed",
    }
    url = recipe.mutation.url if isinstance(recipe, WorkflowRecipe) else recipe.probe.url
    return ControlOutcome(
        check_id=check_id,
        canonical_control="workflow." + result.family,
        category=category,
        status=statuses[result.state],
        summary=result.reason,
        proposed_severity=Severity.HIGH if result.state == "confirmed" else None,
        locations=(Location(route=url, detail=recipe.id),) if result.state == "confirmed" else (),
        proof=ProofResult(
            satisfied=result.state in {"confirmed", "pass"},
            status=EvidenceStatus.CONFIRMED
            if result.state == "confirmed"
            else EvidenceStatus.INCONCLUSIVE,
            evidence_refs=result.evidence_refs,
            reasons=(result.reason,),
        ),
        required_instances=(recipe.id,),
        completed_instances=(recipe.id,) if complete else (),
        incomplete_reasons=()
        if complete
        else (result.reason + "; cleanup=" + result.cleanup_state,),
    )


def recover_cleanup(
    recipe: WorkflowRecipe,
    cleanup_sessions: IdentitySessions,
    journal: CleanupJournal,
    capture: Capture,
    *,
    admit: Callable[[WorkflowRecipe], bool],
) -> WorkflowResult:
    """Reconcile an interrupted disposable workflow without replaying its test mutation."""
    refs, observations = [], []
    cleanup_state = "cleanup_failed"
    reason = "cleanup recovery could not establish restored baseline"
    pending = False
    try:
        pending = journal.state(recipe.id, recipe.resource_id) in {
            "pending",
            "mutation_sent",
            "cleanup_failed",
        }
        if not admit(recipe) or not pending:
            raise SessionUnavailable("no admitted pending cleanup intent")
        if not cleanup_sessions.verify(recipe.owner_identity) or not cleanup_sessions.verify(
            recipe.cleanup_identity
        ):
            raise SessionUnavailable("cleanup recovery identity unavailable")
        initial = cleanup_sessions.request(recipe.owner_identity, recipe.readback)
        if not matches(initial, recipe.seed):
            raise SessionUnavailable("cleanup recovery cannot identify disposable record")
        if not matches(initial, recipe.before):
            response = cleanup_sessions.request(recipe.cleanup_identity, recipe.cleanup)
            item = observation(
                "cleanup",
                recipe.cleanup_identity,
                recipe.cleanup,
                response,
                (recipe.seed, recipe.before),
            )
            refs.append(capture(item))
            observations.append(item)
        restored = cleanup_sessions.request(recipe.owner_identity, recipe.readback)
        item = observation(
            "cleanup_readback",
            recipe.owner_identity,
            recipe.readback,
            restored,
            (recipe.seed, recipe.before),
        )
        refs.append(capture(item))
        observations.append(item)
        if (
            not all(refs)
            or not matches(restored, recipe.seed)
            or not matches(restored, recipe.before)
        ):
            raise SessionUnavailable("cleanup recovery read-back failed")
        journal.mark(recipe.id, recipe.resource_id, "clean")
        cleanup_state = "clean"
        reason = "cleanup recovered and verified; original mutation outcome remains unknown"
    except (RuntimeError, httpx.HTTPError, PermissionError, ValueError, OSError):
        if pending:
            with suppress(RuntimeError, httpx.HTTPError, PermissionError, ValueError, OSError):
                journal.mark(recipe.id, recipe.resource_id, "cleanup_failed")
    return WorkflowResult(
        recipe_id=recipe.id,
        family=recipe.family,
        state="inconclusive",
        reason=reason,
        cleanup_state=cleanup_state,
        evidence_refs=tuple(refs),
        observations=tuple(observations),
    )
