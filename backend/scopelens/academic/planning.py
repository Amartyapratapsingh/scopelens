"""Deterministic review agenda over the existing trusted readiness projection."""

from scopelens.academic.models import (
    AcademicPlan,
    AcademicReadiness,
    AgendaCase,
    FollowupRecommendation,
    PlanBudget,
)
from scopelens.domain.capabilities import canonical_sha256


def project_plan(readiness: AcademicReadiness, *, followup_limit: int = 3) -> AcademicPlan:
    """No new recipes, observations, authority or severity enter through this interface."""
    if isinstance(followup_limit, bool) or not isinstance(followup_limit, int):
        raise ValueError("followup limit must be an integer")
    if not 0 <= followup_limit <= 20:
        raise ValueError("followup limit must be between zero and twenty")

    def priority(case):
        if case.proof == "confirmed_issue":
            return 2, ("trusted_confirmed_case",)
        if case.execution == "observed" and case.proof == "inconclusive":
            return 1, ("trusted_observation_missing_proof",)
        return 0, ()

    def purpose(case):
        if case.kind == "permission":
            return (
                "allowed_comparison"
                if case.expected_permission == "allowed"
                else "forbidden_comparison"
            )
        return "protected_state_transition" if case.kind == "workflow" else "session_policy"

    # Explicit allowed controls lead their baseline group. Every declared case stays
    # in the agenda, including blocked cases and cases already proven by this scan.
    cases = sorted(
        readiness.cases,
        key=lambda case: (
            not case.configuration_ready,
            case.expected_permission != "allowed",
            -priority(case)[0],
            case.kind,
            case.control_id,
            case.id,
        ),
    )
    agenda = []
    for order, case in enumerate(cases, 1):
        score, reasons = priority(case)
        recommendation = "review_declared_case"
        if not case.configuration_ready:
            recommendation = "resolve_declared_prerequisites"
        elif score == 2:
            recommendation = "review_confirmed_case"
        elif score == 1:
            recommendation = "complete_declared_case_proof"
        agenda.append(
            AgendaCase(
                order=order,
                case=case,
                state="ready" if case.configuration_ready else "blocked",
                baseline_purpose=purpose(case),
                priority=score,
                priority_reasons=reasons,
                recommendation=recommendation,
            )
        )
    candidates = sorted(
        (case for case in cases if priority(case)[0]),
        key=lambda case: (not case.configuration_ready, -priority(case)[0], case.id),
    )
    followups = tuple(
        FollowupRecommendation(
            case_id=case.id,
            rank=rank,
            reason="confirmed_case_review"
            if case.proof == "confirmed_issue"
            else "observed_case_missing_proof",
            state="ready" if case.configuration_ready else "blocked",
            blocked_reasons=case.blocked_reasons,
        )
        for rank, case in enumerate(candidates[:followup_limit], 1)
    )
    result = AcademicPlan(
        revision="",
        readiness_revision=readiness.revision,
        configuration_id=readiness.configuration_id,
        configuration_hash=readiness.configuration_hash,
        scope_version_id=readiness.scope_version_id,
        scan_id=readiness.scan_id,
        profile=readiness.profile,
        agenda=tuple(agenda),
        followups=followups,
        budget=PlanBudget(
            baseline_reserved=len(cases),
            baseline_ready=sum(case.configuration_ready for case in cases),
            baseline_blocked=sum(not case.configuration_ready for case in cases),
            followup_limit=followup_limit,
            followup_selected=len(followups),
            followup_deferred=len(candidates) - len(followups),
        ),
        coverage=readiness.coverage,
        features=readiness.features,
    )
    return result.model_copy(
        update={"revision": canonical_sha256(result.model_dump(mode="json", exclude={"revision"}))}
    )
