"""Deterministic scoring and coverage, ``score-v1.0`` (Build Plan §5.15, Spec §9.5-§9.10).

Pure functions over outcomes and findings. Same inputs and same version produce the same
number, always — which is what makes a score reproducible and therefore meaningful, and what
a test asserts directly.

Every rule here is quoted from the specification rather than invented, because the whole point
of a versioned rubric is that the arithmetic is inspectable. The rules that stop a number being
published at all are as important as the deductions:

* a category needs **≥80% control coverage**, every mandatory control assessed, and no
  unresolved Potential High/Critical before it may show a number
* the overall score needs **every applicable category** to qualify. A blocked or
  insufficiently assessed category is never dropped to improve the average
* only an **evidence-backed fully N/A** category may be removed, and the remaining weights are
  renormalised — with the exclusion shown
* an interrupted or cancelled scan cannot publish a completed overall rating

Rounding happens only for display. The full-precision value is carried alongside so that no
downstream calculation is built on a rounded intermediate.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from math import isfinite

from scopelens.domain.check import ControlOutcome
from scopelens.domain.enums import Category, ProfileName, Severity
from scopelens.domain.enums import ControlOutcome as OutcomeStatus
from scopelens.domain.finding import Finding
from scopelens.scoring.profiles import rubric_for

SCORE_VERSION = "score-v1.0"

#: Spec §9.5 — fixed profile weights for the external unauthenticated profile. They sum to 100.
CATEGORY_WEIGHTS: dict[Category, int] = {
    Category.C01_TRANSPORT: 15,
    Category.C02_SERVER_SESSION: 15,
    Category.C03_INJECTION: 20,
    Category.C04_BROWSER_CROSS_ORIGIN: 15,
    Category.C05_DATA_EXPOSURE: 15,
    Category.C06_COMPONENTS: 10,
    Category.C07_API: 10,
}

#: Spec §9.5 — the categories outside this profile. Displayed as `Not assessed in this
#: profile`, never omitted silently and never scored.
OUT_OF_PROFILE: tuple[Category, ...] = (
    Category.C08_AUTHENTICATION,
    Category.C09_AUTHORIZATION,
    Category.C10_FILE_HANDLING,
    Category.C11_BUSINESS_RULES,
    Category.C12_DOMAIN_ASSET,
)

MIN_COVERAGE_PERCENT = 80.0  # Spec §9.7
CRITICAL_CAP = 39
HIGH_CAP = 69

OVERALL_LABEL = (
    "External configuration assessment pilot score — uncalibrated. "
    "Not a whole-website security rating."
)


class CategoryState(enum.StrEnum):
    SCORED = "scored"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"
    VERIFICATION_PENDING = "verification_pending"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class Deduction:
    """One confirmed root cause's deduction, kept so the arithmetic is inspectable."""

    root_cause: str
    severity: Severity
    points: int
    finding_id: str
    locations: tuple[str, ...]


@dataclass(frozen=True)
class CategoryScore:
    category: Category
    weight: int
    state: CategoryState
    coverage_percent: float
    fully_assessed_weight: float
    total_weight: float
    deductions: tuple[Deduction, ...] = ()
    raw_score: float | None = None
    score: int | None = None
    caps_applied: tuple[str, ...] = ()
    reason: str = ""
    mandatory_unassessed: tuple[str, ...] = ()
    unresolved_candidates: tuple[str, ...] = ()
    #: True when the selected profile cannot assess this category at all — as opposed to
    #: assessing it and falling short. The distinction decides whether the category blocks
    #: the overall score or is removed from it and the weights renormalised (Spec §9.7).
    profile_excluded: bool = False


@dataclass(frozen=True)
class OverallScore:
    state: CategoryState
    raw_score: float | None = None
    score: int | None = None
    caps_applied: tuple[str, ...] = ()
    reason: str = ""
    label: str = OVERALL_LABEL
    excluded_categories: tuple[Category, ...] = ()
    blocked_categories: tuple[Category, ...] = ()
    effective_weights: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class ScoreSnapshot:
    score_version: str
    categories: tuple[CategoryScore, ...]
    overall: OverallScore
    coverage_percent: float
    verdict: str

    def category(self, category: Category) -> CategoryScore | None:
        for entry in self.categories:
            if entry.category is category:
                return entry
        return None


def score(
    *,
    outcomes: list[ControlOutcome],
    findings: list[Finding],
    mandatory_controls: set[str],
    scan_interrupted: bool = False,
    profile_includes_active_pack: bool = False,
    control_weights: dict[str, float] | None = None,
    profile: ProfileName | None = None,
    planned_controls: dict[str, Category] | None = None,
) -> ScoreSnapshot:
    """Compute a snapshot from verified outcomes and deduplicated findings.

    Expanded profiles require the frozen registry's complete ID/category map as
    ``planned_controls``. Missing results stay in coverage as NOT_TESTED. Passing only
    controls that happened to finish would change the denominator and is not permitted.
    Legacy callers may omit both new arguments and retain score-v1.0 behavior.
    """
    category_weights = CATEGORY_WEIGHTS
    score_version = SCORE_VERSION
    overall_label = OVERALL_LABEL
    if profile is not None:
        profile = ProfileName(profile)
        profile_includes_active_pack = profile.includes_active_pack
    if profile is not None and profile.expanded:
        if not planned_controls:
            raise ValueError("expanded scoring requires a nonempty frozen planned-control map")
        rubric = rubric_for(profile)
        category_weights = dict(rubric.weights)
        score_version = rubric.version
        overall_label = rubric.label
        outcomes = _planned_outcomes(outcomes, planned_controls, mandatory_controls)
        for check_id, weight in (control_weights or {}).items():
            if not isfinite(weight) or weight <= 0:
                raise ValueError(f"control weight must be finite and positive: {check_id}")
    confirmed = [f for f in findings if f.is_confirmed]
    candidates = [f for f in findings if f.is_unresolved_serious_candidate]

    # Spec §9.6: confirmed unresolved High/Critical findings apply global caps **even if their
    # category is outside the numeric profile**. Collected before the per-category loop so a
    # finding in an out-of-profile category still caps the total.
    global_severities = {f.severity for f in confirmed if f.severity.holds_overall_score}

    categories: list[CategoryScore] = []
    for category, weight in category_weights.items():
        categories.append(
            _score_category(
                category=category,
                weight=weight,
                outcomes=[o for o in outcomes if o.category is category],
                confirmed=[f for f in confirmed if f.category is category],
                candidates=[f for f in candidates if f.category is category],
                mandatory_controls=mandatory_controls,
                profile_includes_active_pack=profile_includes_active_pack,
                control_weights=control_weights or {},
            )
        )

    for category in Category:
        if category in category_weights:
            continue
        categories.append(
            CategoryScore(
                category=category,
                weight=0,
                state=CategoryState.NOT_ASSESSED,
                coverage_percent=0.0,
                fully_assessed_weight=0.0,
                total_weight=0.0,
                reason="Not assessed in this profile",
                profile_excluded=True,
            )
        )

    overall = _overall(
        categories,
        global_severities,
        scan_interrupted=scan_interrupted,
        candidates=candidates,
        category_weights=category_weights,
    )
    overall = replace(overall, label=overall_label)

    applicable = [c for c in categories if c.category in category_weights]
    total_weight = sum(c.total_weight for c in applicable)
    assessed_weight = sum(c.fully_assessed_weight for c in applicable)
    coverage = (100.0 * assessed_weight / total_weight) if total_weight else 0.0

    return ScoreSnapshot(
        score_version=score_version,
        categories=tuple(categories),
        overall=overall,
        coverage_percent=coverage,
        verdict=_verdict(overall),
    )


def _planned_outcomes(
    outcomes: list[ControlOutcome],
    planned: dict[str, Category],
    mandatory: set[str],
) -> list[ControlOutcome]:
    """Keep every planned control, rejecting ambiguous or denominator-changing input."""
    if mandatory - planned.keys():
        raise ValueError("mandatory controls must belong to the frozen planned-control map")
    by_id: dict[str, ControlOutcome] = {}
    for outcome in outcomes:
        if outcome.check_id not in planned:
            raise ValueError(f"unplanned control outcome: {outcome.check_id}")
        if outcome.check_id in by_id:
            raise ValueError(f"duplicate control outcome: {outcome.check_id}")
        if outcome.category != planned[outcome.check_id]:
            raise ValueError(f"control category differs from frozen plan: {outcome.check_id}")
        by_id[outcome.check_id] = outcome
    return [
        by_id.get(check_id)
        or ControlOutcome(
            check_id=check_id,
            canonical_control=check_id,
            category=category,
            status=OutcomeStatus.NOT_TESTED,
            summary="The frozen plan required this control, but no outcome was produced",
            incomplete_reasons=("planned control outcome missing",),
        )
        for check_id, category in sorted(planned.items())
    ]


def _score_category(
    *,
    category: Category,
    weight: int,
    outcomes: list[ControlOutcome],
    confirmed: list[Finding],
    candidates: list[Finding],
    mandatory_controls: set[str],
    profile_includes_active_pack: bool,
    control_weights: dict[str, float],
) -> CategoryScore:
    # A category the selected profile cannot assess is decided *first*, before the
    # no-controls check. Otherwise C03 in the configuration profile would look like a
    # category that was planned and then not assessed — a coverage gap — when in fact the
    # profile declares up front that it does not assess injection at all.
    if category is Category.C03_INJECTION and not profile_includes_active_pack:
        return CategoryScore(
            category=category,
            weight=weight,
            state=CategoryState.NOT_ASSESSED,
            coverage_percent=0.0,
            fully_assessed_weight=0.0,
            total_weight=0.0,
            reason=(
                "Not assessed in this profile: the conditional active pack is not part of "
                "the external configuration assessment"
            ),
            profile_excluded=True,
        )

    if not outcomes:
        return CategoryScore(
            category=category,
            weight=weight,
            state=CategoryState.NOT_ASSESSED,
            coverage_percent=0.0,
            fully_assessed_weight=0.0,
            total_weight=0.0,
            reason="no control in this profile applies to this category",
        )

    # Spec §9.7 defines coverage as *fully-assessed applicable control weight / total
    # applicable weight*. A control with a recorded, evidence-backed Not-applicable is not
    # applicable, so it leaves BOTH the numerator and the denominator. It cannot inflate
    # coverage: a category whose controls are all N/A has no applicable weight left and is
    # removed from the overall as an evidence-backed fully-N/A category rather than scored
    # at 100%.
    #
    # Everything else stays in the denominator, including unsupported controls and those that
    # were blocked, errored or never reached — that is the part that must never be dropped.
    scorable = [
        o
        for o in outcomes
        if not (o.status is OutcomeStatus.NOT_APPLICABLE and o.na_reason and o.na_evidence_ref)
    ]
    total_weight = float(sum(control_weights.get(o.check_id, 1) for o in scorable))
    assessed = [o for o in scorable if o.is_fully_assessed]
    assessed_weight = float(sum(control_weights.get(o.check_id, 1) for o in assessed))
    coverage = 100.0 * assessed_weight / total_weight if total_weight else 0.0

    mandatory_unassessed = tuple(
        o.check_id for o in scorable if o.check_id in mandatory_controls and not o.is_fully_assessed
    )

    deductions = _deductions_for(category, confirmed)
    raw = max(0.0, 100.0 - sum(d.points for d in deductions))

    if candidates:
        return CategoryScore(
            category=category,
            weight=weight,
            state=CategoryState.VERIFICATION_PENDING,
            coverage_percent=coverage,
            fully_assessed_weight=assessed_weight,
            total_weight=total_weight,
            deductions=deductions,
            raw_score=raw,
            reason=(
                "an unresolved Potential High/Critical candidate in this category holds the "
                "score at Verification pending (Spec §9.6)"
            ),
            mandatory_unassessed=mandatory_unassessed,
            unresolved_candidates=tuple(f.id for f in candidates),
        )

    if mandatory_unassessed:
        return CategoryScore(
            category=category,
            weight=weight,
            state=CategoryState.INSUFFICIENT_COVERAGE,
            coverage_percent=coverage,
            fully_assessed_weight=assessed_weight,
            total_weight=total_weight,
            deductions=deductions,
            raw_score=raw,
            reason=(f"mandatory control(s) not fully assessed: {', '.join(mandatory_unassessed)}"),
            mandatory_unassessed=mandatory_unassessed,
        )

    if not scorable:
        return CategoryScore(
            category=category,
            weight=weight,
            state=CategoryState.NOT_APPLICABLE,
            coverage_percent=0,
            fully_assessed_weight=0,
            total_weight=0,
            reason="All planned controls have evidence-backed inapplicability",
        )

    if coverage < MIN_COVERAGE_PERCENT:
        return CategoryScore(
            category=category,
            weight=weight,
            state=CategoryState.INSUFFICIENT_COVERAGE,
            coverage_percent=coverage,
            fully_assessed_weight=assessed_weight,
            total_weight=total_weight,
            deductions=deductions,
            raw_score=raw,
            reason=(
                f"coverage {coverage:.1f}% is below the {MIN_COVERAGE_PERCENT:.0f}% gate; a "
                "number here would overstate what was assessed"
            ),
            mandatory_unassessed=mandatory_unassessed,
        )

    # Eligible: apply the category caps (Spec §9.6).
    capped = raw
    caps: list[str] = []
    severities = {d.severity for d in deductions}
    if Severity.CRITICAL in severities:
        capped = min(capped, CRITICAL_CAP)
        caps.append(f"capped at {CRITICAL_CAP} by an unresolved confirmed Critical finding")
    if Severity.HIGH in severities:
        capped = min(capped, HIGH_CAP)
        caps.append(f"capped at {HIGH_CAP} by an unresolved confirmed High finding")

    return CategoryScore(
        category=category,
        weight=weight,
        state=CategoryState.SCORED,
        coverage_percent=coverage,
        fully_assessed_weight=assessed_weight,
        total_weight=total_weight,
        deductions=deductions,
        raw_score=capped,
        # Round only for display; the full-precision value is carried alongside.
        score=round(capped),
        caps_applied=tuple(caps),
        reason="",
    )


def _deductions_for(category: Category, confirmed: list[Finding]) -> tuple[Deduction, ...]:
    """Per distinct root cause. Deduplication has already grouped by root cause (§9.8)."""
    return tuple(
        Deduction(
            root_cause=finding.root_cause,
            severity=finding.severity,
            points=finding.severity.deduction,
            finding_id=finding.id,
            locations=tuple(location.route for location in finding.locations),
        )
        for finding in confirmed
        if finding.category is category and finding.severity.deduction > 0
    )


def _overall(
    categories: list[CategoryScore],
    global_severities: set[Severity],
    *,
    scan_interrupted: bool,
    candidates: list[Finding],
    category_weights: dict[Category, int],
) -> OverallScore:
    applicable = [c for c in categories if c.category in category_weights]

    if scan_interrupted:
        return OverallScore(
            state=CategoryState.INSUFFICIENT_COVERAGE,
            reason=(
                "an interrupted or cancelled scan cannot publish a completed overall rating "
                "(Spec §9.7)"
            ),
            blocked_categories=tuple(c.category for c in applicable),
        )

    any_candidates = sorted({f.category for f in candidates}, key=lambda c: c.value)
    if any_candidates:
        return OverallScore(
            state=CategoryState.VERIFICATION_PENDING,
            reason=(
                "an unresolved Potential High/Critical candidate on the assessed target holds "
                "the overall score at Verification pending, including candidates from "
                "unmapped or experimental checks (Spec §9.6)"
            ),
            blocked_categories=tuple(any_candidates),
        )

    blocked = [
        c
        for c in applicable
        if c.state in {CategoryState.INSUFFICIENT_COVERAGE, CategoryState.NOT_ASSESSED}
        and not c.profile_excluded
    ]
    if blocked:
        return OverallScore(
            state=CategoryState.INSUFFICIENT_COVERAGE,
            reason=(
                "every applicable category must meet its gate before an overall score is "
                "published; a blocked or insufficiently assessed category is never dropped "
                "to improve the average (Spec §9.7)"
            ),
            blocked_categories=tuple(c.category for c in blocked),
        )

    # Removable categories: those this profile declares it cannot assess, and those with no
    # applicable controls at all. Both are evidence-backed exclusions rather than gaps, and
    # the remaining fixed weights are renormalised with the exclusion shown (Spec §9.7).
    removed = [c for c in applicable if c.profile_excluded or c.total_weight == 0]
    scored = [c for c in applicable if not c.profile_excluded and c.total_weight > 0]

    if not scored:
        return OverallScore(
            state=CategoryState.NOT_ASSESSED,
            reason="no category in this profile is applicable to this target",
            excluded_categories=tuple(c.category for c in removed),
        )

    effective = {c.category.value: float(c.weight) for c in scored}
    total_effective = sum(effective.values())
    weighted = sum((c.raw_score or 0.0) * c.weight for c in scored) / total_effective

    caps: list[str] = []
    capped = weighted
    if Severity.CRITICAL in global_severities:
        capped = min(capped, CRITICAL_CAP)
        caps.append(
            f"capped at {CRITICAL_CAP} by an unresolved confirmed Critical finding on the "
            "assessed target"
        )
    if Severity.HIGH in global_severities:
        capped = min(capped, HIGH_CAP)
        caps.append(
            f"capped at {HIGH_CAP} by an unresolved confirmed High finding on the assessed target"
        )

    return OverallScore(
        state=CategoryState.SCORED,
        raw_score=capped,
        score=round(capped),
        caps_applied=tuple(caps),
        reason="",
        excluded_categories=tuple(c.category for c in removed),
        effective_weights=effective,
    )


def _verdict(overall: OverallScore) -> str:
    """The customer-facing band (Spec §9.8), or the reason there is no band."""
    if overall.state is CategoryState.VERIFICATION_PENDING:
        return "Verification pending"
    if overall.state is CategoryState.NOT_ASSESSED:
        return "Not scored"
    if overall.state is CategoryState.INSUFFICIENT_COVERAGE:
        return "Insufficient coverage"
    score = overall.score or 0
    if score >= 90:
        return "Strong observed posture"
    if score >= 70:
        return "Needs improvement"
    if score >= 40:
        return "Weak observed posture"
    return "Poor observed posture"


def ratings_table() -> dict[str, str]:
    """The band table, exposed so the report and the dashboard share one definition."""
    return {
        "90-100": "Strong observed posture",
        "70-89": "Needs improvement",
        "40-69": "Weak observed posture",
        "0-39": "Poor observed posture",
    }


def blocked_outcome_note(outcome: ControlOutcome) -> str:
    """Why a non-conclusive outcome can never be a pass or an N/A (Spec §9.7).

    Kept as a function so the wording is defined once and the report, the dashboard and the
    API all say the same thing about a control that did not run.
    """
    mapping = {
        OutcomeStatus.BLOCKED: "the policy broker refused the request this control needed",
        OutcomeStatus.ERROR: "the control failed to run",
        OutcomeStatus.NOT_TESTED: "the control was not reached",
        OutcomeStatus.INCONCLUSIVE: "the evidence was not sufficient to conclude",
    }
    return mapping.get(outcome.status, "the control did not produce a conclusive outcome")
