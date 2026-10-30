"""Profile boundaries and frozen denominators for the expansion pilot rubrics."""

import pytest

from scopelens.domain.check import ControlOutcome, Location
from scopelens.domain.enums import Category, Confidence, EvidenceStatus, ProfileName, Severity
from scopelens.domain.enums import ControlOutcome as Status
from scopelens.domain.finding import Finding
from scopelens.scoring.profiles import rubric_for
from scopelens.scoring.score import CategoryState, score


def inputs(profile):
    plan = {f"control-{cat.value}": cat for cat, _ in rubric_for(profile).weights}
    outcomes = [
        ControlOutcome(check_id=key, canonical_control=key, category=cat, status=Status.PASS)
        for key, cat in plan.items()
    ]
    return plan, outcomes


def run(profile, *, findings=(), absent=(), updates=None, mandatory=None):
    plan, outcomes = inputs(profile)
    outcomes = [
        outcome.model_copy(update=(updates or {}).get(outcome.category, {}))
        for outcome in outcomes
        if outcome.category not in absent
    ]
    return score(
        profile=profile,
        planned_controls=plan,
        mandatory_controls=set(plan) if mandatory is None else mandatory,
        outcomes=outcomes,
        findings=list(findings),
    )


def finding(category, severity, evidence_status=EvidenceStatus.CONFIRMED):
    return Finding(
        id="finding-1",
        check_id=f"control-{category.value}",
        canonical_control="test",
        root_cause="test",
        category=category,
        title="Fixture finding",
        severity=severity,
        evidence_status=evidence_status,
        confidence=Confidence.HIGH,
        locations=(Location(route="/fixture"),),
    )


@pytest.mark.parametrize("profile", [p for p in ProfileName if p.expanded])
def test_profiles_use_distinct_versions_and_explain_comparability(profile):
    result = run(profile)
    assert result.score_version == rubric_for(profile).version
    assert len(result.score_version) <= 32
    assert result.overall.score == 100
    assert "not directly comparable" in result.overall.label
    assert "uncalibrated" in result.overall.label
    assert len(result.categories) == 12
    assert sum(weight for _, weight in rubric_for(profile).weights) == 100


@pytest.mark.parametrize("profile", [p for p in ProfileName if p.expanded])
def test_no_frozen_denominator_cannot_publish_score(profile):
    with pytest.raises(ValueError, match="frozen planned-control map"):
        score(profile=profile, outcomes=[], findings=[], mandatory_controls=set())


def test_authenticated_profile_scores_authentication_and_authorization_only():
    result = run(ProfileName.AUTHENTICATED_API_V1)
    assert result.category(Category.C08_AUTHENTICATION).score == 100
    assert result.category(Category.C09_AUTHORIZATION).score == 100
    assert result.category(Category.C10_FILE_HANDLING).profile_excluded
    assert result.category(Category.C11_BUSINESS_RULES).profile_excluded


def test_stateful_profile_includes_files_and_business_rules():
    result = run(ProfileName.STAGING_STATEFUL_V1)
    assert result.category(Category.C10_FILE_HANDLING).score == 100
    assert result.category(Category.C11_BUSINESS_RULES).score == 100
    assert result.category(Category.C12_DOMAIN_ASSET).profile_excluded


@pytest.mark.parametrize("category", [Category.C08_AUTHENTICATION, Category.C09_AUTHORIZATION])
def test_missing_mandatory_auth_control_stays_in_denominator(category):
    result = run(ProfileName.AUTHENTICATED_API_V1, absent=[category])
    assert result.overall.score is None
    entry = result.category(category)
    assert entry.total_weight == 1
    assert entry.fully_assessed_weight == 0
    assert entry.mandatory_unassessed == (f"control-{category.value}",)
    assert category in result.overall.blocked_categories


def test_missing_nonmandatory_control_is_still_a_coverage_gap():
    result = run(
        ProfileName.STAGING_STATEFUL_V1,
        absent=[Category.C10_FILE_HANDLING],
        mandatory=set(),
    )
    assert result.overall.score is None
    assert result.category(Category.C10_FILE_HANDLING).coverage_percent == 0


def test_missing_role_instance_and_cleanup_failure_block_coverage():
    result = run(
        ProfileName.STAGING_STATEFUL_V1,
        updates={
            Category.C09_AUTHORIZATION: {
                "required_instances": ("owner", "other-user"),
                "completed_instances": ("owner",),
            },
            Category.C11_BUSINESS_RULES: {"incomplete_reasons": ("cleanup_failed",)},
        },
    )
    assert result.overall.score is None
    assert result.category(Category.C09_AUTHORIZATION).coverage_percent == 0
    assert result.category(Category.C11_BUSINESS_RULES).coverage_percent == 0


def test_evidence_backed_na_removed_but_bare_na_blocks():
    category = Category.C10_FILE_HANDLING
    result = run(
        ProfileName.STAGING_STATEFUL_V1,
        updates={
            category: {
                "status": Status.NOT_APPLICABLE,
                "na_reason": "absent",
                "na_evidence_ref": "trusted-1",
            }
        },
    )
    assert result.category(category).state == CategoryState.NOT_APPLICABLE
    assert result.overall.score == 100
    assert category in result.overall.excluded_categories
    bare = run(
        ProfileName.STAGING_STATEFUL_V1, updates={category: {"status": Status.NOT_APPLICABLE}}
    )
    assert bare.overall.score is None


def test_high_auth_issue_caps_entire_profile_and_pending_holds_it():
    issue = finding(Category.C09_AUTHORIZATION, Severity.HIGH)
    confirmed = run(ProfileName.AUTHENTICATED_API_V1, findings=[issue])
    assert confirmed.category(Category.C09_AUTHORIZATION).score == 65
    assert confirmed.overall.score == 69
    pending = run(
        ProfileName.AUTHENTICATED_API_V1,
        findings=[issue.model_copy(update={"evidence_status": EvidenceStatus.POTENTIAL})],
    )
    assert pending.overall.state == CategoryState.VERIFICATION_PENDING
    assert pending.overall.score is None


def test_unknown_category_in_profile_is_gap_even_with_no_planned_controls_for_it():
    profile = ProfileName.AUTHENTICATED_API_V1
    plan, outcomes = inputs(profile)
    missing = next(key for key, cat in plan.items() if cat == Category.C09_AUTHORIZATION)
    del plan[missing]
    result = score(
        profile=profile,
        planned_controls=plan,
        outcomes=[o for o in outcomes if o.check_id != missing],
        mandatory_controls=set(plan),
        findings=[],
    )
    assert result.overall.score is None
    assert Category.C09_AUTHORIZATION in result.overall.blocked_categories


@pytest.mark.parametrize("defect", ["duplicate", "category", "unplanned", "mandatory", "weight"])
def test_corrupt_plan_or_outputs_fail_explicitly(defect):
    profile = ProfileName.AUTHENTICATED_API_V1
    plan, outcomes = inputs(profile)
    mandatory = set(plan)
    weights = {}
    if defect == "duplicate":
        outcomes.append(outcomes[0])
    elif defect == "category":
        outcomes[0] = outcomes[0].model_copy(update={"category": Category.C12_DOMAIN_ASSET})
    elif defect == "unplanned":
        outcomes[0] = outcomes[0].model_copy(update={"check_id": "not-planned"})
    elif defect == "mandatory":
        mandatory.add("missing")
    else:
        weights[outcomes[0].check_id] = float("nan")
    with pytest.raises(ValueError):
        score(
            profile=profile,
            planned_controls=plan,
            outcomes=outcomes,
            mandatory_controls=mandatory,
            findings=[],
            control_weights=weights,
        )


def test_legacy_explicit_profile_preserves_existing_version_and_categories():
    result = score(
        profile=ProfileName.EXTERNAL_DAST, outcomes=[], findings=[], mandatory_controls=set()
    )
    assert result.score_version == "score-v1.0"
    assert result.category(Category.C08_AUTHENTICATION).profile_excluded
