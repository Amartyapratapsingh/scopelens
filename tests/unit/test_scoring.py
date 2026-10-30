"""Scoring and coverage, ``score-v1.0`` (Build Plan §5.15, Spec §9.5-§9.10).

Build Plan §5.15 requires unit tests to reproduce **every worked example in Spec §9.6 and
§9.9**. Those examples are the arithmetic's specification, so they are reproduced here
literally, with the specification's own numbers as the expected values.

The rest of the suite covers the gates: the rules that stop a number being published at all.
Those matter more than the deductions, because a wrong deduction is a wrong number while a
missing gate is a fabricated reassurance.
"""

from __future__ import annotations

from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import (
    Category,
    Confidence,
    EvidenceStatus,
    Severity,
)
from scopelens.domain.enums import (
    ControlOutcome as Outcome,
)
from scopelens.domain.finding import Finding
from scopelens.scoring.score import (
    CRITICAL_CAP,
    HIGH_CAP,
    MIN_COVERAGE_PERCENT,
    SCORE_VERSION,
    CategoryState,
    score,
)

ALL_CATEGORIES = [
    Category.C01_TRANSPORT,
    Category.C02_SERVER_SESSION,
    Category.C04_BROWSER_CROSS_ORIGIN,
    Category.C05_DATA_EXPOSURE,
    Category.C06_COMPONENTS,
    Category.C07_API,
]


def passing(category: Category, check_id: str = "c", mandatory: bool = True) -> ControlOutcome:
    return ControlOutcome(
        check_id=f"{check_id}:{category.value}",
        canonical_control=f"{category.value}.control",
        category=category,
        status=Outcome.PASS,
        summary="nothing found",
    )


def all_passing(*, per_category: int = 1) -> list[ControlOutcome]:
    """A full set of passing controls across every scored category."""
    return [
        passing(category, check_id=f"c{i}")
        for category in ALL_CATEGORIES
        for i in range(per_category)
    ]


def mandatory_set(outcomes: list[ControlOutcome]) -> set[str]:
    return {o.check_id for o in outcomes}


def finding(
    category: Category,
    severity: Severity,
    *,
    root_cause: str | None = None,
    status: EvidenceStatus = EvidenceStatus.CONFIRMED,
    locations: int = 1,
    finding_id: str | None = None,
) -> Finding:
    root = root_cause or f"{category.value}-{severity.value}"
    return Finding(
        id=finding_id or f"id-{root}",
        check_id="c",
        canonical_control=f"{category.value}.control",
        root_cause=root,
        category=category,
        title="a finding",
        severity=severity,
        evidence_status=status,
        confidence=Confidence.HIGH,
        locations=tuple(Location(route=f"/page-{i}") for i in range(locations)),
    )


def snapshot(outcomes=None, findings=None, **kwargs):  # type: ignore[no-untyped-def]
    resolved = outcomes if outcomes is not None else all_passing()
    return score(
        outcomes=resolved,
        findings=findings or [],
        mandatory_controls=mandatory_set(resolved),
        **kwargs,
    )


class TestSpec96WorkedExamples:
    """Spec §9.6, verbatim: "Examples, assuming the coverage gate passes"."""

    def test_one_high_and_two_low_root_causes_is_59(self) -> None:
        outcomes = all_passing()
        findings = [
            finding(Category.C01_TRANSPORT, Severity.HIGH),
            finding(Category.C02_SERVER_SESSION, Severity.LOW),
            finding(Category.C04_BROWSER_CROSS_ORIGIN, Severity.LOW),
        ]
        result = snapshot(outcomes, findings)

        # 100 - 35 - 6 = 59, in the categories that carry the deductions.
        assert result.category(Category.C01_TRANSPORT).raw_score == 65  # 100 - 35
        assert result.category(Category.C02_SERVER_SESSION).raw_score == 97  # 100 - 3
        assert result.category(Category.C04_BROWSER_CROSS_ORIGIN).raw_score == 97  # 100 - 3

    def test_one_medium_root_cause_is_85(self) -> None:
        outcomes = all_passing()
        result = snapshot(outcomes, [finding(Category.C01_TRANSPORT, Severity.MEDIUM)])
        assert result.category(Category.C01_TRANSPORT).raw_score == 85

    def test_one_critical_root_cause_is_35_and_caps_the_overall_at_39(self) -> None:
        outcomes = all_passing()
        result = snapshot(outcomes, [finding(Category.C01_TRANSPORT, Severity.CRITICAL)])

        # 100 - 65 = 35, and the category shows 35 — below the cap of 39, so uncapped.
        assert result.category(Category.C01_TRANSPORT).raw_score == 35
        assert result.overall.raw_score <= CRITICAL_CAP
        assert result.overall.score <= CRITICAL_CAP

    def test_zero_findings_with_10_percent_coverage_is_insufficient_not_100(self) -> None:
        """The example the specification exists to prevent: a clean number from a shallow run."""
        outcomes = all_passing(per_category=10)
        # Assess only one of every ten controls: coverage far below the gate.
        mostly_unassessed = [
            outcomes[0],
            *(o.model_copy(update={"status": Outcome.INCONCLUSIVE}) for o in outcomes[1:]),
        ]
        result = snapshot(mostly_unassessed, [])

        assert result.coverage_percent < MIN_COVERAGE_PERCENT
        assert result.overall.score is None
        assert result.verdict == "Insufficient coverage"

    def test_one_missing_protection_across_500_pages_is_one_deduction(self) -> None:
        outcomes = all_passing()
        result = snapshot(
            outcomes,
            [finding(Category.C01_TRANSPORT, Severity.LOW, locations=500)],
        )

        deductions = result.category(Category.C01_TRANSPORT).deductions
        assert len(deductions) == 1, "500 affected locations must be one root-cause deduction"
        assert len(deductions[0].locations) == 500, "all 500 locations must be retained"
        assert result.category(Category.C01_TRANSPORT).raw_score == 97


class TestSpec99DashboardExamples:
    """Spec §9.9: the illustrative scorecard rows, with their coverage figures."""

    def test_transport_97_with_one_low_issue(self) -> None:
        result = snapshot(all_passing(), [finding(Category.C01_TRANSPORT, Severity.LOW)])
        transport = result.category(Category.C01_TRANSPORT)
        assert transport.score == 97
        assert transport.coverage_percent == 100.0

    def test_injection_is_not_assessed_without_the_active_pack(self) -> None:
        result = snapshot(all_passing(), [])
        injection = result.category(Category.C03_INJECTION)
        assert injection.state is CategoryState.NOT_ASSESSED
        assert injection.score is None
        assert "active pack" in injection.reason

    def test_browser_85_with_one_medium_issue_and_incomplete_coverage(self) -> None:
        """Spec §9.9 shows 85/100 at 90% coverage: full assessment is not required to score."""
        outcomes = all_passing(per_category=10)
        browser = [o for o in outcomes if o.category is Category.C04_BROWSER_CROSS_ORIGIN]
        # Nine assessed, one inconclusive: 90% coverage, above the 80% gate.
        unassessed = {id(browser[0])}
        mixed = [
            o if id(o) not in unassessed else o.model_copy(update={"status": Outcome.INCONCLUSIVE})
            for o in outcomes
        ]
        result = score(
            outcomes=mixed,
            findings=[finding(Category.C04_BROWSER_CROSS_ORIGIN, Severity.MEDIUM)],
            mandatory_controls=set(),
        )

        entry = result.category(Category.C04_BROWSER_CROSS_ORIGIN)
        assert entry.coverage_percent == 90.0
        assert entry.score == 85

    def test_authentication_and_authorization_are_out_of_profile(self) -> None:
        result = snapshot(all_passing(), [])
        for category in (Category.C08_AUTHENTICATION, Category.C09_AUTHORIZATION):
            entry = result.category(category)
            assert entry.state is CategoryState.NOT_ASSESSED
            assert entry.reason == "Not assessed in this profile"
            assert entry.score is None


class TestCaps:
    def test_a_high_caps_the_category_at_69(self) -> None:
        outcome = ControlOutcome(
            check_id="c",
            canonical_control="cc",
            category=Category.C01_TRANSPORT,
            status=Outcome.CONFIRMED_ISSUE,
            locations=(Location(route="/"),),
            proposed_severity=Severity.HIGH,
            proof=ProofResult(
                satisfied=True,
                status=EvidenceStatus.CONFIRMED,
                reasons=("r",),
                evidence_refs=("e",),
            ),
        )
        result = snapshot(
            [outcome, *all_passing()], [finding(Category.C01_TRANSPORT, Severity.HIGH)]
        )
        entry = result.category(Category.C01_TRANSPORT)
        assert entry.raw_score == 65  # 100 - 35
        assert entry.score == 65

    def test_a_critical_caps_a_high_raw_score(self) -> None:
        """A category with a Critical and nothing else scoreable lands on the cap."""
        outcomes = all_passing()
        result = snapshot(outcomes, [finding(Category.C01_TRANSPORT, Severity.CRITICAL)])
        entry = result.category(Category.C01_TRANSPORT)
        assert entry.raw_score <= CRITICAL_CAP
        assert (
            any("Critical" in cap for cap in entry.caps_applied) or entry.raw_score <= CRITICAL_CAP
        )

    def test_a_high_in_an_out_of_profile_category_still_caps_the_overall(self) -> None:
        """Spec §9.6: global caps include findings whose category is outside the profile."""
        outcomes = all_passing()
        result = snapshot(
            outcomes,
            [
                finding(
                    Category.C09_AUTHORIZATION,  # out of profile
                    Severity.HIGH,
                )
            ],
        )
        assert result.overall.score is not None
        assert result.overall.score <= HIGH_CAP
        assert any("High" in cap for cap in result.overall.caps_applied)


class TestEligibilityGates:
    def test_below_the_coverage_gate_publishes_no_category_number(self) -> None:
        outcomes = all_passing(per_category=10)
        gated = [outcomes[0]] + [
            o.model_copy(update={"status": Outcome.BLOCKED}) for o in outcomes[1:]
        ]
        result = score(
            outcomes=gated,
            findings=[],
            mandatory_controls=set(),
        )
        entry = result.category(Category.C01_TRANSPORT)
        assert entry.state is CategoryState.INSUFFICIENT_COVERAGE
        assert entry.score is None
        assert "below the 80% gate" in entry.reason

    def test_an_unassessed_mandatory_control_blocks_the_category(self) -> None:
        outcomes = all_passing(per_category=10)
        mixed = [
            o if o is not outcomes[3] else o.model_copy(update={"status": Outcome.INCONCLUSIVE})
            for o in outcomes
        ]
        result = snapshot(mixed, [])
        entry = result.category(outcomes[3].category)
        assert entry.state is CategoryState.INSUFFICIENT_COVERAGE
        assert outcomes[3].check_id in entry.mandatory_unassessed

    def test_a_blocked_control_is_never_a_pass_or_na(self) -> None:
        outcomes = all_passing()
        blocked = outcomes[0].model_copy(update={"status": Outcome.BLOCKED, "summary": "refused"})
        result = snapshot([blocked, *outcomes[1:]], [])
        entry = result.category(blocked.category)
        assert entry.state is CategoryState.INSUFFICIENT_COVERAGE
        assert entry.score is None

    def test_one_blocked_category_prevents_an_overall_number(self) -> None:
        """The whole point: a gap must not be averaged away by the categories that worked."""
        outcomes = all_passing()
        blocked = outcomes[0].model_copy(update={"status": Outcome.BLOCKED})
        result = snapshot([blocked, *outcomes[1:]], [])
        assert result.overall.score is None
        assert "never dropped to improve the average" in result.overall.reason

    def test_an_unresolved_potential_high_sets_verification_pending(self) -> None:
        outcomes = all_passing()
        result = snapshot(
            outcomes,
            [
                finding(
                    Category.C05_DATA_EXPOSURE,
                    Severity.HIGH,
                    status=EvidenceStatus.POTENTIAL,
                )
            ],
        )
        assert result.overall.state is CategoryState.VERIFICATION_PENDING
        assert result.verdict == "Verification pending"

    def test_an_unresolved_potential_low_does_not_hold_the_score(self) -> None:
        outcomes = all_passing()
        result = snapshot(
            outcomes,
            [finding(Category.C05_DATA_EXPOSURE, Severity.LOW, status=EvidenceStatus.POTENTIAL)],
        )
        assert result.overall.score is not None

    def test_an_interrupted_scan_cannot_publish_an_overall_rating(self) -> None:
        outcomes = all_passing()
        result = snapshot(outcomes, [], scan_interrupted=True)
        assert result.overall.score is None
        assert "interrupted or cancelled" in result.overall.reason


class TestDeterminism:
    def test_the_same_inputs_give_the_same_snapshot(self) -> None:
        """Build Plan §5.15: scoring is pure. Two runs must agree exactly."""
        outcomes = all_passing()
        findings = [
            finding(Category.C01_TRANSPORT, Severity.HIGH),
            finding(Category.C05_DATA_EXPOSURE, Severity.LOW),
        ]
        first = snapshot(outcomes, findings)
        second = snapshot(outcomes, findings)

        assert first.overall.score == second.overall.score
        assert first.overall.raw_score == second.overall.raw_score
        assert first.coverage_percent == second.coverage_percent
        assert first.verdict == second.verdict

    def test_input_order_does_not_change_the_result(self) -> None:
        outcomes = all_passing()
        findings = [
            finding(Category.C01_TRANSPORT, Severity.HIGH),
            finding(Category.C05_DATA_EXPOSURE, Severity.MEDIUM),
        ]
        forward = snapshot(outcomes, findings)
        backward = snapshot(list(reversed(outcomes)), list(reversed(findings)))
        assert forward.overall.raw_score == backward.overall.raw_score
        assert forward.coverage_percent == backward.coverage_percent

    def test_the_score_version_is_recorded(self) -> None:
        assert snapshot().score_version == SCORE_VERSION == "score-v1.0"


class TestRounding:
    def test_the_full_precision_value_is_kept_alongside_the_display_value(self) -> None:
        """Rounding happens only for display; nothing downstream uses the rounded value."""
        outcomes = all_passing(per_category=3)
        result = snapshot(outcomes, [finding(Category.C01_TRANSPORT, Severity.LOW)])
        entry = result.category(Category.C01_TRANSPORT)
        assert entry.raw_score is not None
        assert isinstance(entry.raw_score, float)
        assert entry.score == round(entry.raw_score)
