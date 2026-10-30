from evaluation.expansion import (
    BudgetedResult,
    MeasuredCase,
    QualificationRun,
    capability_inventory,
    compare_runs,
    qualify,
)


def case(n, *, family="sql", vulnerable=True, confirmed=True):
    return MeasuredCase(
        id=str(n),
        family=family,
        scenario_group=str(n % 3),
        target="lab",
        check_id=family,
        route="/case/" + str(n),
        label="vulnerable" if vulnerable else "fixed",
        confirmed=confirmed,
        conclusive=True,
        proof_valid=confirmed and vulnerable,
        proof_replay_ref="independent-test-replay" if confirmed and vulnerable else None,
    )


def test_each_declared_family_must_qualify_and_development_never_qualifies():
    cases = tuple(case(n, vulnerable=n < 30, confirmed=n < 30) for n in range(90))
    run = QualificationRun(
        partition="holdout",
        frozen_before_run=True,
        contaminated=False,
        curator_ref="test-only-curator",
        candidate_fingerprint="same",
        frozen_candidate_fingerprint="same",
        manifest_sha256="testmanifest",
        declared_families=("sql", "unmeasured"),
        cases=cases,
    )
    result = qualify(run)
    assert result["families"]["sql"]["qualified"]
    assert not result["families"]["unmeasured"]["qualified"]
    assert not result["passed"]
    assert not qualify(run.model_copy(update={"partition": "validation"}))["families"]["sql"][
        "qualified"
    ]
    assert result["families"]["sql"]["precision"]["interval_95"]


def budgeted(cases, **changes):
    return BudgetedResult(
        candidate_fingerprint="code",
        scope_fingerprint="scope",
        fixture_fingerprint="fixture",
        profile="external-active-v2",
        ceiling_requests=100,
        ceiling_seconds=60,
        ceiling_cost=1,
        requests=10,
        seconds=2,
        cost=0,
        cases=cases,
        **changes,
    )


def test_equal_budget_comparison_separates_gains_from_false_positives():
    baseline = budgeted((case(1, confirmed=False), case(2, vulnerable=False, confirmed=False)))
    adaptive = budgeted((case(1), case(2, vulnerable=False, confirmed=True)))
    comparison = compare_runs(baseline, adaptive)
    assert comparison["comparable"]
    assert comparison["families"]["sql"]["additional_true_positives"] == 1
    assert comparison["families"]["sql"]["additional_false_positives"] == 1
    assert not compare_runs(baseline, adaptive.model_copy(update={"ceiling_requests": 101}))[
        "comparable"
    ]
    assert not compare_runs(baseline, adaptive.model_copy(update={"cost": None}))["comparable"]


def test_tool_installation_is_not_executable_or_qualified_family():
    result = capability_inventory(
        installed_tools=[
            {"name": "nuclei", "measured_version": "3.11.1", "verification_ref": "live-test"},
            {"name": "missing"},
        ],
        executable_control_ids=["a", "a", "b"],
        qualification={"families": {"sql": {"qualified": False}}},
    )
    assert result["installed_tools"]["count"] == 1
    assert result["executable_checks"]["count"] == 2
    assert result["independently_qualified_families"]["count"] == 0
