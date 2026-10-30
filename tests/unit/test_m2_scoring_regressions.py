from tests.unit.test_scoring import all_passing, finding

from scopelens.domain.check import ProofResult
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as Outcome
from scopelens.scoring.score import CategoryState, score


def test_inconclusive_potential_does_not_earn_coverage():
    outcomes = all_passing()
    outcomes[0] = outcomes[0].model_copy(
        update={
            "status": Outcome.INCONCLUSIVE,
            "proof": ProofResult(satisfied=False, status=EvidenceStatus.POTENTIAL),
        }
    )
    s = score(outcomes=outcomes, findings=[], mandatory_controls=set())
    assert s.category(outcomes[0].category).coverage_percent == 0
    assert s.overall.score is None


def test_fully_na_category_removed_with_evidence():
    outcomes = all_passing()
    outcomes[0] = outcomes[0].model_copy(
        update={
            "status": Outcome.NOT_APPLICABLE,
            "na_reason": "observed absence",
            "na_evidence_ref": "e",
        }
    )
    s = score(outcomes=outcomes, findings=[], mandatory_controls={o.check_id for o in outcomes})
    assert s.category(outcomes[0].category).state == CategoryState.NOT_APPLICABLE
    assert s.overall.score == 100
    assert outcomes[0].category in s.overall.excluded_categories


def test_out_of_profile_serious_candidate_holds_overall():
    for category in (Category.C03_INJECTION, Category.C09_AUTHORIZATION):
        s = score(
            outcomes=all_passing(),
            findings=[finding(category, Severity.HIGH, status=EvidenceStatus.POTENTIAL)],
            mandatory_controls=set(),
        )
        assert s.overall.state == CategoryState.VERIFICATION_PENDING
        assert s.overall.score is None


def test_weights_and_missing_required_instances_are_used():
    outcomes = all_passing(per_category=2)
    outcomes[0] = outcomes[0].model_copy(
        update={"required_instances": ("/a", "/b"), "completed_instances": ("/a",)}
    )
    s = score(
        outcomes=outcomes,
        findings=[],
        mandatory_controls=set(),
        control_weights={outcomes[0].check_id: 9},
    )
    assert s.category(outcomes[0].category).coverage_percent == 10
    assert s.overall.score is None


def test_unevidenced_na_is_not_dropped():
    outcomes = [o.model_copy(update={"status": Outcome.NOT_APPLICABLE}) for o in all_passing()]
    assert score(outcomes=outcomes, findings=[], mandatory_controls=set()).overall.score is None


def test_exact_59_category_example():
    findings = [
        finding(Category.C01_TRANSPORT, s, root_cause=str(i))
        for i, s in enumerate((Severity.HIGH, Severity.LOW, Severity.LOW))
    ]
    s = score(outcomes=all_passing(), findings=findings, mandatory_controls=set())
    assert s.category(Category.C01_TRANSPORT).score == 59
