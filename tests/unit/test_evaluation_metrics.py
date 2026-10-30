from evaluation.metrics import classify, metrics, wilson


def test_abstention_never_inflates_fpr_or_negative_coverage():
    m = metrics(["TP", "FN", "TN", "FP", "A-", "A-"])
    assert m["recall"]["value"] == 0.5
    assert m["precision"]["value"] == 0.5
    assert m["false_positive_rate"]["value"] == 0.5
    assert m["negative_conclusive_coverage"]["value"] == 0.5


def test_no_confirmations_is_not_perfect_precision():
    assert metrics(["TN"])["precision"]["value"] is None
    assert metrics([])["recall"]["value"] is None
    assert wilson(0, 0) is None


def test_lost_positive_is_false_negative_and_negative_is_abstention():
    assert classify("vulnerable", confirmed=False, conclusive=False, proof_valid=False) == "FN"
    assert classify("fixed", confirmed=False, conclusive=False, proof_valid=False) == "A-"
    assert classify("vulnerable", confirmed=True, conclusive=True, proof_valid=False) == "FN"
    assert classify("fixed", confirmed=True, conclusive=True, proof_valid=False) == "FP"


def test_intervals_have_uncertainty_even_for_perfect_small_samples():
    low, high = wilson(3, 3)
    assert 0 < low < 0.9 and 0.99 < high <= 1


def test_report_evidence_ids_alone_do_not_count_as_proof():
    from evaluation.metrics import evaluate

    manifest = {
        "partition": "development",
        "cases": [
            {
                "id": "one",
                "target": "bad",
                "check_id": "active",
                "route": "/",
                "label": "vulnerable",
                "family": "xss",
            }
        ],
    }
    report = {
        "findings": [
            {
                "check_id": "active",
                "locations": [{"route": "/"}],
                "evidence_status": "confirmed",
                "evidence_refs": ["invented"],
            }
        ]
    }
    assert evaluate(manifest, {"bad": report})["cases"][0]["verdict"] == "FN"


def test_perfect_development_results_do_not_pass_holdout_gate():
    from evaluation.run import release_gate

    manifest = {
        "partition": "development",
        "frozen_before_run": False,
        "cases": [{"family": "xss", "scenario_group": "one", "label": "vulnerable"}],
    }
    gate = release_gate(manifest, {"families": {"xss": metrics(["TP", "TN"])}})
    assert not gate["passed"]
    assert any("insufficient independent" in r for r in gate["reasons"])
