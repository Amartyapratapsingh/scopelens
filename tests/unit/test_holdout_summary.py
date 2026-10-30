"""Incomplete or different trials cannot earn summary qualification."""

import json

from evaluation.metrics import metrics
from evaluation.run_holdout import PLAN
from evaluation.summarize_holdout import FAMILIES, summarize


def trial(tmp_path, repeat, mode):
    result = {
        "freeze": {
            "repeat": repeat,
            "mode": mode,
            **{
                key: "same"
                for key in (
                    "candidate_commit",
                    "evaluator_commit",
                    "stack_lock_helper_sha256",
                    "candidate_fingerprint",
                    "manifest_sha256",
                    "oracle_sha256",
                    "model_routing",
                    "model_call_ceiling",
                    "model_cost_ceiling",
                    "fixture_artifacts",
                    "fixture_configuration_sha256",
                    "evaluator_sha256",
                )
            },
        },
        "cases": [],
        "candidate_changed": False,
        "supplemental_case_ids": [],
        "qualification": {
            "families": {
                family: {
                    "qualified": True,
                    "reasons": [],
                    "samples": {"positive": 30, "negative": 60, "groups": 3},
                    **metrics(["TP"] * 30 + ["TN"] * 60),
                }
                for family in FAMILIES
            }
        },
        "labelled_condition_metrics": {family: metrics([]) for family in FAMILIES},
        "scans": {},
        "failure_cases": [],
        "unmatched_findings": [],
    }
    directory = tmp_path / f"repeat-{repeat}-{mode}"
    directory.mkdir()
    path = directory / "result.json"
    path.write_text(json.dumps(result))
    return result, path


def test_missing_trials_never_qualify(tmp_path):
    trial(tmp_path, *PLAN[0])
    result = summarize(tmp_path)
    assert not result["complete"] and not result["passed"]
    assert len(result["missing_trials"]) == 5
    assert result["qualified_families_in_all_trials"] == []


def test_freeze_change_invalidates_comparison(tmp_path):
    for repeat, mode in PLAN:
        result, path = trial(tmp_path, repeat, mode)
    result["freeze"]["candidate_commit"] = "different"
    path.write_text(json.dumps(result))
    summary = summarize(tmp_path)
    assert summary["complete"]
    assert not summary["same_frozen_candidate_and_cases"]
    assert not summary["passed"]


def test_one_failed_family_is_not_hidden_by_repeats(tmp_path):
    for repeat, mode in PLAN:
        result, path = trial(tmp_path, repeat, mode)
    result["qualification"]["families"]["xss"]["qualified"] = False
    result["qualification"]["families"]["xss"]["reasons"] = ["recall threshold not met"]
    path.write_text(json.dumps(result))
    summary = summarize(tmp_path)
    assert summary["complete"] and summary["same_frozen_candidate_and_cases"]
    assert not summary["passed"]
    assert "xss" not in summary["qualified_families_in_all_trials"]
    assert summary["trials"][0]["families"]["sql"]["independent"]["counts"] == {
        "TP": 30,
        "FP": 0,
        "FN": 0,
        "TN": 60,
        "A-": 0,
    }
