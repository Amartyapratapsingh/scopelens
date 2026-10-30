"""Case coverage needs registered active capture provenance, even for negatives."""

import pytest
from evaluation.run_holdout import ROOT, measure, sha


@pytest.mark.parametrize("provenance", ["active", "generic_browser", "wrong_source"])
def test_negative_conclusion_requires_actual_active_producer(provenance):
    case = {
        "id": "provenance-fixture",
        "family": "xss",
        "route": "/fixture",
        "target": "target",
        "check_id": "SL-C03-XSS-01",
        "label": "fixed",
        "scenario_group": "independent-fixture",
    }
    protocol = {
        "partition": "development",
        "frozen_before_run": True,
        "contaminated": True,
        "cases": [case],
    }
    captures = [
        {
            "nonce": value * 32,
            "status": 200,
            "response_url_matches": True,
            "marker_present": False,
            "nonce_matches": False,
        }
        for value in "abc"
    ]
    artifact = {
        "payload": {
            "data": {"kind": "xss", "route": "/fixture", "reviewed": True, "captures": captures}
        },
        "metadata": {
            "producer": "reviewed_active_capture",
            "producer_hash": sha(ROOT / "backend/scopelens/browser/active.py"),
        },
    }
    if provenance == "generic_browser":
        artifact["metadata"]["producer"] = "reviewed_browser_capture"
    elif provenance == "wrong_source":
        artifact["metadata"]["producer_hash"] = "0" * 64
    report = {
        "findings": [],
        "check_outcomes": [
            {"check_id": case["check_id"], "status": "pass", "completed_instances": ["/fixture"]}
        ],
    }
    result = measure(
        protocol,
        {"target": report},
        {"target": {"capture": artifact}},
        "candidate",
        "candidate",
        "manifest",
        oracle=[{**case, "curator_ref": {"path": "test-label-only"}}],
        curator_ref="test-label-only",
    )
    counts = result["labelled_condition_metrics"]["xss"]["counts"]
    assert counts == ({"TN": 1} if provenance == "active" else {"A-": 1})
    assert result["qualification"]["partition"] == "development"
    assert not result["qualification"]["passed"]
    assert (
        "Independent untouched held-out curation and pre-run freeze not established"
        in result["qualification"]["families"]["xss"]["reasons"]
    )
