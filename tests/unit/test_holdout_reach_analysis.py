"""Saved-output reach analysis must not turn missing evidence into tested negatives."""

from evaluation.analyze_holdout_reach import reach

CASE = {"family": "xss", "route": "/r/opaque"}


def test_dispatch_evidence_takes_priority_over_missing_discovery():
    artifacts = {
        "ref": {"payload": {"kind": "xss", "route": CASE["route"], "captures": [{"status": 403}]}}
    }
    stage, _, details = reach(CASE, {"captures": [{"ref": "ref", "decision": None}]}, {}, artifacts)
    assert stage == "c" and details["http_statuses"] == [403]
    assert not details["discovered"]


def test_planned_probe_without_capture_is_unresolved():
    report = {"assessment_plan": {"conditional_probes": [{"kind": "xss", "path": CASE["route"]}]}}
    assert reach(CASE, {}, report, {})[0] == "unresolved"


def test_discovered_without_plan_differs_from_undiscovered():
    report = {"attack_surface": {"endpoints": [{"url": "http://fixture/r/opaque?input=redacted"}]}}
    assert reach(CASE, {}, report, {})[0] == "b"
    assert reach(CASE, {}, {}, {})[0] == "a"


def test_success_response_with_inconclusive_proof_remains_stage_d():
    artifacts = {
        "ref": {"payload": {"kind": "xss", "route": CASE["route"], "captures": [{"status": 200}]}}
    }
    stage, _, details = reach(CASE, {"captures": [{"ref": "ref", "decision": None}]}, {}, artifacts)
    assert stage == "d" and details["proof_decisions"] == [None]


def test_unusable_capture_provenance_is_not_called_undiscovered():
    artifacts = {
        "ref": {"payload": {"kind": "xss", "route": CASE["route"], "captures": [{"status": 200}]}}
    }
    assert reach(CASE, {}, {}, artifacts)[0] == "unresolved"


def test_aggregate_endpoint_count_is_not_a_discovery_record():
    artifacts = {"summary": {"payload": {"endpoints": 9, "states": 2}}}
    assert reach(CASE, {}, {}, artifacts)[0] == "a"
