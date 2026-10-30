"""Public metadata must not upgrade inventory into proven scanner capability."""

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scopelens.api.dashboard import ScanSummary, scan_summary
from scopelens.domain.capabilities import canonical_sha256, plan_bindings
from scopelens.domain.enums import ProfileName
from scopelens.domain.registry import CheckRegistry, load_registry
from scopelens.writer.report import (
    _capabilities,
    _reach_summary,
    build_report,
    render_html,
    render_json,
)

PROFILE = "external-active-v2"


def frozen_registry():
    return load_registry(Path("checks_registry")).model_dump(mode="json")


def snapshot():
    base = measured_plan()
    bindings = plan_bindings(base, scan_id="scan", scope_version_id="scope", profile=PROFILE)
    return {
        "version": "capability-snapshot-v2",
        **bindings,
        "image_bindings": base["capability_expected_images"],
        "source_sha256": "a" * 64,
        "verification_ref": "private-measurement-ref",
        "measured_at": "2026-09-28T00:00:00Z",
        "installation_complete": True,
        "runtime_inventory_complete": True,
        "installed_tools": [
            {
                "name": "nuclei",
                "measured_version": "3.8.0",
                "verification_ref": "tool-evidence",
                "image_id": "sha256:" + "1" * 64,
                "binary_sha256": "2" * 64,
            }
        ],
        "runtime_controls": [],
        "qualification": {
            "version": "qualification-v2",
            "partition": "holdout",
            "verification_ref": "evaluation-ref",
            "candidate_fingerprint": "candidate",
            "manifest_sha256": "b" * 64,
            "registry_sha256": bindings["registry_sha256"],
            "image_binding_sha256": canonical_sha256(base["capability_expected_images"]),
            "curator_ref": "independent-curator",
            "frozen_before_run": True,
            "contaminated": False,
            "families": {"F01": {"qualified": True}, "F02": {"qualified": False}},
        },
    }


def measured_plan(snap=None):
    from scopelens.execution.capability_probe import PROBE_SHA256

    result = {
        "registry": frozen_registry(),
        "capability_candidate_fingerprint": "a" * 64,
        "capability_expected_images": [
            {
                "role": "kali",
                "image_id": "sha256:" + "1" * 64,
                "architecture": "arm64",
                "probe_sha256": PROBE_SHA256,
            }
        ],
        "capability_qualification_manifest_sha256": "b" * 64,
        "capability_qualification_verification_ref": "evaluation-ref",
        "capability_qualification_curator_ref": "independent-curator",
    }
    if snap is not None:
        result["capability_snapshot"] = snap
    return result


def test_inventory_does_not_establish_installed_executable_or_qualified():
    result = _capabilities({"registry": frozen_registry(), "templates": list(range(5000))}, PROFILE)
    for key in ("installed_tools", "executable_checks", "independently_qualified_families"):
        assert result[key]["count"] is None
        assert result[key]["evidence_state"] == "unknown"
    assert result["experimental_controls"]["count"] > 0


def test_measured_execution_requires_enabled_supported_admitted_and_prerequisites():
    registry = frozen_registry()
    enabled = [
        entry.model_dump(mode="json")
        for entry in CheckRegistry.model_validate(registry).supported_for_profile(
            ProfileName(PROFILE)
        )
    ]
    snap = snapshot()
    for index, entry in enumerate(enabled):
        snap["runtime_controls"].append(
            {
                "control_id": entry["id"],
                "runtime_supported": index == 0,
                "authority_admitted": True,
                "prerequisites_satisfied": True,
                "verification_ref": "run-evidence",
            }
        )
    snap["runtime_controls"][1]["prerequisites_satisfied"] = False
    snap["runtime_controls"][2]["authority_admitted"] = False
    result = _capabilities(measured_plan(snap), PROFILE, scan_id="scan", scope_version_id="scope")
    assert result["installed_tools"]["names"] == ["nuclei"]
    assert result["executable_checks"]["names"] == [enabled[0]["id"]]
    assert result["independently_qualified_families"]["count"] is None
    assert result["experimental_controls"]["count"] >= 1


@pytest.mark.parametrize(
    "mutation", ["wrong_profile", "missing_provenance", "development", "contaminated", "no_freeze"]
)
def test_unqualified_snapshot_does_not_publish_family_count(mutation):
    snap = snapshot()
    if mutation == "wrong_profile":
        snap["profile"] = "staging-stateful-v1"
    elif mutation == "missing_provenance":
        snap.pop("verification_ref")
    elif mutation == "development":
        snap["qualification"]["partition"] = "development"
    elif mutation == "contaminated":
        snap["qualification"]["contaminated"] = True
    else:
        snap["qualification"]["frozen_before_run"] = False
    result = _capabilities(measured_plan(snap), PROFILE, scan_id="scan", scope_version_id="scope")
    assert result["independently_qualified_families"]["count"] is None


def test_observed_tool_count_is_separate_and_not_tested_does_not_count():
    result = _capabilities(
        {
            "scanner_results": [
                {"tool": "nuclei", "version": "3", "output_hash": "hash", "state": "partial"},
                {"tool": "nuclei", "version": "3", "output_hash": "hash", "state": "completed"},
                {"tool": "zap", "version": "2", "output_hash": "hash", "state": "not_tested"},
            ]
        },
        PROFILE,
    )
    assert result["observed_tools"]["count"] == 1
    assert result["installed_tools"]["count"] is None


def plan():
    return {
        "request_catalogue": {
            "templates": [
                {
                    "id": "t1",
                    "role_id": "alice",
                    "path": "/profile?token=secret-query",
                    "inputs": [{"baseline_value": "secret-input"}],
                },
                {"id": "t2", "role_id": "alice", "path": "/unplanned", "inputs": []},
            ],
            "gaps": [{"reason": "secret-error"}],
        },
        "input_assessment_plan": {
            "tasks": [
                {"id": f"task-{n}", "control_id": "control", "template_id": "t1", "state": state}
                for n, state in enumerate(["ready", "ready", "blocked"])
            ]
        },
        "expansion_config": {
            "identities": [
                {"id": "alice", "role": "user", "login": "secret-login"},
                {"id": "bob", "role": "user"},
            ]
        },
    }


def outcome(**changes):
    value = {
        "check_id": "control",
        "status": "confirmed_issue",
        "required_instances": ["task-0", "task-1", "task-2"],
        "completed_instances": ["task-0", "unplanned-task"],
        "evidence_refs": ["trusted-ref"],
        "incomplete_reasons": ["missing"],
    }
    return value | changes


def test_reach_keeps_missing_planned_instances_ignores_extra_completed_and_secrets():
    data = plan()
    result = _reach_summary(data, [outcome()], PROFILE, [{"category": "C12"}])
    assert (
        result["planned"],
        result["fully_assessed"],
        result["blocked"],
        result["unassessed"],
    ) == (3, 1, 1, 1)
    assert result["discovered"] == {"routes": 2, "templates": 2, "inputs": 1, "roles": 1}
    assert result["groups"][0]["route"] == "/profile"
    assert result["out_of_profile_categories"] == ["C12"]
    assert {gap["kind"] for gap in result["gaps"]} == {"role", "route", "completion", "discovery"}
    assert "secret-" not in render_json(result)
    assert "unplanned-task" not in render_json(result)
    assert result == _reach_summary(deepcopy(data), [outcome()], PROFILE, [{"category": "C12"}])


def test_missing_entire_outcome_stays_in_denominator_and_blocked():
    result = _reach_summary(plan(), [], PROFILE, [])
    assert (
        result["planned"],
        result["fully_assessed"],
        result["unassessed"],
        result["blocked"],
    ) == (3, 0, 2, 1)


def test_missing_frozen_registry_controls_cannot_disappear():
    registry = frozen_registry()
    result = _reach_summary({"registry": registry}, [], PROFILE, [])
    assert result["planned"] > 0
    assert result["unassessed"] == result["planned"]
    assert result["fully_assessed"] == 0


@pytest.mark.parametrize(
    "status,field", [("error", "error"), ("blocked", "blocked"), ("inconclusive", "unassessed")]
)
def test_aggregate_failure_never_counts_completed_as_fully_assessed(status, field):
    result = _reach_summary({}, [outcome(status=status)], PROFILE, [])
    assert result["fully_assessed"] == 0
    assert result[field] == 3


def test_na_requires_evidence_and_is_not_pass():
    result = _reach_summary(
        {},
        [outcome(status="not_applicable", na_reason="absent", na_evidence_ref="ref")],
        PROFILE,
        [],
    )
    assert result["not_applicable"] == 3 and result["fully_assessed"] == 0
    unproven = _reach_summary({}, [outcome(status="not_applicable")], PROFILE, [])
    assert unproven["unassessed"] == 3


def fake_report(data):
    session = Mock()
    session.get.return_value = None
    query = session.query.return_value
    query.filter.return_value.all.return_value = []
    query.filter.return_value.order_by.return_value.first.return_value = None
    scan = SimpleNamespace(
        id="scan",
        profile=PROFILE,
        target_origin="https://lab.invalid",
        status="completed_partial",
        status_reason=None,
        created_at=datetime.now(UTC),
        started_at=None,
        finished_at=None,
        scope_version_id="scope",
        assessment_plan=data,
    )
    return build_report(session=session, scan=scan), scan


def test_json_html_and_typed_summary_share_metadata_without_private_plan(monkeypatch):
    data = plan()
    data["capability_snapshot"] = snapshot()
    data["capability_candidate_fingerprint"] = "private-candidate"
    data["capability_expected_images"] = [{"private-image": "private-image-ref"}]
    data["capability_execution_plan"] = {"admitted_control_ids": ["private-control"]}
    data["capability_qualification_curator_ref"] = "private-curator"
    data["request_catalogue"]["templates"][0]["path"] = "/<img>?secret-query"
    report, scan = fake_report(data)
    assert "capability_snapshot" not in report["assessment_plan"]
    assert "request_catalogue" not in report["assessment_plan"]
    assert "input_assessment_plan" not in report["assessment_plan"]
    exported, html = render_json(report), render_html(report)
    for secret in (
        "secret-query",
        "secret-input",
        "secret-login",
        "private-measurement-ref",
        "private-candidate",
        "private-image-ref",
        "private-control",
        "private-curator",
    ):
        assert secret not in exported and secret not in html
    assert "/&lt;img&gt;" in html and "/<img>" not in html
    monkeypatch.setattr("scopelens.api.dashboard._owned_scan", lambda *args: scan)
    monkeypatch.setattr("scopelens.api.dashboard._report", lambda *args: report)
    summary = scan_summary("scan", None, None).model_dump(mode="json")
    assert summary["capabilities"] == report["capabilities"]
    assert summary["reach"] == report["reach"]
    assert "capabilities" in ScanSummary.model_json_schema()["properties"]


def test_old_report_without_additive_fields_still_renders():
    report, _ = fake_report({})
    report.pop("capabilities")
    report.pop("reach")
    assert "ScopeLens assessment report" in render_html(report)


def test_revision_catalogues_and_execution_claims_remain_private():
    data = plan()
    data["assessment_plan_revisions"] = [
        {
            "catalogue": {
                "templates": [
                    {
                        "inputs": [
                            {
                                "baseline_value": "revision-secret-value",
                                "secret_ref": "revision-secret-reference",
                            }
                        ],
                    }
                ]
            },
            "plan": {"tasks": [{"input_key": "private-revision-input"}]},
        }
    ]
    data["assessment_execution_claims"] = {
        "private-claim-key": {"request": {"body": "claim-secret-value"}},
    }
    report, _ = fake_report(data)
    assert "assessment_plan_revisions" not in report["assessment_plan"]
    assert "assessment_execution_claims" not in report["assessment_plan"]
    for exported in (render_json(report), render_html(report)):
        for secret in (
            "revision-secret-value",
            "revision-secret-reference",
            "private-revision-input",
            "private-claim-key",
            "claim-secret-value",
        ):
            assert secret not in exported
    # Safe current-plan reach remains available, rather than dropping all assessment metadata.
    assert report["reach"]["planned"] == 3


@pytest.mark.parametrize("field", ["curator_ref", "manifest_sha256", "version"])
def test_qualification_requires_each_declared_provenance_field(field):
    snap = snapshot()
    snap["qualification"].pop(field)
    result = _capabilities(measured_plan(snap), PROFILE, scan_id="scan", scope_version_id="scope")
    family_count = result["independently_qualified_families"]
    assert family_count["count"] is None
    assert family_count["names"] == [] and family_count["evidence_state"] == "unknown"
    assert result["installed_tools"]["count"] == 1


@pytest.mark.parametrize(
    "families",
    [
        None,
        [],
        "invalid",
        {"F01": None},
        {"F01": True},
        {"F01": []},
        {"F01": {}},
        {"F01": {"qualified": "true"}},
        {"F01": {"qualified": 1}},
    ],
)
def test_malformed_family_results_are_unknown_without_crashing(families):
    snap = snapshot()
    snap["qualification"]["families"] = families
    result = _capabilities(measured_plan(snap), PROFILE, scan_id="scan", scope_version_id="scope")
    assert result["independently_qualified_families"]["count"] is None
    assert result["independently_qualified_families"]["names"] == []
    assert result["installed_tools"]["count"] == 1


def test_malformed_qualification_manifest_hash_is_unknown():
    snap = snapshot()
    snap["qualification"]["manifest_sha256"] = "not-a-digest"
    result = _capabilities({"capability_snapshot": snap}, PROFILE)
    assert result["independently_qualified_families"]["count"] is None
