"""Resume gates must bind historical scans without repeating mutations."""

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from labs.academic_workflows.scenarios import LAB_BINDINGS
from scripts.verify_academic_workflows_lab import configuration, saved_configuration


def saved_gate(case="marks"):
    scope = {
        "id": str(uuid4()),
        "origin": LAB_BINDINGS["labs-academic-a"],
        "lab_binding": {"service": "labs-academic-a"},
    }
    scan_id, config_id = str(uuid4()), str(uuid4())
    frozen = configuration(scope, "encrypted-synthetic-reference", case)
    digest = hashlib.sha256(
        json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    receipt = {
        "configuration_id": config_id,
        "configuration_hash": digest,
        "scope_version_id": scope["id"],
    }
    responses = {
        f"/api/scans/{scan_id}": {
            "scope_version_id": scope["id"],
            "target_origin": scope["origin"],
        },
        f"/api/academic/scans/{scan_id}/readiness": {
            "configuration_id": config_id,
            "configuration_hash": digest,
            "scope_version_id": scope["id"],
        },
        f"/api/assessments/configurations/{config_id}": {
            "id": config_id,
            "content_hash": digest,
            "configuration": frozen,
        },
        f"/api/scopes/{scope['id']}": scope,
    }
    gate = SimpleNamespace(get=lambda path: SimpleNamespace(json=lambda: responses[path]))
    return gate, responses, scan_id, receipt


def test_saved_scan_rejects_changed_immutable_configuration():
    gate, responses, scan_id, receipt = saved_gate()
    responses[f"/api/assessments/configurations/{receipt['configuration_id']}"]["configuration"][
        "workflows"
    ][0]["forbidden_after"]["value"] = 98
    with pytest.raises(AssertionError):
        saved_configuration(gate, scan_id, "marks", "bad", receipt)


def test_saved_scan_rejects_different_exact_academic_case():
    gate, _, scan_id, receipt = saved_gate("attendance")
    with pytest.raises(AssertionError, match="exact academic lab recipe"):
        saved_configuration(gate, scan_id, "marks", "bad", receipt)


def test_saved_receipt_hash_cannot_be_replaced_by_valid_other_hash():
    gate, _, scan_id, receipt = saved_gate()
    changed = {**receipt, "configuration_hash": "0" * 64}
    with pytest.raises(AssertionError, match="saved configuration hash changed"):
        saved_configuration(gate, scan_id, "marks", "bad", changed)


def test_expired_saved_case_preserves_original_declared_expiry():
    gate, responses, scan_id, receipt = saved_gate("expired")
    config = responses[f"/api/assessments/configurations/{receipt['configuration_id']}"]
    original = copy.deepcopy(config)
    scope, returned = saved_configuration(gate, scan_id, "expired", "bad", receipt)
    assert scope["id"] == receipt["scope_version_id"]
    assert returned == original
    assert datetime.fromisoformat(returned["configuration"]["identities"][1]["expires_at"]) < (
        datetime.now(UTC) - timedelta(microseconds=1)
    )


def run_resume(monkeypatch, tmp_path, case, *, refresh=False):
    import sys

    from scripts import verify_academic_workflows_lab as driver

    gate, responses, scan_id, binding = saved_gate(case)
    receipt = {
        **binding,
        "case": case,
        "variant": "bad",
        "scan_id": scan_id,
        "controls": {"control": "pass"},
        "finding_ids": [],
    }
    receipts = [receipt]
    (tmp_path / "receipts.json").write_text(json.dumps(receipts))
    (tmp_path / f"{case}-bad-scan-id.txt").write_text(scan_id)
    if refresh:
        # The refresh has queued a new scan, but no verified receipt yet.
        original_id = str(uuid4())
        receipts[0]["scan_id"] = original_id
        (tmp_path / "receipts.json").write_text(json.dumps(receipts))
        (tmp_path / f"{case}-bad-pre-repair-scan-id.txt").write_text(original_id)
    observed = []

    class ResumeGate:
        def __init__(self, *_):
            pass

        def get(self, path):
            return gate.get(path)

        def post(self, path, _body):
            assert path == "/api/auth/login", "resume must not queue another mutation or scan"
            return {}

        def verify(self, observed_id, frozen, _label, **_):
            observed.append(observed_id)
            assert (
                frozen
                == responses[f"/api/assessments/configurations/{binding['configuration_id']}"][
                    "configuration"
                ]
            )
            return {}, {"findings": []}, receipt["controls"]

    monkeypatch.setattr(driver, "Gate", ResumeGate)
    monkeypatch.setattr(
        driver,
        "Settings",
        lambda: SimpleNamespace(
            operator_username="synthetic-operator",
            operator_password=SimpleNamespace(get_secret_value=lambda: "synthetic-secret"),
        ),
    )
    arguments = [
        "gate",
        "--output",
        str(tmp_path),
        "--resume",
        "--cases",
        case,
        "--variants",
        "bad",
    ]
    if refresh:
        arguments.append("--refresh-identities")
    monkeypatch.setattr(sys, "argv", arguments)
    driver.main()
    return scan_id, observed


def test_completed_resume_revalidates_saved_scan_without_execution(monkeypatch, tmp_path):
    scan_id, observed = run_resume(monkeypatch, tmp_path, "marks")
    assert observed == [scan_id]


def test_interrupted_identity_refresh_resumes_already_queued_scan(monkeypatch, tmp_path):
    scan_id, observed = run_resume(monkeypatch, tmp_path, "identities", refresh=True)
    assert observed == [scan_id]
    receipt = json.loads((tmp_path / "receipts.json").read_text())[0]
    assert receipt["scan_id"] == scan_id


def test_completed_fixed_retest_resumes_saved_scan_without_new_mutation(tmp_path):
    from scripts.verify_academic_workflows_lab import fixed_retests

    original_gate, original_responses, original_id, original_binding = saved_gate()
    _, retest_responses, retest_id, retest_binding = saved_gate()
    finding_id = str(uuid4())
    original = {
        **original_binding,
        "scan_id": original_id,
        "case": "marks",
        "variant": "bad",
        "finding_ids": [finding_id],
    }
    renewal = {
        **retest_binding,
        "original_configuration_id": original_binding["configuration_id"],
        "original_configuration_hash": original_binding["configuration_hash"],
    }
    responses = {**original_responses, **retest_responses}
    responses[f"/api/findings/{finding_id}"] = {
        "check_id": "SL-C11-WORKFLOW-01",
        "status": "resolved",
        "retest_state": "fixed",
    }
    responses[f"/api/scans/{original_id}/export.json"] = {"findings": [{"id": finding_id}]}
    (tmp_path / "fixed-retests.json").write_text(
        json.dumps(
            [
                {"finding_id": finding_id, "scan_id": retest_id},
            ]
        )
    )
    (tmp_path / "fixed-retest-authorizations.json").write_text(json.dumps({original_id: renewal}))
    verified = []

    def verify(scan_id, _frozen, _label, **_):
        verified.append(scan_id)
        return (
            {"scope_version_id": retest_binding["scope_version_id"]},
            {},
            {
                "SL-C11-WORKFLOW-01": "pass",
            },
        )

    gate = SimpleNamespace(
        output=tmp_path,
        get=lambda path: SimpleNamespace(json=lambda: responses[path]),
        verify=verify,
    )
    fixed_retests(gate, [original])
    assert verified == [retest_id]
    result = json.loads((tmp_path / "fixed-retests.json").read_text())
    assert len(result) == 1 and result[0]["scan_id"] == retest_id
    assert (
        original_gate.get(
            f"/api/assessments/configurations/{original_binding['configuration_id']}"
        ).json()["content_hash"]
        == result[0]["original_configuration_hash"]
    )
