"""Synthetic driver protocol tests, never deployed scan evidence."""

import hashlib
import json
from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4

import pytest
from scripts import verify_session_expiry_lab as driver
from tests.unit.test_session_expiry import expiry_record


def fixture(variant="fixed"):
    service = driver.SERVICES[variant]
    scope = {
        "id": str(uuid4()),
        "origin": driver.LAB_BINDINGS[service],
        "lab_binding": {"service": service},
    }
    frozen = driver.configuration(scope, "encrypted-synthetic-reference")
    record = expiry_record()
    if variant == "bad":
        for replay in record["expiry_replays"]:
            replay.update(
                replay_probe_status=200,
                replay_identity="student",
                replay_denial_observed=False,
                replay_denial=None,
            )
    artifacts = [
        {
            "source": "expansion",
            "kind": "identity_observation",
            "data": record,
            "evidence_ref": "synthetic-stored-1",
            "run_id": "synthetic-run",
        }
    ]
    metadata = [
        {"id": "synthetic-stored-1", "trusted": True, "producer": "reviewed_expansion_capture"}
    ]
    status = "confirmed_issue" if variant == "bad" else "pass"
    report = {
        "profile": "staging-stateful-v1",
        "check_outcomes": [
            {
                "check_id": driver.CONTROL,
                "status": status,
                "required_instances": [driver.INSTANCE],
                "completed_instances": [driver.INSTANCE],
                "incomplete_reasons": [],
                "evidence_refs": ["synthetic-stored-1"],
            }
        ],
        "findings": (
            [
                {
                    "check_id": driver.CONTROL,
                    "evidence_status": "confirmed",
                    "evidence_refs": ["synthetic-stored-1"],
                }
            ]
            if variant == "bad"
            else []
        ),
        "assessment_summary": {
            "checks": [{"check_id": driver.CONTROL, "required": 1, "completed": 1}]
        },
    }
    server_proof = {
        "server_ttl_seconds": 1,
        "sessions": [
            {
                "cookie_hash": record["replayed_cookie_hash"],
                "expired_probe_count": 2,
                "server_age_seconds": 1.01,
            }
        ],
    }
    return scope, frozen, report, metadata, artifacts, server_proof


@pytest.mark.parametrize("variant", ["bad", "fixed"])
def test_driver_recomputes_expiry_and_requires_server_cookie_receipts(variant):
    _, frozen, report, metadata, artifacts, server = fixture(variant)
    record = driver.verify_report(
        report, driver.CONTROL, metadata, artifacts, frozen, variant=variant, server_proof=server
    )
    assert record == artifacts[0]["data"]


@pytest.mark.parametrize(
    "tamper",
    [
        "untrusted",
        "wrong_producer",
        "missing_replay",
        "wrong_hash",
        "insufficient_wait",
        "wrong_status",
        "false_worker_verdict",
        "missing_server_receipt",
        "wrong_server_cookie",
        "wrong_server_ttl",
        "wrong_report",
        "missing_report_instance",
    ],
)
def test_driver_rejects_unproven_expiry(tamper):
    _, frozen, report, metadata, artifacts, server = fixture()
    record = artifacts[0]["data"]
    if tamper == "untrusted":
        metadata[0]["trusted"] = False
    elif tamper == "wrong_producer":
        metadata[0]["producer"] = "local-test"
    elif tamper == "missing_replay":
        record["expiry_replays"].pop()
    elif tamper == "wrong_hash":
        record["replayed_cookie_hash"] = "c" * 64
    elif tamper == "insufficient_wait":
        record["expiry_waited_seconds"] = 0.99
    elif tamper == "wrong_status":
        record["expiry_replays"][0]["replay_probe_status"] = 500
    elif tamper == "false_worker_verdict":
        artifacts[0]["kind"] = "session_observation"
        record["state"] = "pass"
    elif tamper == "missing_server_receipt":
        server["sessions"][0]["expired_probe_count"] = 1
    elif tamper == "wrong_server_cookie":
        server["sessions"][0]["cookie_hash"] = "c" * 64
    elif tamper == "wrong_server_ttl":
        server["server_ttl_seconds"] = 5
    elif tamper == "wrong_report":
        report["check_outcomes"][0]["status"] = "confirmed_issue"
    else:
        report["check_outcomes"][0]["completed_instances"] = []
    with pytest.raises(AssertionError):
        driver.verify_report(
            report,
            driver.CONTROL,
            metadata,
            artifacts,
            frozen,
            variant="fixed",
            server_proof=server,
        )


@pytest.mark.parametrize("change", ["origin", "service", "port"])
def test_driver_cannot_select_a_customer_or_unbound_target(change):
    scope, *_ = fixture()
    if change == "origin":
        scope["origin"] = "https://customer.invalid"
    elif change == "service":
        scope["lab_binding"]["service"] = "customer"
    else:
        scope["origin"] = scope["origin"].replace(":8080", ":8081")
    with pytest.raises(ValueError):
        driver.configuration(scope, "reference")


def saved_gate():
    scope, frozen, *_ = fixture()
    scan_id, config_id = str(uuid4()), str(uuid4())
    digest = hashlib.sha256(
        json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    receipt = {
        "variant": "fixed",
        "scan_id": scan_id,
        "configuration_id": config_id,
        "configuration_hash": digest,
        "scope_version_id": scope["id"],
        "verified": False,
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
    gate = driver.Gate(None, None, 60)
    gate.get = lambda path: SimpleNamespace(json=lambda: responses[path])
    return gate, responses, receipt


def test_saved_driver_rejects_immutable_configuration_change():
    gate, responses, receipt = saved_gate()
    config = responses[f"/api/assessments/configurations/{receipt['configuration_id']}"]
    config["configuration"]["session_policies"][0]["expiry_after_seconds"] = 2
    with pytest.raises(AssertionError):
        gate.saved_configuration(receipt)


def test_saved_driver_rejects_changed_receipt_hash():
    gate, _, receipt = saved_gate()
    with pytest.raises(AssertionError):
        gate.saved_configuration({**receipt, "configuration_hash": "0" * 64})


def test_resume_revalidates_saved_scan_without_new_scan(monkeypatch, tmp_path):
    import sys

    gate, responses, receipt = saved_gate()
    original = deepcopy(receipt)
    (tmp_path / "receipts.json").write_text(json.dumps([receipt]))
    verified = []

    class ResumeGate:
        def __init__(self, *_):
            pass

        def post(self, path, _body):
            assert path == "/api/auth/login", "resume must not create another scan"
            return {}

        def saved_configuration(self, saved):
            assert saved == original
            return gate.saved_configuration(saved)

        def verify(self, saved, frozen):
            verified.append(saved["scan_id"])
            assert (
                frozen
                == responses[f"/api/assessments/configurations/{saved['configuration_id']}"][
                    "configuration"
                ]
            )
            return {**saved, "verified": True}

    monkeypatch.setattr(driver, "Gate", ResumeGate)
    monkeypatch.setattr(
        driver,
        "Settings",
        lambda: SimpleNamespace(
            operator_username="synthetic-operator",
            operator_password=SimpleNamespace(get_secret_value=lambda: "synthetic-secret"),
        ),
    )
    monkeypatch.setattr(
        sys, "argv", ["gate", "--output", str(tmp_path), "--resume", "--variants", "fixed"]
    )
    driver.main()
    assert verified == [receipt["scan_id"]]
