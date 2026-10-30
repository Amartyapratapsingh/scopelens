"""Offline contract tests; these fixtures do not execute ZAP or target a site."""

import json

import pytest
from pydantic import ValidationError

from scopelens.adapters import zap_active

HASH = "a" * 64


@pytest.fixture
def pin():
    return zap_active.ActiveRulePin(
        rule_id="40012",
        control_id="SL-C03-XSS-01",
        engine_version="fixture-only",
        engine_sha256=HASH,
        rule_config_sha256=HASH,
        allowed_values=("marker-one", "marker-two"),
        max_requests=2,
        deadline_seconds=5,
    )


@pytest.fixture
def task():
    return zap_active.ActiveRuleTask(
        scan_id="scan-fixture",
        task_id="task-fixture",
        input_id="input-fixture",
        rule_id="40012",
        url="https://owned.test:443/search?q=baseline&tenant=fixture",
        input_name="q",
        rule_config_sha256=HASH,
        max_requests=2,
        deadline_seconds=5,
    )


def report(*instances, rule="40012"):
    return json.dumps(
        {"site": [{"alerts": [{"pluginid": rule, "riskcode": "2", "instances": list(instances)}]}]}
    ).encode()


def test_admission_stays_blocked_without_broker_rule_gate(task, pin, monkeypatch):
    assert zap_active.active_admission(task).state == "blocked"
    monkeypatch.setitem(zap_active.REVIEWED_RULES, pin.rule_id, pin)
    result = zap_active.active_admission(task)
    assert result.state == "blocked"
    assert "broker" in result.reason
    assert result.task_sha256 and result.rule_config_sha256 == HASH
    expanded = task.model_copy(update={"max_requests": 3})
    assert zap_active.active_admission(expanded).state == "blocked"
    assert "limits" in zap_active.active_admission(expanded).reason


def test_exact_request_boundary_and_finite_reviewed_values(task, pin):
    valid = "https://owned.test/search?q=marker-one&tenant=fixture"
    assert task.accepts("GET", valid, b"", pin)
    for method, url, body in [
        ("POST", valid, b""),
        ("GET", valid, b"data"),
        ("GET", valid.replace("marker-one", "unreviewed"), b""),
        ("GET", valid.replace("tenant=fixture", "tenant=other"), b""),
        ("GET", valid + "&q=marker-two", b""),
        ("GET", valid.replace("/search", "/elsewhere"), b""),
        ("GET", valid.replace("owned.test", "elsewhere.test"), b""),
        ("GET", valid.replace("https://", "http://"), b""),
        ("GET", valid.replace("/search", "/%2e%2e/search"), b""),
    ]:
        assert not task.accepts(method, url, body, pin)


@pytest.mark.parametrize(
    "url",
    [
        "https://owned.test/search?q=a&q=b",
        "https://owned.test/search?tenant=a",
        "https://owned.test/%2e%2e/search?q=a",
        "https://user@owned.test/search?q=a",
        "https://owned.test/search?q=a#fragment",
    ],
)
def test_ambiguous_task_rejected(url):
    with pytest.raises(ValidationError):
        zap_active.ActiveRuleTask(
            scan_id="scan",
            task_id="task",
            input_id="input",
            rule_id="40012",
            url=url,
            input_name="q",
            rule_config_sha256=HASH,
            max_requests=1,
            deadline_seconds=1,
        )


def test_candidate_output_deduplicates_and_retains_provenance(task, pin):
    instance = {"uri": "https://owned.test/search?q=marker-one&tenant=fixture"}
    result = zap_active.normalize_active_report(task, pin, report(instance, instance))
    assert result.state == "completed"
    assert len(result.observations) == 1
    assert result.observations[0].status == "potential"
    assert result.observations[0].mapped_control == pin.control_id
    assert result.task_id == task.task_id and result.input_id == task.input_id
    assert result.output_sha256 == result.observations[0].output_hash


def test_unknown_rule_and_out_of_binding_location_are_rejected(task, pin):
    instance = {"uri": "https://elsewhere.test/search?q=marker-one&tenant=fixture"}
    wrong = zap_active.normalize_active_report(task, pin, report(instance))
    assert wrong.state == "error" and not wrong.observations
    unknown = zap_active.normalize_active_report(task, pin, report(instance, rule="99999"))
    assert unknown.state == "error" and not unknown.observations


@pytest.mark.parametrize(
    "kwargs,state",
    [
        ({"truncated": True}, "partial"),
        ({"exit_code": 2}, "partial"),
        ({"timed_out": True}, "timeout"),
        ({"cancelled": True}, "cancelled"),
    ],
)
def test_incomplete_process_retains_candidate_without_completion(task, pin, kwargs, state):
    instance = {"uri": "https://owned.test/search?q=marker-two&tenant=fixture"}
    result = zap_active.normalize_active_report(task, pin, report(instance), **kwargs)
    assert result.state == state and len(result.observations) == 1


def test_malformed_and_oversize_reports_fail_closed(task, pin):
    assert zap_active.normalize_active_report(task, pin, b"{").state == "error"
    assert (
        zap_active.normalize_active_report(
            task, pin, b"x" * (zap_active.MAX_REPORT_BYTES + 1)
        ).state
        == "error"
    )
    changed = task.model_copy(update={"rule_config_sha256": "b" * 64})
    assert zap_active.normalize_active_report(changed, pin, report()).state == "error"


def test_report_cannot_exceed_task_request_ceiling(task, pin):
    narrowed = task.model_copy(update={"max_requests": 1})
    instances = [
        {"uri": f"https://owned.test/search?q={value}&tenant=fixture"}
        for value in pin.allowed_values
    ]
    result = zap_active.normalize_active_report(narrowed, pin, report(*instances))
    assert result.state == "partial"
    assert len(result.observations) == 1
    assert "ceiling" in result.errors[0]
