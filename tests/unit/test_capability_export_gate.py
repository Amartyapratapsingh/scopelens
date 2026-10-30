"""A deployed verifier accepts inventory only by replaying private trusted evidence."""

from copy import deepcopy

import pytest
from scripts.verify_runtime_capability_lab import verify_capability_projection
from tests.unit.test_capability_producer import bind, measured

from scopelens.writer.report import _capabilities


def fixture():
    measurement = measured()
    plan = bind(evidence=measurement)
    plan["capability_measurement"] = measurement
    report = {
        "profile": "external-active-v2",
        "capabilities": _capabilities(
            plan, "external-active-v2", scan_id="scan-1", scope_version_id="scope-1"
        ),
    }
    return plan, report


def verify(plan, report, **kwargs):
    return verify_capability_projection(
        plan, report, scan_id="scan-1", scope_id="scope-1", **kwargs
    )


def test_exact_private_measurement_accepts_numeric_export_without_qualification():
    plan, report = fixture()
    result = verify(plan, report, require_measured=True)
    assert result["installed_tools"]["count"] == 1
    assert result["executable_checks"]["count"] > 0
    assert result["independently_qualified_families"]["count"] is None


@pytest.mark.parametrize("fault", ["export", "measurement", "source", "snapshot", "privacy"])
def test_gate_rejects_invented_or_stale_inventory(fault):
    plan, report = fixture()
    if fault == "export":
        report["capabilities"]["installed_tools"]["count"] += 1
    elif fault == "measurement":
        plan["capability_measurement"]["installed_tools"][0]["measured_version"] = "invented"
    elif fault == "source":
        plan["capability_measurement"]["source_sha256"] = "f" * 64
    elif fault == "snapshot":
        plan["capability_snapshot"]["scan_id"] = "other"
    else:
        report["assessment_plan"] = {
            "capability_measurement": deepcopy(plan["capability_measurement"])
        }
    with pytest.raises(AssertionError):
        verify(plan, report, require_measured=True)


def test_legacy_unknown_projection_remains_valid_without_a_measurement():
    plan, _ = fixture()
    plan.pop("capability_snapshot")
    plan.pop("capability_measurement")
    report = {
        "profile": "external-active-v2",
        "capabilities": _capabilities(plan, "external-active-v2"),
    }
    assert verify(plan, report)["installed_tools"]["count"] is None
    with pytest.raises(KeyError):
        verify(plan, report, require_measured=True)
