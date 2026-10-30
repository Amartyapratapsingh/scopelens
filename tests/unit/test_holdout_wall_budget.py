"""A longer BenchmarkJava deadline cannot widen another target or budget."""

from datetime import UTC, datetime

import pytest
from evaluation.run_holdout import scope_request, scope_wall_receipt


@pytest.mark.parametrize("target", ["labs-holdout-a", "labs-holdout-b", "labs-holdout-c"])
def test_other_targets_keep_original_scope_and_terminal_wait(target):
    expiry = datetime(2026, 10, 11, 20, tzinfo=UTC)
    expected = {
        "authority_domain": "lab",
        "scheme": "http",
        "lab_service": target,
        "lab_port": 8080,
        "allowed_check_profile": "external-dast",
        "budgets_override": {
            "requests_per_second": 20,
            "max_in_flight": 2,
            "max_total_requests": 5000,
            "wall_clock_seconds": 900,
        },
        "authorization_expires_at": expiry.isoformat(),
    }
    request = scope_request(target, expiry)
    assert request == expected
    receipt = scope_wall_receipt(request)
    assert receipt["previous_request"] == expected
    assert receipt["submitted_request"] == expected
    assert receipt["changed_fields"] == {}
    assert receipt["runner_deadline_seconds"] == 1020


def test_benchmark_scope_diff_changes_only_wall_with_unchanged_request_cap():
    expiry = datetime(2026, 10, 11, 20, tzinfo=UTC)
    request = scope_request("labs-holdout-d", expiry)
    receipt = scope_wall_receipt(request)
    prior = receipt["previous_request"]
    assert prior["authorization_expires_at"] == request["authorization_expires_at"]
    assert receipt["changed_fields"] == {
        "budgets_override.wall_clock_seconds": {"previous": 900, "submitted": 2700}
    }
    assert receipt["runner_deadline_seconds"] == 2820
    assert request["budgets_override"]["max_total_requests"] == 5000
    prior["budgets_override"]["wall_clock_seconds"] = 2700
    assert prior == request


def test_terminal_wait_is_derived_from_the_submitted_scope_budget():
    request = scope_request("labs-holdout-d", datetime(2026, 10, 11, 20, tzinfo=UTC))
    request["budgets_override"]["wall_clock_seconds"] = 1800
    assert scope_wall_receipt(request)["runner_deadline_seconds"] == 1920
    assert request["budgets_override"]["wall_clock_seconds"] == 1800
