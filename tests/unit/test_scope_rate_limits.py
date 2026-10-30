"""Approved scope rates use separate ceilings instead of the pilot defaults."""

from types import SimpleNamespace

import pytest

from scopelens.execution.ledger import budget_limits_for


@pytest.fixture
def settings(settings):
    """The asserted defaults and ceilings belong to this test, not the live deployment."""
    return settings.model_copy(
        update={
            "scope_max_in_flight": 8,
            "scope_max_requests_per_second": 10,
            "budgets": settings.budgets.model_copy(
                update={"max_in_flight": 2, "requests_per_second": 2}
            ),
        }
    )


@pytest.mark.parametrize(
    "override,concurrency,rate",
    [
        (None, 2, 2),
        ({}, 2, 2),
        ({"max_in_flight": 4, "requests_per_second": 5}, 4, 5),
        ({"max_in_flight": 20, "requests_per_second": 20}, 8, 10),
        ({"max_in_flight": 1, "requests_per_second": 1}, 1, 1),
        ({"max_pages": 1}, 2, 2),
    ],
)
def test_approved_scope_rates_are_bounded_separately(settings, override, concurrency, rate):
    limits = budget_limits_for(SimpleNamespace(budgets_override=override), settings)
    assert limits.max_in_flight == concurrency
    assert limits.requests_per_second == rate


@pytest.mark.parametrize("override", [None, {"max_in_flight": 20, "requests_per_second": 20}])
def test_configured_rate_ceiling_also_bounds_defaults(settings, override):
    settings = settings.model_copy(
        update={"scope_max_in_flight": 1, "scope_max_requests_per_second": 1.5}
    )
    limits = budget_limits_for(SimpleNamespace(budgets_override=override), settings)
    assert limits.max_in_flight == 1
    assert limits.requests_per_second == 1.5


def test_scope_rate_approval_does_not_raise_other_budgets(settings):
    override = {
        "max_in_flight": 4,
        "requests_per_second": 5,
        "max_total_requests": 999999,
        "max_pages": 999999,
        "max_body_bytes": 999999999,
        "wall_clock_seconds": 999999,
        "max_redirects_per_fetch": 999999,
    }
    limits = budget_limits_for(SimpleNamespace(budgets_override=override), settings)
    baseline = budget_limits_for(SimpleNamespace(budgets_override=None), settings)
    assert limits.max_requests == baseline.max_requests
    assert limits.max_pages == baseline.max_pages
    assert limits.max_response_bytes == baseline.max_response_bytes
    assert limits.wall_clock_seconds == baseline.wall_clock_seconds
    assert limits.max_redirects_per_fetch == baseline.max_redirects_per_fetch


@pytest.mark.parametrize(
    "name,value",
    [
        ("scope_max_in_flight", 0),
        ("scope_max_in_flight", -1),
        ("scope_max_requests_per_second", 0),
        ("scope_max_requests_per_second", -1),
        ("scope_max_requests_per_second", float("nan")),
        ("scope_max_requests_per_second", float("inf")),
    ],
)
def test_invalid_deployment_ceiling_is_rejected(settings, name, value):
    from pydantic import ValidationError

    from scopelens.config import Settings

    with pytest.raises(ValidationError):
        Settings(**{**settings.model_dump(), name: value})
